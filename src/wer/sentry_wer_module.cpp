// WER runtime exception module for Sentry Native.
// Runs out-of-process after a crash. Reads a small context struct,
// gathers previously written msgpack files + creates a fresh minidump,
// then uploads via WinHTTP (multipart) directly to Sentry.
#include "sentry_boot.h"

#include "../transports/winhttp_common.h"
extern "C" {
#include "sentry_alloc.h"
#include "sentry_string.h"
#include "sentry_utils.h"
#include "sentry_wer_common.h"
}
#include <dbghelp.h>
#include <shlwapi.h>
#include <strsafe.h>
#include <werapi.h>
#include <winhttp.h>

// Minimal global state used only after callback copies run_path from context.
struct sentry_wer_state {
    wchar_t run_path[MAX_PATH];
};
static sentry_wer_state g_state = {};

// Helper to build a path under g_state.run_path without pulling
// the full sentry path subsystem. Returns false if formatting fails.
static bool
build_run_path_file(wchar_t *dst, size_t cap, const wchar_t *fname)
{
    if (!dst || !cap || !fname || !fname[0]) {
        return false;
    }
    if (FAILED(
            StringCchPrintfW(dst, cap, L"%ls\\%ls", g_state.run_path, fname))) {
        dst[0] = L'\0';
        return false;
    }
    return true;
}

// Internal status codes to map to fitting HRESULTs.
enum wer_status {
    WER_STATUS_OK = 0,
    WER_STATUS_CONTEXT_READ_FAIL,
    WER_STATUS_NO_MINIDUMP_URL,
    WER_STATUS_CONSENT_REQUIRED,
    WER_STATUS_DUMP_WRITE_FAIL,
    WER_STATUS_UPLOAD_FAIL,
};

static HRESULT
status_to_hresult(wer_status st)
{
    switch (st) {
    case WER_STATUS_OK:
        return S_OK; // success
    case WER_STATUS_CONTEXT_READ_FAIL:
        return HRESULT_FROM_WIN32(
            ERROR_INVALID_DATA); // malformed / unreadable context
    case WER_STATUS_NO_MINIDUMP_URL:
        return HRESULT_FROM_WIN32(
            ERROR_INVALID_PARAMETER); // missing required field
    case WER_STATUS_CONSENT_REQUIRED:
        return HRESULT_FROM_WIN32(
            ERROR_ACCESS_DENIED); // policy / consent gating
    case WER_STATUS_DUMP_WRITE_FAIL:
        return HRESULT_FROM_WIN32(ERROR_WRITE_FAULT); // failed to create dump
    case WER_STATUS_UPLOAD_FAIL:
    default:
        return HRESULT_FROM_WIN32(
            ERROR_CONNECTION_ABORTED); // upload failed/aborted
    }
}

// Lightweight debug logger (OutputDebugString only; no file IO).
// Can be monitored with DebugView or similar tools.
static void
log_line(const wchar_t *fmt, ...)
{
    wchar_t buf[640];
    va_list args;
    va_start(args, fmt);
    _vsnwprintf_s(buf, _countof(buf), _TRUNCATE, fmt, args);
    va_end(args);
    size_t len = wcslen(buf);
    if (len + 2 < _countof(buf)) {
        buf[len++] = L'\r';
        buf[len++] = L'\n';
        buf[len] = 0;
    }
    OutputDebugStringW(buf);
}

// Create a timestamped dump filename (UTC) for uniqueness.
static bool
create_dump_name(wchar_t *out, size_t cap)
{
    SYSTEMTIME st;
    GetSystemTime(&st);
    return SUCCEEDED(
        StringCchPrintfW(out, cap, L"sentry_dump_%04u%02u%02u_%02u%02u%02u.dmp",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond));
}

// Generate a minidump for the crashing process/thread; returns path.
static bool
write_minidump(const PWER_RUNTIME_EXCEPTION_INFORMATION info, wchar_t *path_out,
    size_t cap)
{
    if (!info || !path_out) {
        return false;
    }
    wchar_t file[64];
    if (!create_dump_name(file, _countof(file))) {
        return false;
    }
    if (!build_run_path_file(path_out, cap, file)) {
        return false;
    }
    HANDLE h = CreateFileW(path_out, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        log_line(L"CreateFile failed err=%lu", GetLastError());
        return false;
    }
    MINIDUMP_EXCEPTION_INFORMATION mei = {};
    mei.ThreadId = GetThreadId(info->hThread);
    mei.ClientPointers = TRUE;
    EXCEPTION_POINTERS exc_ptrs = { &info->exceptionRecord, &info->context };
    mei.ExceptionPointers = &exc_ptrs;
    BOOL ok = MiniDumpWriteDump(info->hProcess, GetProcessId(info->hProcess), h,
        MiniDumpWithThreadInfo, &mei, nullptr, nullptr);
    CloseHandle(h);
    if (!ok) {
        log_line(L"MiniDumpWriteDump failed err=%lu", GetLastError());
        DeleteFileW(path_out);
        return false;
    }
    log_line(L"Minidump created: %ls", path_out);
    return true;
}

// Local helpers (kept minimal) for file IO to avoid linking full path system.
static bool
read_file(const wchar_t *path, BYTE **data, DWORD *len)
{
    *data = nullptr;
    *len = 0;
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        return false;
    }
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(h, &sz) || sz.HighPart) {
        CloseHandle(h);
        return false;
    }
    DWORD size = sz.LowPart;
    BYTE *buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, size);
    if (!buf) {
        CloseHandle(h);
        return false;
    }
    DWORD rd = 0;
    if (!ReadFile(h, buf, size, &rd, nullptr) || rd != size) {
        HeapFree(GetProcessHeap(), 0, buf);
        CloseHandle(h);
        return false;
    }
    CloseHandle(h);
    *data = buf;
    *len = size;
    return true;
}

static bool
file_exists(const wchar_t *p)
{
    DWORD attrs = GetFileAttributesW(p);
    return attrs != INVALID_FILE_ATTRIBUTES
        && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

// Append a binary part (with optional trailing CRLF) to multipart body.
static int
append_part_fn(sentry_stringbuilder_t *sbuilder, const char *boundary_str,
    const char *name, const char *filename, const BYTE *data, size_t len,
    bool add_crlf)
{
    char head[256];
    int w = snprintf(head, sizeof(head),
        "--%s\r\nContent-Disposition: form-data; name=\"%s\"; "
        "filename=\"%s\"\r\nContent-Type: application/octet-stream\r\n\r\n",
        boundary_str, name, filename);
    if (w < 0 || (size_t)w >= sizeof(head)
        || sentry__stringbuilder_append(sbuilder, head)) {
        return 1;
    }
    char *dst
        = sentry__stringbuilder_reserve(sbuilder, len + (add_crlf ? 2 : 1));
    if (!dst) {
        return 1;
    }
    memcpy(dst, data, len);
    sbuilder->len += len;
    if (add_crlf) {
        dst = sbuilder->buf + sbuilder->len;
        dst[0] = '\r';
        dst[1] = '\n';
        sbuilder->len += 2;
        sbuilder->buf[sbuilder->len] = '\0';
    } else {
        sbuilder->buf[sbuilder->len] = '\0';
    }
    return 0;
}

// Test helper: build the multipart body for given presence flags. Not exported.
// Returns 0 on success and sets out_body/out_len (caller frees with
// sentry_free). Build and POST multipart payload containing: event,
// breadcrumbs, minidump. Returns true on HTTP 2xx.
static bool
upload_dump(
    const sentry_wer_runtime_context *ctx, const wchar_t *dump_file_path)
{
    /* Multipart layout (Crashpad-compatible):
         Parts (all Content-Type: application/octet-stream):
             1. __sentry-event (msgpack)        [optional]
             2. __sentry-breadcrumb1 (msgpack)  [optional]
             3. __sentry-breadcrumb2 (msgpack)  [optional]
             4. upload_file_minidump (dmp)      [required]
         Boundary: randomized per invocation to reduce any collision risk.
         Assembly uses `sentry_stringbuilder_t` for a single contiguous buffer
         to avoid manual size arithmetic and multiple allocations. Each optional
         part is followed by CRLF except the final dump part which is directly
         followed by the terminating boundary line starting with CRLF.
    */
    if (!ctx) {
        return false;
    }
    if (!ctx->minidump_url[0]) {
        log_line(L"Missing minidump_url; skip upload");
        return false;
    }
    URL_COMPONENTSW uc;
    memset(&uc, 0, sizeof(uc));
    wchar_t host_buf[260];
    wchar_t path_buf[768];
    uc.dwStructSize = sizeof(uc);
    uc.lpszHostName = host_buf;
    uc.dwHostNameLength = _countof(host_buf);
    uc.lpszUrlPath = path_buf;
    uc.dwUrlPathLength = _countof(path_buf);
    uc.dwSchemeLength = 1;
    if (!WinHttpCrackUrl(ctx->minidump_url, 0, 0, &uc)) {
        log_line(L"WinHttpCrackUrl failed; skip upload");
        return false;
    }
    host_buf[MIN(uc.dwHostNameLength, _countof(host_buf) - 1)] = 0;
    path_buf[MIN(uc.dwUrlPathLength, _countof(path_buf) - 1)] = 0;
    const wchar_t *host = host_buf;
    const wchar_t *scheme
        = (uc.nScheme == INTERNET_SCHEME_HTTPS) ? L"https" : L"http";
    const wchar_t *rel_path = path_buf;
    BYTE *dump_data = NULL;
    DWORD dump_len = 0;
    if (!read_file(dump_file_path, &dump_data, &dump_len)) {
        log_line(L"Read dump failed");
        return false;
    }
    // Event (msgpack) file, like Crashpad: __sentry-event
    wchar_t event_path[MAX_PATH];
    BYTE *event_data = nullptr;
    DWORD event_len = 0;
    bool have_event = false;
    build_run_path_file(
        event_path, _countof(event_path), SENTRY_WER_EVENT_FILE_W);
    if (file_exists(event_path)
        && read_file(event_path, &event_data, &event_len) && event_len) {
        have_event = true;
        log_line(L"Including event msgpack (%lu bytes)", event_len);
    } else {
        log_line(L"No event msgpack file present");
    }
    // Breadcrumb msgpack concatenated entries, like Crashpad:
    // __sentry-breadcrumb1 and __sentry-breadcrumb2
    wchar_t bc1_path[MAX_PATH];
    wchar_t bc2_path[MAX_PATH];
    BYTE *bc1_data = nullptr;
    DWORD bc1_len = 0;
    bool have_bc1 = false;
    BYTE *bc2_data = nullptr;
    DWORD bc2_len = 0;
    bool have_bc2 = false;
    build_run_path_file(
        bc1_path, _countof(bc1_path), SENTRY_WER_BREADCRUMB1_FILE_W);
    build_run_path_file(
        bc2_path, _countof(bc2_path), SENTRY_WER_BREADCRUMB2_FILE_W);
    if (file_exists(bc1_path) && read_file(bc1_path, &bc1_data, &bc1_len)
        && bc1_len) {
        have_bc1 = true;
        log_line(L"Including breadcrumb1 (%lu bytes)", bc1_len);
    }
    if (file_exists(bc2_path) && read_file(bc2_path, &bc2_data, &bc2_len)
        && bc2_len) {
        have_bc2 = true;
        log_line(L"Including breadcrumb2 (%lu bytes)", bc2_len);
    }

    // rel_path already resolved above
    char boundary[64];
    {
        DWORD pid = GetCurrentProcessId();
        DWORD tick = GetTickCount();
        // Random-ish boundary; must not contain CR/LF. Keep simple hex.
        _snprintf_s(boundary, _TRUNCATE, "----sentry-wer-%08lX-%08lX",
            (unsigned long)pid, (unsigned long)tick);
    }
    char header_a[128];
    StringCchPrintfA(header_a, _countof(header_a),
        "Content-Type: multipart/form-data; boundary=%s", boundary);
    wchar_t header_w[128];
    MultiByteToWideChar(CP_UTF8, 0, header_a, -1, header_w, _countof(header_w));

    // Build multipart body with stringbuilder for safer growth management.
    sentry_stringbuilder_t sb;
    sentry__stringbuilder_init(&sb);

    int err = 0;
    if (have_event && !err) {
        err = append_part_fn(&sb, boundary, SENTRY_WER_MP_EVENT_PART,
            SENTRY_WER_MP_EVENT_PART, event_data, event_len, true);
    }
    if (have_bc1 && !err) {
        err = append_part_fn(&sb, boundary, SENTRY_WER_MP_BREADCRUMB1_PART,
            SENTRY_WER_MP_BREADCRUMB1_PART, bc1_data, bc1_len, true);
    }
    if (have_bc2 && !err) {
        err = append_part_fn(&sb, boundary, SENTRY_WER_MP_BREADCRUMB2_PART,
            SENTRY_WER_MP_BREADCRUMB2_PART, bc2_data, bc2_len, true);
    }
    // Dump part: CRLF not appended here; a footer starting with CRLF is added
    // later.
    if (!err) {
        err = append_part_fn(&sb, boundary, SENTRY_WER_MP_MINIDUMP_PART,
            "dump.dmp", dump_data, dump_len, false);
    }
    if (!err) {
        char foot[96];
        int w = snprintf(foot, sizeof(foot), "\r\n--%s--\r\n", boundary);
        if (w < 0 || (size_t)w >= sizeof(foot)
            || sentry__stringbuilder_append(&sb, foot)) {
            err = 1;
        }
    }
    bool ok = false;
    if (!err) {
        size_t body_len = sentry__stringbuilder_len(&sb);
        char *body = sentry__stringbuilder_into_string(&sb);
        const wchar_t *ua
            = (ctx->user_agent[0]) ? ctx->user_agent : L"sentry-wer/1.0";
        const wchar_t *proxy = (ctx->proxy[0]) ? ctx->proxy : NULL;
        HINTERNET session = sentry__winhttp_open_session(ua, proxy);
        if (!session) {
            log_line(L"Failed to open WinHTTP session");
        } else {
            sentry_winhttp_result_t result;
            INTERNET_PORT port = uc.nPort
                ? uc.nPort
                : (wcscmp(scheme, L"https") == 0 ? 443 : 80);
            if (sentry__winhttp_simple_post(session, host, port,
                    wcscmp(scheme, L"https") == 0, rel_path, header_w,
                    (const unsigned char *)body, body_len, &result)
                == 0) {
                log_line(L"HTTP status %u", result.status_code);
                ok = result.status_code >= 200 && result.status_code < 300;
            } else {
                log_line(L"HTTP post failed");
            }
            WinHttpCloseHandle(session);
        }
        sentry_free(body);
    } else {
        sentry__stringbuilder_cleanup(&sb);
        log_line(L"Failed to build multipart body");
    }
    if (dump_data)
        HeapFree(GetProcessHeap(), 0, dump_data);
    if (event_data)
        HeapFree(GetProcessHeap(), 0, event_data);
    if (bc1_data)
        HeapFree(GetProcessHeap(), 0, bc1_data);
    if (bc2_data)
        HeapFree(GetProcessHeap(), 0, bc2_data);
    log_line(L"Upload %s", ok ? L"ok" : L"fail");
    return ok;
}

// Read runtime context structure from crashing process memory into dst.
// Returns true on success (validated version/size and minimum bytes read).
static bool
read_runtime_context(const PWER_RUNTIME_EXCEPTION_INFORMATION info,
    PVOID remote_ctx, sentry_wer_runtime_context *dst)
{
    if (!info || !info->hProcess || !remote_ctx || !dst) {
        return false;
    }
    SIZE_T rd = 0;
    if (!ReadProcessMemory(
            info->hProcess, remote_ctx, dst, sizeof(*dst), &rd)) {
        return false;
    }
    if (rd < offsetof(sentry_wer_runtime_context, flags) + sizeof(dst->flags)) {
        return false;
    }
    if (dst->version != SENTRY_WER_RUNTIME_CONTEXT_VERSION
        || dst->size != sizeof(*dst)) {
        return false;
    }
    return true;
}

// Write microsecond-resolution crash timestamp marker file at run_path.
static void
write_crash_marker()
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER ull;
    ull.LowPart = ft.dwLowDateTime;
    ull.HighPart = ft.dwHighDateTime;
    unsigned long long usec
        = (ull.QuadPart - 116444736000000000ULL) / 10ULL; // 100ns->us
    wchar_t marker_path[MAX_PATH];
    if (!build_run_path_file(
            marker_path, _countof(marker_path), SENTRY_WER_LAST_CRASH_FILE_W)) {
        return;
    }
    HANDLE mh = CreateFileW(marker_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, NULL);
    if (mh == INVALID_HANDLE_VALUE) {
        return;
    }
    char buf[32];
    int n = _snprintf_s(buf, _TRUNCATE, "%llu", (unsigned long long)usec);
    if (n > 0) {
        DWORD wr;
        WriteFile(mh, buf, (DWORD)strlen(buf), &wr, NULL);
    }
    CloseHandle(mh);
    // marker file written
}

// Main WER callback: copy context, create minidump, try upload. Never blocks
// WER flow.
extern "C" __declspec(dllexport) HRESULT CALLBACK
OutOfProcessExceptionEventCallback(PVOID ctx,
    const PWER_RUNTIME_EXCEPTION_INFORMATION info, BOOL *claimed, PWSTR evt,
    PDWORD evt_sz, PDWORD sig_count)
{
    // Read runtime context (ctx) from crashing process into local buffer.
    (void)ctx;
    sentry_wer_runtime_context ctx_copy = {};
    wer_status status = WER_STATUS_OK;
    bool ctx_ok = read_runtime_context(info, ctx, &ctx_copy);
    if (ctx_ok && ctx_copy.run_path[0]) {
        wcsncpy_s(g_state.run_path, ctx_copy.run_path, _TRUNCATE);
    }
    if (!ctx_ok) {
        log_line(L"Failed to read runtime context; aborting");
        return status_to_hresult(WER_STATUS_CONTEXT_READ_FAIL);
    }
    if (!ctx_copy.minidump_url[0]) {
        log_line(L"Missing minidump_url in context");
        status = WER_STATUS_NO_MINIDUMP_URL;
    } else {
        log_line(L"Context minidump_url present");
    }
    log_line(
        L"Callback invoked (pid=%lu)", info ? GetProcessId(info->hProcess) : 0);

    if (claimed) {
        // Do not claim the crash
        // This allows WER to also do its own processing (e.g. upload to MS)
        // Otherwise, the signature callback would also need to be implemented.
        // This could be done in future if needed.
        *claimed = FALSE;
    }

    if (sig_count) {
        *sig_count = 0;
    }

    if (evt && evt_sz) {
        const wchar_t *name = L"sentry-wer";
        size_t need = wcslen(name) + 1;
        if (*evt_sz >= need) {
            wcscpy_s(evt, *evt_sz, name);
        }
        *evt_sz = (DWORD)need;
    }

    bool wrote_dump = false;
    bool performed_upload = false;
    bool upload_ok = false;
    if (status == WER_STATUS_OK && info && info->hProcess) {
        wchar_t dump[MAX_PATH];
        if (write_minidump(info, dump, _countof(dump))) {
            wrote_dump = true;
            write_crash_marker();
            bool require_consent
                = (ctx_copy.flags & SENTRY_WER_FLAG_REQUIRE_CONSENT) != 0;
            if (require_consent) {
                log_line(L"Consent required flag set; skipping upload");
                status = WER_STATUS_CONSENT_REQUIRED;
            } else if (ctx_copy.minidump_url[0]) {
                performed_upload = true;
                upload_ok = upload_dump(&ctx_copy, dump);
                if (!upload_ok) {
                    status = WER_STATUS_UPLOAD_FAIL;
                }
            } else {
                // Only set if not already a more specific error.
                if (status == WER_STATUS_OK) {
                    status = WER_STATUS_NO_MINIDUMP_URL;
                }
            }
        } else {
            status = (status == WER_STATUS_OK) ? WER_STATUS_DUMP_WRITE_FAIL
                                               : status;
        }
    }
    if (status == WER_STATUS_OK && performed_upload && upload_ok
        && wrote_dump) {
        return status_to_hresult(WER_STATUS_OK);
    }
    return status_to_hresult(status);
}

// Optional signature callback (unused).
extern "C" __declspec(dllexport) HRESULT CALLBACK
OutOfProcessExceptionEventSignatureCallback(PVOID,
    const PWER_RUNTIME_EXCEPTION_INFORMATION, DWORD, PWSTR, PDWORD, PWSTR,
    PDWORD)
{
    return E_FAIL; // use default WER behavior
}

// Optional debugger launch callback (unused).
extern "C" __declspec(dllexport) HRESULT CALLBACK
OutOfProcessExceptionEventDebuggerLaunchCallback(PVOID,
    const PWER_RUNTIME_EXCEPTION_INFORMATION, PBOOL custom, PWSTR launch,
    PDWORD launch_sz, PBOOL autolaunch)
{
    return E_FAIL; // use default WER behavior
}

// Basic DllMain: silent on attach, trace on detach.
// Will be loaded by WerFault.exe
BOOL WINAPI
DllMain(HINSTANCE h, DWORD r, LPVOID reserved)
{
    (void)h;
    (void)reserved;
    if (r == DLL_PROCESS_ATTACH) {
        // Run path not yet known; logging is deferred until the callback unless
        // a speculative temp path file is desired. Kept silent.
    } else if (r == DLL_PROCESS_DETACH) {
        log_line(L"DLL_PROCESS_DETACH");
    }
    return TRUE;
}
