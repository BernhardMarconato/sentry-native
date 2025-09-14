// Minimal Windows Error Reporting (WER) backend implementation for Sentry
// This backend prepares crash metadata (event + rotating breadcrumb files)
// and registers an out-of-process Runtime Exception Module
// (sentry_wer_module.dll) via WerRegisterRuntimeExceptionModule. The external
// module is responsible for reacting to the crash. For a first iteration the
// data is only prepared similarly to the crashpad backend so future work can
// be picked up from the WER module side and submitted to Sentry infrastructure.

extern "C" {
#include "sentry_boot.h"

#include "sentry_alloc.h"
#include "sentry_backend.h"
#include "sentry_core.h"
#include "sentry_envelope.h"
#include "sentry_options.h"
#include "sentry_path.h"
#include "sentry_sync.h"
#include "sentry_transport.h"
#include "sentry_utils.h"
#include "sentry_uuid.h"
}

#include "wer/sentry_wer_common.h"
#include <appmodel.h>
#include <shlwapi.h>
#include <strsafe.h>
#include <werapi.h>
#include <windows.h>

#include <atomic>
#include <errno.h>
#include <stdlib.h>

extern "C" {

typedef struct {
    sentry_path_t *event_path;
    sentry_path_t *breadcrumb1_path;
    sentry_path_t *breadcrumb2_path;
    size_t num_breadcrumbs;
    std::atomic<bool> crashed;
    std::atomic<bool> scope_flush;
    sentry_uuid_t crash_event_id;
    wchar_t registered_module_path[MAX_PATH];
    sentry_wer_runtime_context *runtime_ctx; // pointer kept alive for WER
} wer_state_t;

static void
wer_backend_flush_scope_to_event(const sentry_path_t *event_path,
    const sentry_options_t *options, sentry_value_t crash_event)
{
    SENTRY_WITH_SCOPE (scope) {
        sentry__scope_apply_to_event(
            scope, options, crash_event, SENTRY_SCOPE_NONE);
    }

    size_t mpack_size = 0;
    char *mpack = sentry_value_to_msgpack(crash_event, &mpack_size);
    sentry_value_decref(crash_event);
    if (mpack) {
        int rv = sentry__path_write_buffer(event_path, mpack, mpack_size);
        sentry_free(mpack);
        if (rv != 0) {
            SENTRY_WARN("flushing scope to msgpack failed");
        }
    }
}

static void
wer_backend_flush_scope(
    sentry_backend_t *backend, const sentry_options_t *options)
{
    auto *state = static_cast<wer_state_t *>(backend->data);
    if (!state || !state->event_path) {
        return;
    }
    bool expected = false;
    if (state->crashed.load(std::memory_order_relaxed)
        || !state->scope_flush.compare_exchange_strong(
            expected, true, std::memory_order_acquire)) {
        return;
    }

    sentry_value_t event = sentry_value_new_object();
    sentry_value_set_by_key(
        event, "event_id", sentry__value_new_uuid(&state->crash_event_id));
    sentry_value_set_by_key(
        event, "level", sentry__value_new_level(SENTRY_LEVEL_FATAL));
    wer_backend_flush_scope_to_event(state->event_path, options, event);
    state->scope_flush.store(false, std::memory_order_release);
}

static void
wer_backend_add_breadcrumb(sentry_backend_t *backend, sentry_value_t breadcrumb,
    const sentry_options_t *options)
{
    auto *state = static_cast<wer_state_t *>(backend->data);
    if (!state) {
        return;
    }
    size_t max_breadcrumbs = options->max_breadcrumbs;
    if (!max_breadcrumbs) {
        return;
    }

    bool first_breadcrumb = state->num_breadcrumbs % max_breadcrumbs == 0;
    const sentry_path_t *breadcrumb_file
        = state->num_breadcrumbs % (max_breadcrumbs * 2) < max_breadcrumbs
        ? state->breadcrumb1_path
        : state->breadcrumb2_path;
    state->num_breadcrumbs++;
    if (!breadcrumb_file) {
        return;
    }

    size_t mpack_size;
    char *mpack = sentry_value_to_msgpack(breadcrumb, &mpack_size);
    if (!mpack) {
        return;
    }

    int rv = first_breadcrumb
        ? sentry__path_write_buffer(breadcrumb_file, mpack, mpack_size)
        : sentry__path_append_buffer(breadcrumb_file, mpack, mpack_size);
    sentry_free(mpack);

    if (rv != 0) {
        SENTRY_WARN("flushing breadcrumb to msgpack failed");
    }
}

typedef HRESULT(WINAPI *pWerRegisterRuntimeExceptionModule)(PCWSTR, PVOID);
typedef HRESULT(WINAPI *pWerUnregisterRuntimeExceptionModule)(PCWSTR, PVOID);

// Detect MSIX packaged context via GetCurrentPackageFullName.
// Rationale: MSIX packaged processes run with file system & registry
// virtualization. Direct writes to HKCU WER key will be virtualized only for
// the package, so WerFault.exe cannot see them. This can lead to the WER module
// not being loaded. Additionally, it is not possible for WerFault.exe or other
// processes to LoadLibrary DLLs from within a MSIX package due to restricted
// ACLs. Therefore:
//   1) Create the required registry value by using reg.exe so the write occurs
//      outside any registry virtualization layer (as processes started by the
//      package and not contained in the package will not have package identity
//      by default).
//   2) Copy the runtime WER module DLL into the writable run/cache directory
//      (outside the packaged install path) to allow WerFault.exe to load it.
static bool
wer_is_msix_packaged()
{
    using GetCurrentPackageFullName_t = LONG(WINAPI *)(UINT32 *, PWSTR);
    HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
    if (!kernel) {
        return false;
    }
    auto fn = (GetCurrentPackageFullName_t)GetProcAddress(
        kernel, "GetCurrentPackageFullName");
    if (!fn) {
        return false;
    }
    UINT32 len = 0;
    LONG rc = fn(&len, nullptr);
    if (rc == APPMODEL_ERROR_NO_PACKAGE) {
        return false;
    }
    if (rc == ERROR_INSUFFICIENT_BUFFER && len > 0) {
        return true;
    }
    return false;
}

static bool
wer_set_registry_value_via_regexe(const wchar_t *dll_path)
{
    // Build explicit System32 path to reg.exe
    wchar_t system_dir[MAX_PATH];
    UINT sys_len = GetSystemDirectoryW(system_dir, _countof(system_dir));
    if (sys_len == 0 || sys_len >= _countof(system_dir)) {
        return false;
    }
    wchar_t reg_path[MAX_PATH];
    if (FAILED(StringCchPrintfW(
            reg_path, _countof(reg_path), L"%ls\\reg.exe", system_dir))) {
        return false;
    }

    // Command line: reg.exe ADD "HKCU..." /v "<dll_path>" /t REG_DWORD /d 1 /f
    // Use a separate buffer to hold mutable command line for CreateProcessW.
    wchar_t cmd[1400];
    if (FAILED(StringCchPrintfW(cmd, _countof(cmd),
            L"\"%ls\" ADD \"HKCU\\Software\\Microsoft\\Windows\\Windows Error "
            L"Reporting\\RuntimeExceptionHelperModules\" /v \"%ls\" /t "
            L"REG_DWORD /d 1 /f",
            reg_path, dll_path))) {
        return false;
    }

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    BOOL ok = CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    if (!ok) {
        SENTRY_WARN(
            "failed launching System32 reg.exe for WER module registration");
        return false;
    }
    WaitForSingleObject(pi.hProcess, 4000);
    DWORD exit_code = 0;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    if (exit_code != 0) {
        SENTRY_WARN("reg.exe exited with non-zero code adding WER module");
        return false;
    }
    return true;
}

static bool
wer_register_runtime_module(const wchar_t *dll_path, void *ctx, bool is_msix)
{
    HMODULE hKernel = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel) {
        SENTRY_WARN("kernel32.dll handle not found for WER registration");
        return false;
    }
    auto fnRegister = (pWerRegisterRuntimeExceptionModule)GetProcAddress(
        hKernel, "WerRegisterRuntimeExceptionModule");
    if (!fnRegister) {
        SENTRY_WARN("WerRegisterRuntimeExceptionModule not available");
        return false;
    }

    bool reg_ok = false;
    if (is_msix) {
        reg_ok = wer_set_registry_value_via_regexe(dll_path);
    } else {
        constexpr DWORD dwOne = 1;
        LSTATUS reg_res = RegSetKeyValueW(HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\Windows Error "
            L"Reporting\\RuntimeExceptionHelperModules",
            dll_path, REG_DWORD, &dwOne, sizeof(DWORD));
        if (reg_res == ERROR_SUCCESS) {
            reg_ok = true;
        } else {
            SENTRY_WARN("registering WER runtime module in registry failed");
        }
    }
    if (reg_ok) {
        SENTRY_DEBUG("runtime module registry value set");
    }

    HRESULT hr = fnRegister(dll_path, ctx);
    if (FAILED(hr)) {
        SENTRY_WARNF("WerRegisterRuntimeExceptionModule failed hr=0x%08x", hr);
        return false;
    }
    SENTRY_INFOF("registered WER runtime exception module path=%S", dll_path);
    return true;
}

static void
wer_unregister_runtime_module(const wchar_t *dll_path)
{
    HMODULE hKernel = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel) {
        return;
    }
    auto fnUnregister = (pWerUnregisterRuntimeExceptionModule)GetProcAddress(
        hKernel, "WerUnregisterRuntimeExceptionModule");
    if (!fnUnregister) {
        return;
    }
    fnUnregister(dll_path, nullptr);
}

static int
wer_backend_startup(sentry_backend_t *backend, const sentry_options_t *options)
{
    sentry_path_t *current_run_folder = options->run->run_path;
    auto *state = static_cast<wer_state_t *>(backend->data);
    state->crash_event_id = sentry__new_event_id();

    // Prepare files similar to crashpad backend
    state->event_path
        = sentry__path_join_str(current_run_folder, SENTRY_WER_EVENT_FILE_A);
    state->breadcrumb1_path = sentry__path_join_str(
        current_run_folder, SENTRY_WER_BREADCRUMB1_FILE_A);
    state->breadcrumb2_path = sentry__path_join_str(
        current_run_folder, SENTRY_WER_BREADCRUMB2_FILE_A);
    sentry__path_touch(state->event_path);
    sentry__path_touch(state->breadcrumb1_path);
    sentry__path_touch(state->breadcrumb2_path);

    // Determine sentry_wer_module.dll path using sentry_path helpers. Prefer
    // explicitly configured options->handler_path if provided; otherwise use
    // directory of current executable.
    sentry_path_t *module_pathp = NULL;
    bool custom_handler = false;
    if (options->handler_path && options->handler_path->path) {
        if (sentry__path_ends_with(options->handler_path, ".dll")) {
            module_pathp = sentry__path_clone(options->handler_path);
            custom_handler = true;
        } else {
            module_pathp = sentry__path_join_wstr(
                options->handler_path, L"sentry_wer_module.dll");
            if (module_pathp) {
                custom_handler = true;
            }
        }
    }
    if (!module_pathp) {
        sentry_path_t *exe_path = sentry__path_current_exe();
        if (!exe_path) {
            SENTRY_WARN("failed to get current exe for WER registration");
            return 1;
        }
        sentry_path_t *exe_dir = sentry__path_dir(exe_path);
        sentry__path_free(exe_path);
        if (!exe_dir) {
            SENTRY_WARN("failed to get exe directory for WER module path");
            return 1;
        }
        module_pathp
            = sentry__path_join_wstr(exe_dir, L"sentry_wer_module.dll");
        sentry__path_free(exe_dir);
        if (!module_pathp) {
            SENTRY_WARN("failed to build default WER module path");
            return 1;
        }
    }
    SENTRY_DEBUGF("WER module path=%S (custom=%d)", module_pathp->path,
        custom_handler ? 1 : 0);

    if (!sentry__path_is_file(module_pathp)) {
        SENTRY_WARN("sentry_wer_module.dll not found at resolved path");
#ifdef SENTRY_UNITTEST
        // In unit tests the WER module is not required to exist. Initialization
        // continues so other subsystems can be exercised without crash capture.
        sentry__path_free(module_pathp);
        module_pathp = NULL;
        return 0;
#else
        sentry__path_free(module_pathp);
        return 1;
#endif
    }

    // Build runtime context and pass pointer to WER registration so the module
    // can ReadProcessMemory it later.
    state->runtime_ctx = (sentry_wer_runtime_context *)VirtualAlloc(NULL,
        sizeof(sentry_wer_runtime_context), MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);
    if (!state->runtime_ctx) {
        SENTRY_WARN("failed to allocate WER runtime context");
        return 1;
    }
    memset(state->runtime_ctx, 0, sizeof(*state->runtime_ctx));
    state->runtime_ctx->version = SENTRY_WER_RUNTIME_CONTEXT_VERSION;
    state->runtime_ctx->size = sizeof(*state->runtime_ctx);
    if (current_run_folder && current_run_folder->path) {
        wcsncpy_s(state->runtime_ctx->run_path,
            _countof(state->runtime_ctx->run_path), current_run_folder->path,
            _TRUNCATE);
    }
    // Populate absolute minidump URL only (split DSN fields removed).
    if (options->dsn && options->dsn->is_valid) {
        const char *ua
            = options->user_agent ? options->user_agent : SENTRY_SDK_USER_AGENT;
        char *full_url = sentry__dsn_get_minidump_url(options->dsn, ua);
        if (full_url) {
            MultiByteToWideChar(CP_UTF8, 0, full_url, -1,
                state->runtime_ctx->minidump_url,
                (int)_countof(state->runtime_ctx->minidump_url));
            state->runtime_ctx
                ->minidump_url[_countof(state->runtime_ctx->minidump_url) - 1]
                = L'\0';
            sentry_free(full_url);
        }
    }

    // Flags & auxiliary networking fields (v5+)
    // Consent required? Mirror logic of sentry__should_skip_upload but
    // evaluated ahead-of-crash. Module will still sanity check.
    if (options->require_user_consent) {
        state->runtime_ctx->flags |= SENTRY_WER_FLAG_REQUIRE_CONSENT;
    }
    // Future knob: option to claim crash (not exposed yet) could be plumbed
    // via an internal option or env var. For now default keep unclaimed.
    // if (some_condition) state->runtime_ctx->flags |=
    // SENTRY_WER_FLAG_CLAIM_CRASH;

    auto narrow_to_wide_opt = [](const char *src, wchar_t *dst, size_t cap) {
        if (!dst || !cap) {
            return;
        }
        if (!src || !src[0]) {
            dst[0] = L'\0';
            return;
        }
        int rv = MultiByteToWideChar(CP_UTF8, 0, src, -1, dst, (int)cap);
        if (rv == 0) {
            dst[0] = L'\0';
        } else {
            dst[cap - 1] = L'\0';
        }
    };
    narrow_to_wide_opt(options->proxy, state->runtime_ctx->proxy,
        _countof(state->runtime_ctx->proxy));
    narrow_to_wide_opt(options->user_agent, state->runtime_ctx->user_agent,
        _countof(state->runtime_ctx->user_agent));

    bool is_msix = wer_is_msix_packaged();
    SENTRY_DEBUGF("WER module path=%S (custom=%d msix=%d)", module_pathp->path,
        custom_handler ? 1 : 0, is_msix ? 1 : 0);

    // MSIX: place a *stable* copy of the runtime module in the user provided
    // database (cache) directory if available instead of the per-run directory
    // which contains a random component. This keeps the registry value from
    // changing every process start and avoids accumulating stale values.
    if (is_msix) {
        const sentry_path_t *cache_root = options->database_path
            ? options->database_path
            : current_run_folder; // fallback to run path if no database path
        if (cache_root) {
            sentry_path_t *dll_cache_path
                = sentry__path_join_wstr(cache_root, L"sentry_wer_module.dll");
            if (dll_cache_path) {
                // Always overwrite to ensure updated module after app update.
                if (!CopyFileW(
                        module_pathp->path, dll_cache_path->path, FALSE)) {
                    DWORD gle = GetLastError();
                    SENTRY_WARNF("failed copying WER module to stable cache "
                                 "gle=%lu; proceeding with original path",
                        gle);
                    sentry__path_free(dll_cache_path);
                } else {
                    SENTRY_DEBUG("copied (overwrote) WER module in stable "
                                 "cache for MSIX");
                    sentry__path_free(module_pathp);
                    module_pathp = dll_cache_path;
                }
            }
        }
    }

    if (!wer_register_runtime_module(
            module_pathp->path, state->runtime_ctx, is_msix)) {
        SENTRY_WARN("WER runtime module registration failed");
        sentry__path_free(module_pathp);
        return 1;
    }
    lstrcpynW(state->registered_module_path, module_pathp->path, MAX_PATH);
    sentry__path_free(module_pathp);

    // Initial flush so event file exists with base content
    wer_backend_flush_scope(backend, options);
    return 0;
}

static void
wer_backend_shutdown(sentry_backend_t *backend)
{
    auto *state = static_cast<wer_state_t *>(backend->data);
    if (!state) {
        return;
    }
    if (state->registered_module_path[0]) {
        wer_unregister_runtime_module(state->registered_module_path);
        // Remove registry value that was set at startup to avoid stale entries.
        RegDeleteKeyValueW(HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\Windows Error "
            L"Reporting\\RuntimeExceptionHelperModules",
            state->registered_module_path);
    }
    if (state->runtime_ctx) {
        VirtualFree(state->runtime_ctx, 0, MEM_RELEASE);
        state->runtime_ctx = nullptr;
    }
}

static void
wer_backend_free(sentry_backend_t *backend)
{
    auto *state = static_cast<wer_state_t *>(backend->data);
    if (!state) {
        return;
    }
    sentry__path_free(state->event_path);
    sentry__path_free(state->breadcrumb1_path);
    sentry__path_free(state->breadcrumb2_path);
    sentry_free(state);
}

static uint64_t
wer_backend_last_crash(sentry_backend_t *backend)
{
    auto *state = static_cast<wer_state_t *>(backend->data);
    if (!state || !state->runtime_ctx || !state->runtime_ctx->run_path[0]) {
        return 0;
    }
    sentry_path_t *run_path
        = sentry__path_from_wstr(state->runtime_ctx->run_path);
    if (!run_path) {
        return 0;
    }
    sentry_path_t *marker
        = sentry__path_join_wstr(run_path, SENTRY_WER_LAST_CRASH_FILE_W);
    sentry__path_free(run_path);
    if (!marker) {
        return 0;
    }
    size_t file_sz = 0;
    char *contents = sentry__path_read_to_buffer(marker, &file_sz);
    sentry__path_free(marker);
    if (!contents || file_sz == 0) {
        sentry_free(contents);
        return 0;
    }
    // Ensure buffer null-terminated for strtoull parsing.
    if (contents[file_sz - 1] != '\0') {
        char *tmp = (char *)sentry_malloc(file_sz + 1);
        if (!tmp) {
            sentry_free(contents);
            return 0;
        }
        memcpy(tmp, contents, file_sz);
        tmp[file_sz] = '\0';
        sentry_free(contents);
        contents = tmp;
    }
    errno = 0;
    char *endp = NULL;
    unsigned long long usec = strtoull(contents, &endp, 10);
    sentry_free(contents);
    if (errno != 0 || endp == contents) {
        return 0;
    }
    return (uint64_t)usec;
}

static void
wer_backend_prune_database(sentry_backend_t *UNUSED(backend))
{
    // WER backend currently does not keep a Sentry-managed minidump database
}

static void
wer_backend_user_consent_changed(sentry_backend_t *UNUSED(backend))
{
    // WER flow currently does not use persisted consent flag; placeholder.
}

static void
wer_backend_except(
    sentry_backend_t *UNUSED(backend), const sentry_ucontext_t *UNUSED(ctx))
{
    // A deliberate crash could be triggered to make WER kick in, but for now
    // this remains a no-op. Future work: implement manual dump triggering.
}

sentry_backend_t *
sentry__backend_new(void)
{
    auto *backend = SENTRY_MAKE(sentry_backend_t);
    if (!backend) {
        return nullptr;
    }
    memset(backend, 0, sizeof(sentry_backend_t));

    auto *state = SENTRY_MAKE(wer_state_t);
    if (!state) {
        sentry_free(backend);
        return nullptr;
    }
    memset(state, 0, sizeof(wer_state_t));
    state->scope_flush = false;
    state->crashed = false;

    backend->startup_func = wer_backend_startup;
    backend->shutdown_func = wer_backend_shutdown;
    backend->free_func = wer_backend_free;
    backend->flush_scope_func = wer_backend_flush_scope;
    backend->add_breadcrumb_func = wer_backend_add_breadcrumb;
    backend->user_consent_changed_func = wer_backend_user_consent_changed;
    backend->get_last_crash_func = wer_backend_last_crash;
    backend->prune_database_func = wer_backend_prune_database;
    backend->except_func = wer_backend_except;
    backend->data = state;
    backend->can_capture_after_shutdown = true;

    return backend;
}
}
