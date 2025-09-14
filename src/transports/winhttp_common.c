#include "winhttp_common.h"

#include <string.h>

static void
set_result_defaults(sentry_winhttp_result_t *r)
{
    if (r) {
        r->status_code = 0;
        r->rate_limited = false;
    }
}

HINTERNET
sentry__winhttp_open_session(const wchar_t *user_agent, const wchar_t *proxy_w)
{
    HINTERNET session = NULL;
    if (proxy_w && *proxy_w) {
        session = WinHttpOpen(user_agent, WINHTTP_ACCESS_TYPE_NAMED_PROXY,
            proxy_w, WINHTTP_NO_PROXY_BYPASS, 0);
    } else {
#if _WIN32_WINNT >= 0x0603
        session = WinHttpOpen(user_agent, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
#endif
        if (!session) {
            session = WinHttpOpen(user_agent, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        }
    }
    return session;
}

int
sentry__winhttp_simple_post(HINTERNET session, const wchar_t *host,
    INTERNET_PORT port, bool secure, const wchar_t *path,
    const wchar_t *extra_headers, const unsigned char *body, size_t body_len,
    sentry_winhttp_result_t *out_result)
{
    set_result_defaults(out_result);
    if (!session || !host || !path) {
        return -1;
    }
    HINTERNET connect = WinHttpConnect(session, host, port, 0);
    if (!connect) {
        return -1;
    }
    DWORD flags = secure ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET request = WinHttpOpenRequest(connect, L"POST", path, NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!request) {
        WinHttpCloseHandle(connect);
        return -1;
    }
    if (!WinHttpSendRequest(request, extra_headers ? extra_headers : L"",
            (DWORD)-1, (LPVOID)body, (DWORD)body_len, (DWORD)body_len, 0)) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        return -1;
    }
    if (!WinHttpReceiveResponse(request, NULL)) {
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connect);
        return -1;
    }
    if (out_result) {
        DWORD sc = 0;
        DWORD sl = sizeof(sc);
        if (WinHttpQueryHeaders(request,
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                WINHTTP_HEADER_NAME_BY_INDEX, &sc, &sl, NULL)) {
            out_result->status_code = (unsigned)sc;
            if (sc == 429) {
                out_result->rate_limited = true;
            }
        }
    }
    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    return 0;
}
