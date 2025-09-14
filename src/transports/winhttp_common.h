#ifndef SENTRY_WINHTTP_COMMON_H_INCLUDED
#define SENTRY_WINHTTP_COMMON_H_INCLUDED

#include <stdbool.h>
#include <stddef.h>
#ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winhttp.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Result of a simple synchronous WinHTTP POST */
typedef struct sentry_winhttp_result_s {
    unsigned status_code; /* 0 if request not sent */
    bool rate_limited; /* true if 429 or rate-limit header triggered */
} sentry_winhttp_result_t;

/* Open (or reuse) a WinHTTP session. Returns NULL on failure. */
HINTERNET sentry__winhttp_open_session(
    const wchar_t *user_agent, const wchar_t *proxy_w);

/* Perform a one-shot POST. Returns 0 on success (HTTP layer executed). */
int sentry__winhttp_simple_post(HINTERNET session, const wchar_t *host,
    INTERNET_PORT port, bool secure, const wchar_t *path,
    const wchar_t *extra_headers, /* may be NULL, CRLF terminated lines */
    const unsigned char *body, size_t body_len,
    sentry_winhttp_result_t *out_result);

#ifdef __cplusplus
}
#endif

#endif /* SENTRY_WINHTTP_COMMON_H_INCLUDED */
