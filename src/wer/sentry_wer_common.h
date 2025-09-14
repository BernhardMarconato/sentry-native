#ifndef SENTRY_WER_COMMON_H_INCLUDED
#define SENTRY_WER_COMMON_H_INCLUDED

#include <stdint.h>
#include <wchar.h>

// Shared context structure passed from the Sentry process to the WER
// runtime exception module via WerRegisterRuntimeExceptionModule's context
// pointer. The module will ReadProcessMemory this structure out of the
// crashing process.
// Keep this versioned; extend by bumping version and appending fields.
struct sentry_wer_runtime_context {
    uint32_t version; // structure version
    uint32_t size; // sizeof(struct) as written by producer
    uint32_t flags; // flag bits (see SENTRY_WER_FLAG_*)
    wchar_t run_path[260]; // cache/run path (MAX_PATH safe subset)
    wchar_t
        minidump_url[768]; // absolute minidump URL (https://..../minidump/...)
    wchar_t proxy[260]; // full proxy spec if configured (host:port or URL)
    wchar_t user_agent[128]; // custom user agent (fallback if empty)
};
#define SENTRY_WER_RUNTIME_CONTEXT_VERSION 1u

// Shared file / multipart part name constants to keep module & backend aligned.
// Wide + narrow variants where both are commonly needed.
#define SENTRY_WER_EVENT_FILE_W L"__sentry-event"
#define SENTRY_WER_BREADCRUMB1_FILE_W L"__sentry-breadcrumb1"
#define SENTRY_WER_BREADCRUMB2_FILE_W L"__sentry-breadcrumb2"
#define SENTRY_WER_LAST_CRASH_FILE_W L"wer_last_crash"

#define SENTRY_WER_EVENT_FILE_A "__sentry-event"
#define SENTRY_WER_BREADCRUMB1_FILE_A "__sentry-breadcrumb1"
#define SENTRY_WER_BREADCRUMB2_FILE_A "__sentry-breadcrumb2"
#define SENTRY_WER_LAST_CRASH_FILE_A "wer_last_crash"

// Multipart field names
#define SENTRY_WER_MP_EVENT_PART "__sentry-event"
#define SENTRY_WER_MP_BREADCRUMB1_PART "__sentry-breadcrumb1"
#define SENTRY_WER_MP_BREADCRUMB2_PART "__sentry-breadcrumb2"
#define SENTRY_WER_MP_MINIDUMP_PART "upload_file_minidump"

// Flag bits for `flags` (forward compatible; unknown bits ignored by module)
#define SENTRY_WER_FLAG_REQUIRE_CONSENT                                        \
    0x00000001u // skip upload unless consent given

#endif // SENTRY_WER_COMMON_H_INCLUDED
