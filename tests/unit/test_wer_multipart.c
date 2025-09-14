#include "sentry_alloc.h"
#include "sentry_string.h"
#include "sentry_testsupport.h"
#include "wer/sentry_wer_common.h"

// Local replica of append_part logic extracted from module for testing.
static int
test_append_part(sentry_stringbuilder_t *sbuilder, const char *boundary_str,
    const char *name, const char *filename, const unsigned char *data,
    size_t len, int add_crlf)
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

static int
build_multipart_body_for_test(bool have_event, const unsigned char *event_data,
    size_t event_len, bool have_bc1, const unsigned char *bc1_data,
    size_t bc1_len, bool have_bc2, const unsigned char *bc2_data,
    size_t bc2_len, const unsigned char *dump_data, size_t dump_len,
    const char *boundary, char **out_body, size_t *out_len)
{
    if (!dump_data || !dump_len || !boundary || !out_body || !out_len) {
        return 1;
    }
    sentry_stringbuilder_t sb;
    sentry__stringbuilder_init(&sb);
    int err = 0;
    if (have_event && !err)
        err = test_append_part(&sb, boundary, SENTRY_WER_MP_EVENT_PART,
            SENTRY_WER_MP_EVENT_PART, event_data, event_len, 1);
    if (have_bc1 && !err)
        err = test_append_part(&sb, boundary, SENTRY_WER_MP_BREADCRUMB1_PART,
            SENTRY_WER_MP_BREADCRUMB1_PART, bc1_data, bc1_len, 1);
    if (have_bc2 && !err)
        err = test_append_part(&sb, boundary, SENTRY_WER_MP_BREADCRUMB2_PART,
            SENTRY_WER_MP_BREADCRUMB2_PART, bc2_data, bc2_len, 1);
    if (!err)
        err = test_append_part(&sb, boundary, SENTRY_WER_MP_MINIDUMP_PART,
            "dump.dmp", dump_data, dump_len, 0);
    if (!err) {
        char foot[96];
        int w = snprintf(foot, sizeof(foot), "\r\n--%s--\r\n", boundary);
        if (w < 0 || (size_t)w >= sizeof(foot)
            || sentry__stringbuilder_append(&sb, foot))
            err = 1;
    }
    if (err) {
        sentry__stringbuilder_cleanup(&sb);
        return 1;
    }
    *out_len = sentry__stringbuilder_len(&sb);
    *out_body = sentry__stringbuilder_into_string(&sb);
    return 0;
}

SENTRY_TEST(wer_multipart_basic)
{
    const char *boundary = "----sentry-test-boundary";
    const unsigned char dump[] = { 0x44, 0x4d, 0x50 };
    char *body = NULL;
    size_t len = 0;
    int rv = build_multipart_body_for_test(false, NULL, 0, false, NULL, 0,
        false, NULL, 0, dump, sizeof(dump), boundary, &body, &len);
    TEST_CHECK(rv == 0);
    TEST_CHECK(body != NULL);
    TEST_CHECK(len > 0);
    // Must start with first part header
    TEST_CHECK(strstr(body, "upload_file_minidump") != NULL);
    // Must end with boundary terminator
    TEST_CHECK(len >= strlen(boundary));
    TEST_CHECK(strstr(body, "--sentry-test-boundary--") != NULL);
    sentry_free(body);
}

SENTRY_TEST(wer_multipart_with_event_and_breadcrumbs)
{
    const char *boundary = "----sentry-test-boundary2";
    const unsigned char dump[] = { 0x44 };
    const unsigned char ev[] = { 0x01, 0x02 };
    const unsigned char bc1[] = { 0x11 };
    const unsigned char bc2[] = { 0x22, 0x23 };
    char *body = NULL;
    size_t len = 0;
    int rv = build_multipart_body_for_test(true, ev, sizeof(ev), true, bc1,
        sizeof(bc1), true, bc2, sizeof(bc2), dump, sizeof(dump), boundary,
        &body, &len);
    TEST_CHECK(rv == 0);
    TEST_CHECK(body && len);
    const char *p_event = strstr(body, SENTRY_WER_MP_EVENT_PART);
    const char *p_bc1 = strstr(body, SENTRY_WER_MP_BREADCRUMB1_PART);
    const char *p_bc2 = strstr(body, SENTRY_WER_MP_BREADCRUMB2_PART);
    const char *p_dump = strstr(body, SENTRY_WER_MP_MINIDUMP_PART);
    TEST_CHECK(p_event && p_bc1 && p_bc2 && p_dump);
    // Order: event < bc1 < bc2 < dump
    TEST_CHECK(p_event < p_bc1 && p_bc1 < p_bc2 && p_bc2 < p_dump);
    TEST_CHECK(strstr(body, "--sentry-test-boundary2--") != NULL);
    sentry_free(body);
}

SENTRY_TEST(wer_multipart_invalid_args)
{
    char *body = NULL;
    size_t len = 0;
    int rv = build_multipart_body_for_test(false, NULL, 0, false, NULL, 0,
        false, NULL, 0, NULL, 0, "b", &body, &len);
    TEST_CHECK(rv != 0);
    TEST_CHECK(body == NULL);
}
