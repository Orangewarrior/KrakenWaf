#include "libinjection_compat.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

static void kwaf_write_fp(char *out, size_t out_len, const char *value) {
    if (out == NULL || out_len == 0) {
        return;
    }
    out[0] = '\0';
    if (value == NULL) {
        return;
    }
    snprintf(out, out_len, "%s", value);
}

static size_t kwaf_lowercase_copy(const unsigned char *data, size_t len, char *out, size_t out_len) {
    if (out_len == 0) {
        return 0;
    }
    size_t written = len < (out_len - 1) ? len : (out_len - 1);
    for (size_t i = 0; i < written; ++i) {
        out[i] = (char)tolower((unsigned char)data[i]);
    }
    out[written] = '\0';
    return written;
}

static int kwaf_contains(const char *haystack, const char *needle) {
    return haystack != NULL && needle != NULL && strstr(haystack, needle) != NULL;
}

int kwaf_libinjection_sqli(const unsigned char *data, size_t len, char *fingerprint_out, size_t fingerprint_out_len) {
    char lowered[8192];
    kwaf_lowercase_copy(data, len, lowered, sizeof(lowered));

    if (kwaf_contains(lowered, "union select")) {
        kwaf_write_fp(fingerprint_out, fingerprint_out_len, "sqli-union-select");
        return 1;
    }
    if (kwaf_contains(lowered, "information_schema")) {
        kwaf_write_fp(fingerprint_out, fingerprint_out_len, "sqli-information-schema");
        return 1;
    }
    if (kwaf_contains(lowered, "sleep(")) {
        kwaf_write_fp(fingerprint_out, fingerprint_out_len, "sqli-time-based");
        return 1;
    }
    if (kwaf_contains(lowered, "benchmark(")) {
        kwaf_write_fp(fingerprint_out, fingerprint_out_len, "sqli-benchmark");
        return 1;
    }
    if (kwaf_contains(lowered, "waitfor delay")) {
        kwaf_write_fp(fingerprint_out, fingerprint_out_len, "sqli-waitfor-delay");
        return 1;
    }
    if (kwaf_contains(lowered, "' or '1'='1") || kwaf_contains(lowered, "\" or \"1\"=\"1") || kwaf_contains(lowered, " or 1=1") || kwaf_contains(lowered, " and 1=1")) {
        kwaf_write_fp(fingerprint_out, fingerprint_out_len, "sqli-boolean-bypass");
        return 1;
    }
    return 0;
}

int kwaf_libinjection_xss(const unsigned char *data, size_t len, char *fingerprint_out, size_t fingerprint_out_len) {
    char lowered[8192];
    kwaf_lowercase_copy(data, len, lowered, sizeof(lowered));

    if (kwaf_contains(lowered, "<script")) {
        kwaf_write_fp(fingerprint_out, fingerprint_out_len, "xss-script-tag");
        return 1;
    }
    if (kwaf_contains(lowered, "javascript:")) {
        kwaf_write_fp(fingerprint_out, fingerprint_out_len, "xss-javascript-uri");
        return 1;
    }
    if (kwaf_contains(lowered, "onerror=") || kwaf_contains(lowered, "onload=") || kwaf_contains(lowered, "onmouseover=")) {
        kwaf_write_fp(fingerprint_out, fingerprint_out_len, "xss-event-handler");
        return 1;
    }
    if (kwaf_contains(lowered, "<svg") || kwaf_contains(lowered, "alert(")) {
        kwaf_write_fp(fingerprint_out, fingerprint_out_len, "xss-inline-payload");
        return 1;
    }
    return 0;
}
