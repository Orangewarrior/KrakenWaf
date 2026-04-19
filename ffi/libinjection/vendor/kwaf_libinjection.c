#include "kwaf_libinjection.h"
#include "libinjection.h"
#include "libinjection_xss.h"

#include <stdio.h>
#include <string.h>

void kwaf_write_fp(char *out, size_t out_len, const char *value) {
    if (out == NULL || out_len == 0) return;
    out[0] = '\0';
    if (value == NULL) return;
    snprintf(out, out_len, "%s", value);
}

int kwaf_libinjection_sqli(const unsigned char *data, size_t len, char *fingerprint_out, size_t fingerprint_out_len) {
    char fp[8] = {0};
    injection_result_t result = libinjection_sqli((const char *)data, len, fp);
    if (result == LIBINJECTION_RESULT_TRUE) {
        kwaf_write_fp(fingerprint_out, fingerprint_out_len, fp);
        return 1;
    }
    kwaf_write_fp(fingerprint_out, fingerprint_out_len, "");
    return 0;
}

int kwaf_libinjection_xss(const unsigned char *data, size_t len, char *fingerprint_out, size_t fingerprint_out_len) {
    injection_result_t result = libinjection_xss((const char *)data, len);
    if (result == LIBINJECTION_RESULT_TRUE) {
        kwaf_write_fp(fingerprint_out, fingerprint_out_len, "xss-match");
        return 1;
    }
    kwaf_write_fp(fingerprint_out, fingerprint_out_len, "");
    return 0;
}
