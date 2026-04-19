#ifndef KWAF_LIBINJECTION_H
#define KWAF_LIBINJECTION_H

#include <stddef.h>

int kwaf_libinjection_sqli(const unsigned char *data, size_t len, char *fingerprint_out, size_t fingerprint_out_len);
int kwaf_libinjection_xss(const unsigned char *data, size_t len, char *fingerprint_out, size_t fingerprint_out_len);

#endif
