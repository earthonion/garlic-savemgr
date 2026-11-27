#ifndef GARLIC_JSON_ESCAPE_H
#define GARLIC_JSON_ESCAPE_H

#include <stddef.h>

static void json_escape(const char *in, char *out, size_t out_sz) {
    size_t n = 0;
    if (!out_sz) return;
    for (const unsigned char *p = (const unsigned char *)in; p && *p && n + 1 < out_sz; p++) {
        if ((*p == '"' || *p == '\\') && n + 2 < out_sz) {
            out[n++] = '\\';
            out[n++] = (char)*p;
        } else if (*p == '\n' && n + 2 < out_sz) {
            out[n++] = '\\';
            out[n++] = 'n';
        } else if (*p == '\r' && n + 2 < out_sz) {
            out[n++] = '\\';
            out[n++] = 'r';
        } else if (*p == '\t' && n + 2 < out_sz) {
            out[n++] = '\\';
            out[n++] = 't';
        } else if (*p >= 0x20) {
            out[n++] = (char)*p;
        }
    }
    out[n] = 0;
}

#endif
