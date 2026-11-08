/* CMP add-in implementation; declarations are in chives.h.
 * Extracted without algorithm changes from CMP Rebuild4. */
#include "chives.h"
#include <string.h>
#include <ctype.h>

uint16_t chives_le16(const uint8_t *p) {
    return (uint16_t)p[0] | (uint16_t)p[1] << 8;
}

uint32_t chives_le32(const uint8_t *p) {
    return (uint32_t)chives_le16(p) | (uint32_t)chives_le16(p + 2) << 16;
}

uint64_t chives_le64(const uint8_t *p) {
    return (uint64_t)chives_le32(p) | (uint64_t)chives_le32(p + 4) << 32;
}

int chives_geometry_valid(const chives_geometry_t *g) {
    if (g->version != (uint64_t)(g->is_ps4 ? 1 : 2) ||
        (g->block_size_bytes != 32768 && g->block_size_bytes != 65536) || !g->block_count ||
        g->block_count > CHIVES_MAX_IMAGE / g->block_size_bytes)
        return 0;
    if (g->has_fs_ext &&
        (g->fs_ext >= g->block_count || (g->fs_ext && (g->is_ps4 || g->block_size_bytes != 65536))))
        return 0;
    uint64_t size = g->block_count * g->block_size_bytes;
    return size >= (uint64_t)g->block_size_bytes * 2 && g->original_image_size_bytes >= 0x40 &&
           g->original_image_size_bytes <= CHIVES_MAX_IMAGE;
}

int chives_from_header(const uint8_t *p, size_t len, uint64_t file_size, chives_geometry_t *g) {
    if (len < 0x40 || chives_le64(p + 8) != UINT64_C(20130315))
        return -1;
    memset(g, 0, sizeof(*g));
    g->version = chives_le64(p);
    g->is_ps4 = g->version == 1;
    g->mode_raw = chives_le16(p + 0x1c);
    g->block_size_bytes = chives_le32(p + 0x20);
    g->backup_header_count = chives_le32(p + 0x24);
    if (g->is_ps4)
        return -1; /* PS4 sizing is deliberately left on its existing path. */
    g->block_count = chives_le64(p + 0x38);
    g->original_image_size_bytes = file_size;
    if (len >= 0x36c) {
        g->fs_ext = chives_le32(p + 0x368);
        g->has_fs_ext = 1;
    }
    return chives_geometry_valid(g) ? 0 : -1;
}

/* Small bounded JSON reader. Only plain ASCII keys are needed by this schema;
 * unknown values are parsed and skipped, never searched by substring. */
typedef struct {
    const char *p, *end;
    unsigned depth;
} chives_json_t;

static void chives_ws(chives_json_t *j) {
    while (j->p < j->end && (*j->p == ' ' || *j->p == '\t' || *j->p == '\r' || *j->p == '\n'))
        j->p++;
}

static int chives_string(chives_json_t *j, char *out, size_t cap) {
    chives_ws(j);
    if (j->p == j->end || *j->p++ != '"')
        return -1;
    size_t n = 0;
    while (j->p < j->end) {
        unsigned char c = (unsigned char)*j->p++;
        if (c == '"') {
            if (out && cap)
                out[n < cap ? n : cap - 1] = 0;
            return 0;
        }
        if (c < 32)
            return -1;
        if (c == '\\') {
            if (j->p == j->end)
                return -1;
            c = (unsigned char)*j->p++;
            if (c == 'u') {
                unsigned v = 0;
                for (int i = 0; i < 4; i++) {
                    if (j->p == j->end || !isxdigit((unsigned char)*j->p))
                        return -1;
                    unsigned char h = (unsigned char)*j->p++;
                    v = v * 16 + (h <= '9' ? h - '0' : (h | 32) - 'a' + 10);
                }
                c = v > 0 && v < 128 ? (unsigned char)v : '?';
            } else if (c == 'b')
                c = '\b';
            else if (c == 'f')
                c = '\f';
            else if (c == 'n')
                c = '\n';
            else if (c == 'r')
                c = '\r';
            else if (c == 't')
                c = '\t';
            else if (c != '"' && c != '\\' && c != '/')
                return -1;
        }
        if (out && n + 1 < cap)
            out[n] = (char)c;
        n++;
    }
    return -1;
}

static int chives_uint(chives_json_t *j, uint64_t *v) {
    chives_ws(j);
    if (j->p == j->end || *j->p < '0' || *j->p > '9')
        return -1;
    uint64_t n = 0;
    const char *start = j->p;
    do {
        unsigned d = (unsigned)(*j->p++ - '0');
        if (n > (UINT64_MAX - d) / 10)
            return -1;
        n = n * 10 + d;
    } while (j->p < j->end && *j->p >= '0' && *j->p <= '9');
    if (j->p - start > 1 && *start == '0')
        return -1;
    *v = n;
    return 0;
}

static int chives_skip(chives_json_t *j) {
    chives_ws(j);
    if (j->p == j->end || j->depth > 12)
        return -1;
    if (*j->p == '"')
        return chives_string(j, NULL, 0);
    if (*j->p == '{' || *j->p == '[') {
        int object = *j->p++ == '{';
        char close = object ? '}' : ']';
        j->depth++;
        chives_ws(j);
        if (j->p < j->end && *j->p == close) {
            j->p++;
            j->depth--;
            return 0;
        }
        for (;;) {
            if (object) {
                if (chives_string(j, NULL, 0) < 0)
                    return -1;
                chives_ws(j);
                if (j->p == j->end || *j->p++ != ':')
                    return -1;
            }
            if (chives_skip(j) < 0)
                return -1;
            chives_ws(j);
            if (j->p == j->end)
                return -1;
            if (*j->p == close) {
                j->p++;
                j->depth--;
                return 0;
            }
            if (*j->p++ != ',')
                return -1;
        }
    }
    for (int i = 0; i < 3; i++) {
        const char *w = i == 0 ? "true" : i == 1 ? "false" : "null";
        size_t n = strlen(w);
        if ((size_t)(j->end - j->p) >= n && !memcmp(j->p, w, n)) {
            j->p += n;
            return 0;
        }
    }
    /* Unknown numeric fields may be signed/fractional JSON numbers. */
    if (*j->p == '-') {
        j->p++;
        if (j->p == j->end || !isdigit((unsigned char)*j->p))
            return -1;
    }
    uint64_t unused;
    if (chives_uint(j, &unused) < 0)
        return -1;
    if (j->p < j->end && *j->p == '.') {
        j->p++;
        const char *s = j->p;
        while (j->p < j->end && isdigit((unsigned char)*j->p))
            j->p++;
        if (j->p == s)
            return -1;
    }
    if (j->p < j->end && (*j->p == 'e' || *j->p == 'E')) {
        j->p++;
        if (j->p < j->end && (*j->p == '+' || *j->p == '-'))
            j->p++;
        const char *s = j->p;
        while (j->p < j->end && isdigit((unsigned char)*j->p))
            j->p++;
        if (j->p == s)
            return -1;
    }
    return 0;
}

static int chives_pfs(chives_json_t *j, chives_geometry_t *g) {
    unsigned seen = 0;
    chives_ws(j);
    if (j->p == j->end || *j->p++ != '{')
        return -1;
    for (;;) {
        char key[64];
        uint64_t v;
        if (chives_string(j, key, sizeof(key)) < 0)
            return -1;
        chives_ws(j);
        if (j->p == j->end || *j->p++ != ':')
            return -1;
        unsigned bit = !strcmp(key, "version")               ? 1
                       : !strcmp(key, "block_size_bytes")    ? 2
                       : !strcmp(key, "block_count")         ? 4
                       : !strcmp(key, "mode_raw")            ? 8
                       : !strcmp(key, "backup_header_count") ? 16
                       : !strcmp(key, "fs_ext")              ? 32
                                                             : 0;
        if (bit) {
            if (seen & bit || chives_uint(j, &v) < 0)
                return -1;
            seen |= bit;
            if (bit == 1)
                g->version = v;
            if (bit == 2) {
                if (v > UINT32_MAX)
                    return -1;
                g->block_size_bytes = (uint32_t)v;
            }
            if (bit == 4)
                g->block_count = v;
            if (bit == 8) {
                if (v > UINT16_MAX)
                    return -1;
                g->mode_raw = (uint16_t)v;
            }
            if (bit == 32) {
                if (v > UINT32_MAX)
                    return -1;
                g->fs_ext = (uint32_t)v;
                g->has_fs_ext = 1;
            }
            if (bit == 16) {
                if (v > UINT32_MAX)
                    return -1;
                g->backup_header_count = (uint32_t)v;
            }
        } else if (chives_skip(j) < 0)
            return -1;
        chives_ws(j);
        if (j->p == j->end)
            return -1;
        if (*j->p == '}') {
            j->p++;
            return (seen & 7) == 7 ? 0 : -1;
        }
        if (*j->p++ != ',')
            return -1;
    }
}

int chives_parse(const char *json, size_t len, chives_geometry_t *g) {
    if (!len || len > CHIVES_MAX_JSON)
        return -1;
    chives_json_t j = {json, json + len, 0};
    memset(g, 0, sizeof(*g));
    chives_ws(&j);
    if (j.p == j.end || *j.p++ != '{')
        return -1;
    unsigned seen = 0;
    for (;;) {
        char key[64], text[32];
        uint64_t v;
        if (chives_string(&j, key, sizeof(key)) < 0)
            return -1;
        chives_ws(&j);
        if (j.p == j.end || *j.p++ != ':')
            return -1;
        unsigned bit = !strcmp(key, "schema_version")              ? 1
                       : !strcmp(key, "platform")                  ? 2
                       : !strcmp(key, "original_image_size_bytes") ? 4
                       : !strcmp(key, "pfs")                       ? 8
                                                                   : 0;
        if (bit && seen & bit)
            return -1;
        seen |= bit;
        if (bit == 1) {
            if (chives_uint(&j, &v) < 0 || v != 1)
                return -1;
        } else if (bit == 2) {
            if (chives_string(&j, text, sizeof(text)) < 0 ||
                (strcmp(text, "PS4") && strcmp(text, "PS5")))
                return -1;
            g->is_ps4 = !strcmp(text, "PS4");
        } else if (bit == 4) {
            if (chives_uint(&j, &g->original_image_size_bytes) < 0)
                return -1;
        } else if (bit == 8) {
            if (chives_pfs(&j, g) < 0)
                return -1;
        } else if (chives_skip(&j) < 0)
            return -1;
        chives_ws(&j);
        if (j.p == j.end)
            return -1;
        if (*j.p == '}') {
            j.p++;
            break;
        }
        if (*j.p++ != ',')
            return -1;
    }
    chives_ws(&j);
    return j.p == j.end && seen == 15 && !g->is_ps4 && chives_geometry_valid(g) ? 0 : -1;
}

int chives_path_safe(const char *name) {
    if (!name[0] || name[0] == '/' || strchr(name, '\\') || strchr(name, ':'))
        return 0;
    const char *p = name;
    while (*p) {
        const char *end = strchr(p, '/');
        size_t n = end ? (size_t)(end - p) : strlen(p);
        if (!n || (n == 1 && *p == '.') || (n == 2 && p[0] == '.' && p[1] == '.'))
            return 0;
        if (!end)
            break;
        p = end + 1;
    }
    return 1;
}

int chives_is_sidecar(const char *name) {
    while (name[0] == '.' && name[1] == '/')
        name += 2;
    const char *expected = "chives.json";
    while (*name && *expected && tolower((unsigned char)*name) == *expected) {
        name++;
        expected++;
    }
    return !*name && !*expected;
}

int chives_zip_next(const uint8_t *data, size_t len, size_t *offset, char *name, size_t name_cap,
                    const uint8_t **payload, size_t *payload_len) {
    size_t off = *offset;
    if (off > len || len - off < 4)
        return -1;
    uint32_t sig = chives_le32(data + off);
    if (sig == UINT32_C(0x02014b50) || sig == UINT32_C(0x06054b50))
        return 0;
    if (sig != UINT32_C(0x04034b50) || len - off < 30)
        return -1;
    uint16_t flags = chives_le16(data + off + 6), method = chives_le16(data + off + 8);
    uint32_t packed = chives_le32(data + off + 18), plain = chives_le32(data + off + 22);
    size_t nlen = chives_le16(data + off + 26), extra = chives_le16(data + off + 28);
    if (flags & 9 || method != 0 || packed != plain || !nlen || nlen >= name_cap ||
        nlen + extra > len - off - 30)
        return -1;
    size_t start = off + 30 + nlen + extra;
    if (packed > len - start || memchr(data + off + 30, 0, nlen))
        return -1;
    memcpy(name, data + off + 30, nlen);
    name[nlen] = 0;
    if (!chives_path_safe(name))
        return -1;
    *payload = data + start;
    *payload_len = plain;
    *offset = start + packed;
    return 1;
}
