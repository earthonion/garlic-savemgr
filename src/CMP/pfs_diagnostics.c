/* CMP add-in implementation; declarations are in pfs_diagnostics.h.
 * Extracted without algorithm changes from CMP Rebuild4. */
#include "pfs_diagnostics.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

static int garlic_pfs_diag_word(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
}

static int garlic_pfs_diag_decimal(const unsigned char **cursor, const unsigned char *end,
                                   int *value) {
    const unsigned char *p = *cursor;
    int n = 0;
    if (p == end || *p < '0' || *p > '9')
        return 0;
    do {
        int digit = *p - '0';
        if (n > (INT_MAX - digit) / 10)
            return 0;
        n = n * 10 + digit;
        p++;
    } while (p < end && *p >= '0' && *p <= '9');
    *cursor = p;
    *value = n;
    return 1;
}

/* The native format is "%s() line=%d error=%d 0x%x\n". Match its
 * function/line/error fields together, never an unrelated errno elsewhere.
 * A kernel timestamp/priority prefix is allowed before the function name. */
static int garlic_pfs_diag_record(const unsigned char *start, const unsigned char *end, int wanted,
                                  const unsigned char **record, int *line) {
    static const char hash[] = "set_icv() line=";
    static const char block[] = "zblock() line=";
    for (const unsigned char *p = start; p < end; p++) {
        if (p > start && garlic_pfs_diag_word(p[-1]))
            continue;
        size_t prefix;
        int is_hash;
        if ((size_t)(end - p) >= sizeof(hash) - 1 && memcmp(p, hash, sizeof(hash) - 1) == 0) {
            prefix = sizeof(hash) - 1;
            is_hash = 1;
        } else if ((size_t)(end - p) >= sizeof(block) - 1 &&
                   memcmp(p, block, sizeof(block) - 1) == 0) {
            prefix = sizeof(block) - 1;
            is_hash = 0;
        } else
            continue;
        const unsigned char *q = p + prefix;
        int source_line, error;
        if (!garlic_pfs_diag_decimal(&q, end, &source_line) || (size_t)(end - q) < 7 ||
            memcmp(q, " error=", 7))
            continue;
        q += 7;
        if (!garlic_pfs_diag_decimal(&q, end, &error) || error != wanted ||
            (q < end && *q != ' ' && *q != '\t'))
            continue;
        int kind = is_hash               ? (source_line == 418 ? GARLIC_PFS_DIAG_HASH : 0)
                   : source_line == 9939 ? GARLIC_PFS_DIAG_ENCRYPT
                   : source_line == 9974 ? GARLIC_PFS_DIAG_BACKING_WRITE
                                         : 0;
        if (kind) {
            *record = p;
            *line = source_line;
            return kind;
        }
    }
    return GARLIC_PFS_DIAG_NONE;
}

/* KMP finds the longest suffix of before equal to a prefix of after in
 * O(blen + alen) time. The largest allocation is 1 MiB. On allocation failure
 * freshness is unknown; callers can still show a clearly labelled recent log. */
static int garlic_pfs_diag_overlap(const unsigned char *before, size_t blen,
                                   const unsigned char *after, size_t alen, size_t *overlap) {
    if (!alen) {
        *overlap = 0;
        return 1;
    }
    uint32_t *prefix = malloc(alen * sizeof(*prefix));
    if (!prefix)
        return 0;
    prefix[0] = 0;
    for (size_t i = 1, matched = 0; i < alen; i++) {
        while (matched && after[i] != after[matched])
            matched = prefix[matched - 1];
        if (after[i] == after[matched])
            matched++;
        prefix[i] = (uint32_t)matched;
    }
    size_t matched = 0;
    for (size_t i = 0; i < blen; i++) {
        while (matched && (matched == alen || before[i] != after[matched]))
            matched = prefix[matched - 1];
        if (before[i] == after[matched])
            matched++;
    }
    free(prefix);
    *overlap = matched;
    return 1;
}

int garlic_pfs_diag_find(const void *before_data, size_t blen, const void *after_data, size_t alen,
                         int wanted_errno, garlic_pfs_diag_t *out) {
    if (!out)
        return 0;
    memset(out, 0, sizeof(*out));
    if (!after_data || wanted_errno < 0)
        return 0;
    const unsigned char *before = before_data, *after = after_data;
    if (alen > GARLIC_PFS_DIAG_MAX_INPUT) {
        after += alen - GARLIC_PFS_DIAG_MAX_INPUT;
        alen = GARLIC_PFS_DIAG_MAX_INPUT;
    }
    if (before && blen > GARLIC_PFS_DIAG_MAX_INPUT) {
        before += blen - GARLIC_PFS_DIAG_MAX_INPUT;
        blen = GARLIC_PFS_DIAG_MAX_INPUT;
    }
    while (alen && !after[alen - 1])
        alen--;
    if (before)
        while (blen && !before[blen - 1])
            blen--;
    size_t offset = 0;
    int fresh = 0;
    if (before) {
        if (!blen)
            fresh = 1;
        else {
            size_t overlap;
            if (garlic_pfs_diag_overlap(before, blen, after, alen, &overlap) &&
                overlap >= (blen < 512 ? blen : 512)) {
                offset = overlap;
                fresh = 1;
            }
        }
    }
    struct {
        int kind, line;
        char text[166];
    } saved[3];
    unsigned records = 0;
    while (offset < alen && (!fresh || records < 3)) {
        size_t begin = offset;
        while (offset < alen && after[offset] != '\n' && after[offset] != '\r' && after[offset])
            offset++;
        const unsigned char *end = after + offset, *record = NULL;
        int line, kind = garlic_pfs_diag_record(after + begin, end, wanted_errno, &record, &line);
        if (kind) {
            unsigned slot = records % 3;
            saved[slot].kind = kind;
            saved[slot].line = line;
            /* Keep the classified native record even if a long kernel prefix
             * precedes it. At most 165 bytes per record leaves room for three. */
            size_t n = (size_t)(end - record);
            if (n > 165)
                n = 165;
            for (size_t i = 0; i < n; i++) {
                unsigned char c = record[i];
                saved[slot].text[i] = c < 32 || c > 126 ? ' ' : (char)c;
            }
            saved[slot].text[n] = 0;
            records++;
        }
        if (offset < alen)
            offset++;
    }
    if (!records)
        return 0;
    /* Proven fresh data keeps the first causal records. Unknown freshness
     * keeps the latest three matches from the ring, explicitly labelled 0. */
    unsigned first = records > 3 ? records % 3 : 0;
    unsigned count = records < 3 ? records : 3;
    out->kind = saved[first].kind;
    out->line = saved[first].line;
    out->error = wanted_errno;
    out->fresh = fresh;
    size_t used = 0;
    for (unsigned i = 0; i < count; i++) {
        if (i) {
            memcpy(out->text + used, " | ", 3);
            used += 3;
        }
        const char *text = saved[(first + i) % 3].text;
        size_t n = strlen(text);
        memcpy(out->text + used, text, n);
        used += n;
    }
    out->text[used] = 0;
    return 1;
}
