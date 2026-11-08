#ifndef GARLIC_PFS_DIAGNOSTICS_H
#define GARLIC_PFS_DIAGNOSTICS_H

#include <stddef.h>

#define GARLIC_PFS_DIAG_MAX_INPUT (256u * 1024u)
enum {
    GARLIC_PFS_DIAG_NONE = 0,
    GARLIC_PFS_DIAG_HASH = 1,
    GARLIC_PFS_DIAG_ENCRYPT = 2,
    GARLIC_PFS_DIAG_BACKING_WRITE = 3
};
typedef struct {
    int kind, error, line, fresh;
    char text[512];
} garlic_pfs_diag_t;

/* A non-NULL, empty baseline is known empty. A NULL baseline, insufficient
 * ring overlap or failed allocation yields fresh=0: a recent record, never
 * attributed to the current operation. When overlap proves a fresh slice,
 * only that slice is parsed, so stale matching errors cannot be reused. */
int garlic_pfs_diag_find(const void *before_data, size_t blen, const void *after_data, size_t alen,
                         int wanted_errno, garlic_pfs_diag_t *out);

#endif
