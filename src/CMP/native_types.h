#ifndef CMP_NATIVE_TYPES_H
#define CMP_NATIVE_TYPES_H

#include <stdint.h>

/* Existing PS5 native ABIs, shared with Garlic's platform adapter. */
typedef struct {
    uint8_t reserved;
    char *budgetid;
} MountOpt;
typedef struct {
    uint8_t dummy;
} UmountOpt;

typedef struct {
    int blockSize;
    uint8_t flags[2];
} CreateOpt;
typedef int (*PprCreateFn)(CreateOpt *opt, const char *path, int x, uint64_t size);

int sceFsInitUmountSaveDataOpt(UmountOpt *opt);
int sceFsUmountSaveData(UmountOpt *opt, const char *mount, int handle, int ignore);

#endif
