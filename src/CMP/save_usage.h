#ifndef GARLIC_SAVE_USAGE_H
#define GARLIC_SAVE_USAGE_H

#include <stdint.h>

/* savedata.db blocks/free_blocks use 64 KiB allocation units. Keep this
 * bound in step with the existing chives.json 64 GiB image-capacity bound. */
#define GARLIC_SAVE_USAGE_UNIT UINT64_C(65536)
#define GARLIC_SAVE_USAGE_MAX_BYTES (UINT64_C(64) * 1024 * 1024 * 1024)
#define GARLIC_SAVE_USAGE_MAX_BLOCKS (GARLIC_SAVE_USAGE_MAX_BYTES / GARLIC_SAVE_USAGE_UNIT)

typedef struct {
    uint64_t blocks;
    uint64_t free_blocks;
    uint64_t size_kib;
    uint64_t system_blocks;
    int estimated;
} garlic_save_usage_t;

/* Measure registration usage without modifying SFO metadata or filesystem
 * geometry. fs_* are a mounted filesystem's statfs units/counts; supply all
 * zero when native statistics are unavailable. Capacity preference is the
 * SFO's declared 64 KiB units, then the measured filesystem, then the image's
 * logical byte capacity. SYSTEM_BLOCKS is preserved, not added to that quota.
 *
 * size_kib records occupied bytes rounded up to KiB, not the whole capacity.
 * File-byte fallback is an estimate: it does not claim to include directory,
 * allocation or encryption overhead. Invalid/overflowing or over-quota values
 * fail instead of silently clamping, wrapping or inventing free space.
 */
int garlic_save_usage(uint64_t sfo_blocks, uint64_t system_blocks, uint64_t fs_unit,
                      uint64_t fs_blocks, uint64_t fs_free, uint64_t file_bytes,
                      uint64_t image_capacity, garlic_save_usage_t *out);

#endif
