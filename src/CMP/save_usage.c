/* CMP add-in implementation; declarations are in save_usage.h.
 * Extracted without algorithm changes from CMP Rebuild4. */
#include "save_usage.h"
#include <string.h>

static uint64_t garlic_save_usage_ceil(uint64_t bytes, uint64_t unit) {
    /* Avoid the overflow possible in (bytes + unit - 1) / unit. */
    return bytes / unit + (bytes % unit != 0);
}

int garlic_save_usage(uint64_t sfo_blocks, uint64_t system_blocks, uint64_t fs_unit,
                      uint64_t fs_blocks, uint64_t fs_free, uint64_t file_bytes,
                      uint64_t image_capacity, garlic_save_usage_t *out) {
    if (!out)
        return -1;
    memset(out, 0, sizeof(*out));
    if (sfo_blocks > GARLIC_SAVE_USAGE_MAX_BLOCKS || file_bytes > GARLIC_SAVE_USAGE_MAX_BYTES ||
        image_capacity > GARLIC_SAVE_USAGE_MAX_BYTES)
        return -1;

    uint64_t fs_bytes = 0, used_bytes = 0;
    int have_stats = fs_unit != 0 || fs_blocks != 0 || fs_free != 0;
    if (have_stats) {
        if (!fs_unit || !fs_blocks || fs_free > fs_blocks || fs_unit > UINT64_MAX / fs_blocks)
            return -1;
        fs_bytes = fs_unit * fs_blocks;
        if (!fs_bytes || fs_bytes > GARLIC_SAVE_USAGE_MAX_BYTES)
            return -1;
        /* fs_blocks * fs_unit was already bounded, so this also cannot wrap. */
        used_bytes = (fs_blocks - fs_free) * fs_unit;
    }

    uint64_t capacity = sfo_blocks;
    if (!capacity && fs_bytes)
        capacity = garlic_save_usage_ceil(fs_bytes, GARLIC_SAVE_USAGE_UNIT);
    if (!capacity && image_capacity)
        capacity = garlic_save_usage_ceil(image_capacity, GARLIC_SAVE_USAGE_UNIT);
    if (!capacity || capacity > GARLIC_SAVE_USAGE_MAX_BLOCKS)
        return -1;

    int estimated = !have_stats || (!used_bytes && file_bytes != 0);
    if (estimated)
        used_bytes = file_bytes;
    uint64_t used_blocks = garlic_save_usage_ceil(used_bytes, GARLIC_SAVE_USAGE_UNIT);
    if (used_blocks > capacity)
        return -1;
    uint64_t size_kib = garlic_save_usage_ceil(used_bytes, UINT64_C(1024));
    if (size_kib > capacity * UINT64_C(64))
        return -1;

    out->blocks = capacity;
    out->free_blocks = capacity - used_blocks;
    out->size_kib = size_kib;
    out->system_blocks = system_blocks;
    out->estimated = estimated;
    return 0;
}
