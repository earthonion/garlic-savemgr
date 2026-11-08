/* CMP add-in implementation; declarations are in metadata_layout.h.
 * Extracted without algorithm changes from CMP Rebuild4. */
#include "metadata_layout.h"
#include "internal/save_format.h"
#include <string.h>

static int garlic_metadata_text(const uint8_t *value, size_t length, const char *expected,
                                size_t expected_length) {
    return (length == expected_length ||
            (length == expected_length + 1 && value[expected_length] == 0)) &&
           !memcmp(value, expected, expected_length);
}

static int garlic_metadata_blocks(const uint8_t *value, uint16_t format, uint32_t length,
                                  uint64_t *number) {
    /* The observed native SFO uses 0x0004 with eight bytes. Also accept its
     * four-byte form and the standard 0x0404 four-byte integer encoding. */
    if (format == 0x0004 && (length == 4 || length == 8)) {
        *number = length == 8 ? chives_le64(value) : chives_le32(value);
        return 1;
    }
    if (format == 0x0404 && length == 4) {
        *number = chives_le32(value);
        return 1;
    }
    return 0;
}

int garlic_legacy_geometry_matches(const chives_geometry_t *geometry) {
    return geometry && chives_geometry_valid(geometry) && !geometry->is_ps4 &&
           geometry->version == 2 && geometry->block_size_bytes == CMP_PFS_NATIVE_BLOCK_BYTES &&
           geometry->has_fs_ext == 1 && geometry->fs_ext == 0 &&
           geometry->backup_header_count == 1 && geometry->mode_raw == 0x000d &&
           geometry->original_image_size_bytes ==
               geometry->block_count * (uint64_t)geometry->block_size_bytes;
}

int garlic_legacy_sfo_matches(const chives_geometry_t *geometry, const uint8_t *sfo, size_t size) {
    if (!garlic_legacy_geometry_matches(geometry) || !sfo || size < CMP_SFO_HEADER_BYTES ||
        size > CMP_PS5PARAM_MAX_SFO_BYTES || memcmp(sfo, "\0PSF", 4) ||
        chives_le32(sfo + 4) != 0x00000101u)
        return 0;

    uint32_t key_offset = chives_le32(sfo + 8);
    uint32_t data_offset = chives_le32(sfo + 12);
    uint32_t entries = chives_le32(sfo + 16);
    if (!entries || entries > (size - CMP_SFO_HEADER_BYTES) / 16 ||
        key_offset < CMP_SFO_HEADER_BYTES + (size_t)entries * 16u || key_offset >= data_offset ||
        data_offset > size)
        return 0;

    unsigned seen = 0;
    uint64_t data_blocks = 0, system_blocks = 0;
    for (uint32_t i = 0; i < entries; ++i) {
        const uint8_t *entry = sfo + CMP_SFO_HEADER_BYTES + (size_t)i * 16u;
        uint16_t key_relative = chives_le16(entry);
        uint16_t format = chives_le16(entry + 2);
        uint32_t length = chives_le32(entry + 4);
        uint32_t capacity = chives_le32(entry + 8);
        uint32_t value_relative = chives_le32(entry + 12);
        if ((uint64_t)key_relative >= (uint64_t)data_offset - key_offset || length > capacity ||
            value_relative > size - data_offset || capacity > size - data_offset - value_relative)
            return 0;

        const uint8_t *key = sfo + key_offset + key_relative;
        size_t available = data_offset - (size_t)(key - sfo);
        const uint8_t *terminator = memchr(key, 0, available);
        if (!terminator || terminator == key || terminator - key > 127)
            return 0;
        size_t key_length = (size_t)(terminator - key);
        for (size_t j = 0; j < key_length; ++j)
            if (key[j] < 0x20 || key[j] > 0x7e)
                return 0;

        const uint8_t *value = sfo + data_offset + value_relative;
        unsigned field = 0;
        if (key_length == 6 && !memcmp(key, "FORMAT", 6)) {
            field = 1;
            if (format != 0x0204 || !garlic_metadata_text(value, length, "ppr", 3))
                return 0;
        } else if (key_length == 15 && !memcmp(key, "SAVEDATA_BLOCKS", 15)) {
            field = 2;
            if (!garlic_metadata_blocks(value, format, length, &data_blocks))
                return 0;
        } else if (key_length == 13 && !memcmp(key, "SYSTEM_BLOCKS", 13)) {
            field = 4;
            if (!garlic_metadata_blocks(value, format, length, &system_blocks))
                return 0;
        } else if (key_length == 8 && !memcmp(key, "TITLE_ID", 8)) {
            field = 8;
            if (format != 0x0204 || !((length == 9) || (length == 10 && value[9] == 0)) ||
                memcmp(value, "PPSA", 4))
                return 0;
            for (size_t j = 4; j < 9; ++j)
                if (value[j] < '0' || value[j] > '9')
                    return 0;
        }
        if (field && (seen & field))
            return 0;
        seen |= field;
    }
    return seen == 15 && data_blocks == geometry->block_count && system_blocks == 0;
}
