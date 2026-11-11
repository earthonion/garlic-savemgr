#ifndef GARLIC_CHIVES_H
#define GARLIC_CHIVES_H

#include <stdint.h>
#include <stddef.h>

#define CHIVES_MAX_JSON 8192
#define CHIVES_MAX_IMAGE (UINT64_C(64) * 1024 * 1024 * 1024)
typedef struct {
    uint64_t version, block_count, original_image_size_bytes;
    uint32_t block_size_bytes, backup_header_count, fs_ext;
    int has_fs_ext;
    uint16_t mode_raw;
    int is_ps4;
    char encrypted_name[256];
} chives_geometry_t;

uint16_t chives_le16(const uint8_t *p);
uint32_t chives_le32(const uint8_t *p);
uint64_t chives_le64(const uint8_t *p);
int chives_geometry_valid(const chives_geometry_t *g);
/* The PS5 savedata superblock is at offset zero. Its logical block
 * count is at 0x38 (verified against original and recreated save images).
 * Physical file size can differ from the declared logical capacity. */
int chives_from_header(const uint8_t *p, size_t len, uint64_t file_size, chives_geometry_t *g);

int chives_parse(const char *json, size_t len, chives_geometry_t *g);

int chives_path_safe(const char *name);
int chives_is_sidecar(const char *name);
/* Supports stored and deflated entries with known local lengths. */
int chives_zip_next(const uint8_t *data, size_t len, size_t *offset, char *name, size_t name_cap,
                    const uint8_t **payload, size_t *payload_len);
#endif
