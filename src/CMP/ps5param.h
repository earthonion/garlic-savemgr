#ifndef CMP_PS5PARAM_H
#define CMP_PS5PARAM_H

/* Protected PS5 metadata I/O and its mount-scoped real-SFO cache.
 * Calls remain serialized by Garlic's existing save mutex. The cache belongs
 * to one tracked image; normal unmount/reset clears both metadata and key
 * association through the documented bridge. */
#include <stddef.h>
#include <stdint.h>
#include "common.h"

#define CMP_PS5PARAM_PATH_BYTES CMP_PATH_BYTES
#define CMP_PS5PARAM_SFO_BYTES 0x8000
#define CMP_PS5PARAM_ERROR_BYTES 512

/* Read-only views remain valid only under the existing save-mutex discipline,
 * until the next cache mutation. The module is the single storage owner. */
const uint8_t *ps5param_cache_data(void);
uint32_t ps5param_cache_size(void);
const char *ps5param_cache_image(void);
int ps5param_cache_replace(const uint8_t *sfo, uint32_t size);

const char *ps5param_error(void);
const char *ps5param_warning(void);
void ps5param_clear_error(void);
void ps5param_clear_warning(void);
void ps5param_set_error(const char *format, ...);

int sfo_bytes_valid(const uint8_t *buf, size_t size);
void ps5param_clear_cache(void);
int ps5param_cached_for_mount(const char *base);
int ps5param_is_sfo_name(const char *name);
void ps5param_elevate(void);
int ps5param_read_sfo(const char *img, uint8_t *sfo, uint32_t sfomax);
int ps5param_write_sfo(const char *img, const uint8_t *sfo, uint32_t sz);
void ps5param_capture_for_image(const char *img);

#endif
