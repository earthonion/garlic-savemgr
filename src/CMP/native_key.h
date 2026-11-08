#ifndef CMP_NATIVE_KEY_H
#define CMP_NATIVE_KEY_H

#include <stddef.h>
#include <stdint.h>
#include "common.h"
#include "key_capture.h"

#define CMP_NATIVE_KEY_PATH_BYTES CMP_PATH_BYTES

/* Cache calls retain Garlic's existing save-mutex discipline. A read copies
 * a snapshot only when the exact image association is valid. */
void save_key_clear_cache(void);
int save_key_cached_image(const char *image, garlic_key_capture_t *capture, uint64_t *source_size);

int save_key_capture_image(const char *image, garlic_key_capture_t *capture, uint64_t *source_size);
void save_key_cache_image(const char *image);

#endif
