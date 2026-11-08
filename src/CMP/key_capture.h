#ifndef GARLIC_KEY_CAPTURE_H
#define GARLIC_KEY_CAPTURE_H

#include <stdint.h>
#include <stddef.h>

#define GARLIC_KEY_HEADER_BYTES 4096u
#define GARLIC_KEY_JSON_BYTES 2048u
#define GARLIC_KEY_SEALED_BYTES 96u
#define GARLIC_KEY_NATIVE_BYTES 256u

enum {
    GARLIC_KEY_ERR_HEADER = -1,
    GARLIC_KEY_ERR_GEOMETRY = -2,
    GARLIC_KEY_ERR_SEALED = -3,
    GARLIC_KEY_ERR_UNWRAP = -4,
    GARLIC_KEY_ERR_EMPTY = -5,
    GARLIC_KEY_ERR_ARGUMENT = -6
};

typedef struct {
    char header_sha256[65];
    char sealed_key_sha256[65];
    char sealed_key_hex[193];
    char unwrapped_key_hex[65];
} garlic_key_capture_t;

typedef int (*garlic_key_unwrap_fn)(void *context, uint8_t *buffer, size_t capacity);

/* This result is candidate material returned by pfsmgr, not proof that the
 * complete native version-2 filesystem can be decrypted outside the PS5. */
void garlic_key_wipe(void *memory, size_t size);
int garlic_key_capture(const uint8_t *header, size_t length, uint64_t image_size,
                       garlic_key_unwrap_fn unwrap, void *context, garlic_key_capture_t *out);
int garlic_key_crypto_json(const garlic_key_capture_t *key, char *out, size_t cap);
#endif
