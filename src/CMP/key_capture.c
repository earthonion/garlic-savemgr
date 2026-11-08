/* CMP add-in implementation; declarations are in key_capture.h.
 * Extracted without algorithm changes from CMP Rebuild4. */
#include "key_capture.h"
#include "internal/save_format.h"
#include "chives.h"
#include <stdio.h>
#include <string.h>

_Static_assert(GARLIC_KEY_SEALED_BYTES == CMP_PFS_SEALED_KEY_BYTES, "sealed key record capacity");

void garlic_key_wipe(void *memory, size_t size) {
    volatile uint8_t *p = (volatile uint8_t *)memory;
    while (size--)
        *p++ = 0;
}

static uint32_t garlic_key_rotr(uint32_t value, unsigned bits) {
    return (value >> bits) | (value << (32 - bits));
}

static void garlic_key_sha256_block(uint32_t state[8], const uint8_t block[64]) {
    static const uint32_t k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2};
    uint32_t w[64];
    for (unsigned i = 0; i < 16; i++) {
        const uint8_t *p = block + i * 4;
        w[i] = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
    }
    for (unsigned i = 16; i < 64; i++) {
        uint32_t x = w[i - 15], y = w[i - 2];
        uint32_t s0 = garlic_key_rotr(x, 7) ^ garlic_key_rotr(x, 18) ^ (x >> 3);
        uint32_t s1 = garlic_key_rotr(y, 17) ^ garlic_key_rotr(y, 19) ^ (y >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
    for (unsigned i = 0; i < 64; i++) {
        uint32_t sum1 = garlic_key_rotr(e, 6) ^ garlic_key_rotr(e, 11) ^ garlic_key_rotr(e, 25);
        uint32_t choose = (e & f) ^ (~e & g);
        uint32_t t1 = h + sum1 + choose + k[i] + w[i];
        uint32_t sum0 = garlic_key_rotr(a, 2) ^ garlic_key_rotr(a, 13) ^ garlic_key_rotr(a, 22);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = sum0 + majority;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
    garlic_key_wipe(w, sizeof(w));
}

static void garlic_key_sha256(const uint8_t *data, size_t size, uint8_t digest[32]) {
    uint32_t state[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                         0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    uint64_t bit_length = (uint64_t)size * 8;
    while (size >= 64) {
        garlic_key_sha256_block(state, data);
        data += 64;
        size -= 64;
    }
    uint8_t tail[128];
    memset(tail, 0, sizeof(tail));
    if (size)
        memcpy(tail, data, size);
    tail[size] = 0x80;
    size_t padded = size < 56 ? 64 : 128;
    for (unsigned i = 0; i < 8; i++)
        tail[padded - 1 - i] = (uint8_t)(bit_length >> (8 * i));
    garlic_key_sha256_block(state, tail);
    if (padded == 128)
        garlic_key_sha256_block(state, tail + 64);
    for (unsigned i = 0; i < 8; i++) {
        digest[i * 4] = (uint8_t)(state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)state[i];
    }
    garlic_key_wipe(tail, sizeof(tail));
    garlic_key_wipe(state, sizeof(state));
}

static void garlic_key_hex(const uint8_t *data, size_t size, char *out) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < size; i++) {
        out[2 * i] = digits[data[i] >> 4];
        out[2 * i + 1] = digits[data[i] & 15];
    }
    out[2 * size] = 0;
}

static int garlic_key_nonzero(const uint8_t *data, size_t size) {
    uint8_t value = 0;
    for (size_t i = 0; i < size; i++)
        value |= data[i];
    return value != 0;
}

int garlic_key_capture(const uint8_t *header, size_t length, uint64_t image_size,
                       garlic_key_unwrap_fn unwrap, void *context, garlic_key_capture_t *out) {
    if (out)
        memset(out, 0, sizeof(*out));
    if (!header || !unwrap || !out)
        return GARLIC_KEY_ERR_ARGUMENT;
    if (length != GARLIC_KEY_HEADER_BYTES || image_size < GARLIC_KEY_HEADER_BYTES)
        return GARLIC_KEY_ERR_HEADER;
    chives_geometry_t geometry;
    if (chives_from_header(header, length, image_size, &geometry) < 0 || geometry.is_ps4)
        return GARLIC_KEY_ERR_GEOMETRY;
    const uint8_t *sealed = header + CMP_PFS_SEALED_KEY_OFFSET;
    if (memcmp(sealed, "pfsSKKey", 8) || garlic_key_nonzero(sealed + 10, 6) ||
        !garlic_key_nonzero(sealed + 0x20, 32))
        return GARLIC_KEY_ERR_SEALED;
    uint8_t native[GARLIC_KEY_NATIVE_BYTES];
    memset(native, 0, sizeof(native));
    memcpy(native, sealed, GARLIC_KEY_SEALED_BYTES);
    int result = unwrap(context, native, sizeof(native));
    if (result < 0) {
        garlic_key_wipe(native, sizeof(native));
        return GARLIC_KEY_ERR_UNWRAP;
    }
    if (!garlic_key_nonzero(native + 0x60, 32)) {
        garlic_key_wipe(native, sizeof(native));
        return GARLIC_KEY_ERR_EMPTY;
    }
    uint8_t digest[32];
    garlic_key_sha256(header, length, digest);
    garlic_key_hex(digest, 32, out->header_sha256);
    garlic_key_sha256(sealed, GARLIC_KEY_SEALED_BYTES, digest);
    garlic_key_hex(digest, 32, out->sealed_key_sha256);
    garlic_key_hex(sealed, GARLIC_KEY_SEALED_BYTES, out->sealed_key_hex);
    garlic_key_hex(native + 0x60, 32, out->unwrapped_key_hex);
    garlic_key_wipe(digest, sizeof(digest));
    garlic_key_wipe(native, sizeof(native));
    return 0;
}

static int garlic_key_hex_valid(const char *text, size_t chars) {
    for (size_t i = 0; i < chars; i++)
        if (!((text[i] >= '0' && text[i] <= '9') || (text[i] >= 'a' && text[i] <= 'f')))
            return 0;
    return text[chars] == 0;
}

int garlic_key_crypto_json(const garlic_key_capture_t *key, char *out, size_t cap) {
    if (out && cap)
        out[0] = 0;
    if (!key || !out || !cap || !garlic_key_hex_valid(key->header_sha256, 64) ||
        !garlic_key_hex_valid(key->sealed_key_sha256, 64) ||
        !garlic_key_hex_valid(key->sealed_key_hex, 192) ||
        !garlic_key_hex_valid(key->unwrapped_key_hex, 64))
        return -1;
    int n = snprintf(out, cap,
                     "{\"schema_version\":1,\"key_type\":\"pfsmgr_unwrapped_candidate\","
                     "\"source\":\"ps5-pfsmgr-0xc0845302\",\"header_bytes\":4096,"
                     "\"header_sha256\":\"%s\",\"sealed_key_offset\":2048,\"sealed_key_bytes\":96,"
                     "\"sealed_key_hex\":\"%s\",\"sealed_key_sha256\":\"%s\","
                     "\"unwrapped_key_hex\":\"%s\",\"offline_decryption_verified\":false}",
                     key->header_sha256, key->sealed_key_hex, key->sealed_key_sha256,
                     key->unwrapped_key_hex);
    if (n < 0 || (size_t)n >= cap) {
        out[0] = 0;
        return -1;
    }
    return n;
}
