#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "CMP/chives.h"

static void put16(uint8_t *p, uint16_t value) {
    p[0] = value & 0xff;
    p[1] = value >> 8;
}

static void put32(uint8_t *p, uint32_t value) {
    p[0] = value & 0xff;
    p[1] = (value >> 8) & 0xff;
    p[2] = (value >> 16) & 0xff;
    p[3] = value >> 24;
}

static size_t entry(uint8_t *out, uint16_t method, uint32_t packed,
                    uint32_t plain, const uint8_t *payload) {
    memset(out, 0, 512);
    put32(out, 0x04034b50);
    put16(out + 8, method);
    put32(out + 18, packed);
    put32(out + 22, plain);
    put16(out + 26, 4);
    memcpy(out + 30, "empty", 4);
    if (packed) memcpy(out + 34, payload, packed);
    size_t offset = 34 + packed;
    put32(out + offset, 0x02014b50);
    return offset + 4;
}

static void empty_deflate(void) {
    static const uint8_t compressed[] = {0x03, 0x00};
    uint8_t zip[512];
    char name[32];
    const uint8_t *payload;
    size_t length = entry(zip, 8, 2, 0, compressed), offset = 0, payload_len;
    assert(chives_zip_next(zip, length, &offset, name, sizeof(name), &payload, &payload_len) == 1);
    assert(payload_len == 0 && offset == 36);
    assert(chives_zip_next(zip, length, &offset, name, sizeof(name), &payload, &payload_len) == 0);
}

static void empty_stored(void) {
    uint8_t zip[512];
    char name[32];
    const uint8_t *payload;
    size_t length = entry(zip, 0, 0, 0, NULL), offset = 0, payload_len;
    assert(chives_zip_next(zip, length, &offset, name, sizeof(name), &payload, &payload_len) == 1);
    assert(payload_len == 0 && offset == 34);
}

static void overflowing_deflate(void) {
    static const uint8_t compressed[] = {0x03, 0x00};
    uint8_t zip[512];
    char name[32];
    const uint8_t *payload;
    size_t length = entry(zip, 8, 2, 1, compressed), offset = 0, payload_len;
    assert(chives_zip_next(zip, length, &offset, name, sizeof(name), &payload, &payload_len) < 0);
}

static void oversized_declaration(void) {
    static const uint8_t compressed[] = {0x03, 0x00};
    uint8_t zip[512];
    char name[32];
    const uint8_t *payload;
    size_t length = entry(zip, 8, 2, 0x80000001U, compressed), offset = 0, payload_len;
    assert(chives_zip_next(zip, length, &offset, name, sizeof(name), &payload, &payload_len) < 0);
}

int main(void) {
    empty_deflate();
    empty_stored();
    overflowing_deflate();
    oversized_declaration();
    puts("chives ZIP boundary tests passed");
    return 0;
}
