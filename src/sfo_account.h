#ifndef GARLIC_SFO_ACCOUNT_H
#define GARLIC_SFO_ACCOUNT_H

#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

/* Account IDs use numeric hex in the UI and little-endian bytes in SFO. */
static int sfo_account_from_hex(const char *hex, uint8_t bytes[8]) {
    if (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) hex += 2;
    if (strlen(hex) != 16) return -1;
    uint64_t value = 0;
    for (int i = 0; i < 16; i++) {
        unsigned digit;
        if (hex[i] >= '0' && hex[i] <= '9') digit = hex[i] - '0';
        else if (hex[i] >= 'a' && hex[i] <= 'f') digit = hex[i] - 'a' + 10;
        else if (hex[i] >= 'A' && hex[i] <= 'F') digit = hex[i] - 'A' + 10;
        else return -1;
        value = (value << 4) | digit;
    }
    for (int i = 0; i < 8; i++) bytes[i] = (uint8_t)(value >> (i * 8));
    return 0;
}

/* Locate a value through the SFO index; layouts vary between games. */
static int sfo_field_offset(int fd, const char *name, size_t within, size_t length,
                            off_t *result) {
    struct stat st;
    uint8_t header[20];
    if (fstat(fd, &st) < 0 || st.st_size < 20 ||
        pread(fd, header, sizeof(header), 0) != (ssize_t)sizeof(header) ||
        memcmp(header, "\0PSF", 4)) return -1;
    uint32_t keys, data, count;
    memcpy(&keys, header + 8, 4);
    memcpy(&data, header + 12, 4);
    memcpy(&count, header + 16, 4);
    if (count > ((uint64_t)st.st_size - 20) / 16 ||
        keys < 20 + (uint64_t)count * 16 || keys >= data || data > (uint64_t)st.st_size) return -1;
    for (uint32_t i = 0; i < count; i++) {
        uint8_t entry[16];
        uint16_t key;
        uint32_t size, capacity, offset;
        if (pread(fd, entry, sizeof(entry), 20 + (off_t)i * 16) != (ssize_t)sizeof(entry)) return -1;
        memcpy(&key, entry, 2);
        memcpy(&size, entry + 4, 4);
        memcpy(&capacity, entry + 8, 4);
        memcpy(&offset, entry + 12, 4);
        uint64_t key_pos = (uint64_t)keys + key;
        uint64_t value_pos = (uint64_t)data + offset;
        if (key_pos >= data || size > capacity || value_pos > (uint64_t)st.st_size ||
            capacity > (uint64_t)st.st_size - value_pos) return -1;
        size_t key_len = strlen(name) + 1;
        char key_name[32];
        if (key_len > sizeof(key_name) || key_len > data - key_pos) continue;
        if (pread(fd, key_name, key_len, (off_t)key_pos) != (ssize_t)key_len) return -1;
        if (memcmp(key_name, name, key_len)) continue;
        if (within > size || length > size - within) return -1;
        *result = (off_t)(value_pos + within);
        return 0;
    }
    return -1;
}

/* Zero is a valid Account ID. Read back both fields before reporting success. */
static int patch_sfo_account(const char *path, const uint8_t account[8], const uint32_t *uid) {
    int fd = open(path, O_RDWR);
    if (fd < 0) return -1;
    off_t account_offset, user_offset = 0;
    uint8_t check[8];
    int ret = -1;
    if (sfo_field_offset(fd, "ACCOUNT_ID", 0, 8, &account_offset) < 0) goto done;
    if (uid && sfo_field_offset(fd, "USER_ID", 0, 4, &user_offset) < 0 &&
        sfo_field_offset(fd, "PARAMS", 4, 4, &user_offset) < 0) goto done;
    if (pwrite(fd, account, 8, account_offset) != 8) goto done;
    if (uid && pwrite(fd, uid, 4, user_offset) != 4) goto done;
    if (fsync(fd) < 0 || pread(fd, check, 8, account_offset) != 8 ||
        memcmp(check, account, 8)) goto done;
    if (uid && (pread(fd, check, 4, user_offset) != 4 || memcmp(check, uid, 4))) goto done;
    ret = 0;
done:
    close(fd);
    return ret;
}

/* PS4 ownership includes the whole PARAMS record, not just ACCOUNT_ID.
 * The record is copied only from the selected user's same-title/same-slot save. */
static int sfo_read_owner_params(const char *path, const uint8_t account[8], uint32_t uid,
                                 uint8_t params[1024]) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    off_t account_offset, params_offset;
    uint8_t stored_account[8];
    uint32_t stored_uid;
    int ret = -1, nonzero = 0;
    if (sfo_field_offset(fd, "ACCOUNT_ID", 0, 8, &account_offset) < 0 ||
        sfo_field_offset(fd, "PARAMS", 0, 1024, &params_offset) < 0 ||
        pread(fd, stored_account, 8, account_offset) != 8 || memcmp(stored_account, account, 8) ||
        pread(fd, params, 1024, params_offset) != 1024) goto done;
    memcpy(&stored_uid, params + 4, 4);
    for (int i = 8; i < 40; i++) nonzero |= params[i];
    if (stored_uid == uid && nonzero) ret = 0;
done:
    close(fd);
    return ret;
}

static int patch_sfo_owner_params(const char *path, const uint8_t account[8],
                                   uint32_t uid, const uint8_t params[1024]) {
    uint32_t template_uid;
    memcpy(&template_uid, params + 4, 4);
    if (template_uid != uid) return -1;
    int fd = open(path, O_RDWR);
    if (fd < 0) return -1;
    off_t account_offset, params_offset;
    uint8_t check[1024];
    int ret = -1;
    if (sfo_field_offset(fd, "ACCOUNT_ID", 0, 8, &account_offset) < 0 ||
        sfo_field_offset(fd, "PARAMS", 0, 1024, &params_offset) < 0) goto done;
    if (pwrite(fd, account, 8, account_offset) != 8 ||
        pwrite(fd, params, 1024, params_offset) != 1024 || fsync(fd) < 0) goto done;
    if (pread(fd, check, 8, account_offset) != 8 || memcmp(check, account, 8) ||
        pread(fd, check, 1024, params_offset) != 1024 || memcmp(check, params, 1024)) goto done;
    ret = 0;
done:
    close(fd);
    return ret;
}

/* A different slot/title supplies only the user identity bytes. Keep the
 * incoming game's slot metadata; this is a partial, unverified recovery. */
static int patch_sfo_owner_identity(const char *path, const uint8_t account[8],
                                    uint32_t uid, const uint8_t donor[1024]) {
    uint8_t params[1024];
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    off_t offset;
    int valid = sfo_field_offset(fd, "PARAMS", 0, 1024, &offset) == 0 &&
                pread(fd, params, sizeof(params), offset) == sizeof(params);
    close(fd);
    if (!valid) return -1;
    memcpy(params + 4, donor + 4, 36);
    return patch_sfo_owner_params(path, account, uid, params);
}

#endif
