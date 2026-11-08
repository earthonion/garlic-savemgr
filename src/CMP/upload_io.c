/* CMP add-in implementation; declarations are in upload_io.h.
 * Extracted without algorithm changes from CMP Rebuild4. */
#include "upload_io.h"
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>

static void garlic_upload_fail(garlic_upload_t *u, const char *stage, int error) {
    if (!u->stage) {
        u->stage = stage;
        u->error = error ? error : EIO;
    }
}

static uint32_t garlic_upload_crc(uint32_t crc, const void *data, size_t size) {
    const unsigned char *p = data;
    while (size--) {
        crc ^= *p++;
        for (unsigned i = 0; i < 8; i++)
            crc = (crc >> 1) ^ ((crc & 1) ? UINT32_C(0xedb88320) : 0);
    }
    return crc;
}

int garlic_upload_write(int fd, const void *data, size_t size, garlic_upload_t *u) {
    const unsigned char *p = data;
    while (size && !u->stage) {
        u->last_write_offset = u->written;
        u->last_write_request = size;
        ssize_t n = write(fd, p, size);
        u->last_write_result = n;
        u->write_calls++;
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            garlic_upload_fail(u, "write", n < 0 ? errno : EIO);
            return -1;
        }
        u->crc = garlic_upload_crc(u->crc, p, (size_t)n);
        u->written += (size_t)n;
        p += n;
        size -= (size_t)n;
    }
    return u->stage ? -1 : 0;
}

int garlic_upload_receive(int fd, const void *initial, size_t initial_size, garlic_upload_t *u,
                          void *buffer, size_t capacity, garlic_upload_receive_fn receive,
                          void *context) {
    if (!buffer || capacity < GARLIC_UPLOAD_BLOCK || !receive || initial_size > u->expected ||
        (initial_size && !initial)) {
        garlic_upload_fail(u, "buffer", EINVAL);
        return -1;
    }
    unsigned char *block = buffer;
    const unsigned char *prefix = initial;
    size_t used = 0, prefix_offset = 0;
    while (!u->stage && u->received < u->expected) {
        size_t want = GARLIC_UPLOAD_BLOCK - used;
        if (want > u->expected - u->received)
            want = u->expected - u->received;
        size_t got;
        if (prefix_offset < initial_size) {
            got = initial_size - prefix_offset;
            if (got > want)
                got = want;
            memcpy(block + used, prefix + prefix_offset, got);
            prefix_offset += got;
        } else {
            ssize_t n = receive(context, block + used, want);
            if (n < 0 && errno == EINTR)
                continue;
            if (n <= 0) {
                garlic_upload_fail(u, "receive", n < 0 ? errno : ECONNRESET);
                break;
            }
            if ((size_t)n > want) {
                garlic_upload_fail(u, "receive", EIO);
                break;
            }
            got = (size_t)n;
        }
        used += got;
        u->received += got;
        if (used == GARLIC_UPLOAD_BLOCK || u->received == u->expected) {
            if (garlic_upload_write(fd, block, used, u) < 0)
                break;
            used = 0;
        }
    }
    return u->stage ? -1 : 0;
}

int garlic_upload_finish(int fd, const char *path, garlic_upload_t *u, void *buffer,
                         size_t capacity) {
    struct stat st;
    if (!u->stage && (u->received != u->expected || u->written != u->expected))
        garlic_upload_fail(u, "receive", EIO);
    u->actual_size = -1;
    if (fstat(fd, &st) == 0)
        u->actual_size = (int64_t)st.st_size;
    else if (!u->stage)
        garlic_upload_fail(u, "fstat", errno);
    if (!u->stage) {
        if (!S_ISREG(st.st_mode) || st.st_size < 0 || (uint64_t)st.st_size != u->expected)
            garlic_upload_fail(u, "size", EIO);
    }
    if (!u->stage) {
        int ret;
        do {
            ret = fsync(fd);
        } while (ret < 0 && errno == EINTR);
        if (ret < 0) {
            int saved = errno;
            if (saved == EOPNOTSUPP || saved == ENOSYS || saved == EINVAL) {
                u->sync_warning = saved;
                sync();
            } else
                garlic_upload_fail(u, "fsync", saved);
        }
    }
    if (close(fd) < 0)
        garlic_upload_fail(u, "close", errno);
    if (!u->stage && u->sync_warning) {
        int check = open(path, O_RDONLY);
        if (check < 0)
            garlic_upload_fail(u, "verify-open", errno);
        else {
            size_t total = 0;
            uint32_t crc = UINT32_C(0xffffffff);
            if (!buffer || !capacity)
                garlic_upload_fail(u, "verify-buffer", EINVAL);
            while (!u->stage) {
                ssize_t n = read(check, buffer, capacity);
                if (n < 0 && errno == EINTR)
                    continue;
                if (n < 0) {
                    garlic_upload_fail(u, "verify-read", errno);
                    break;
                }
                if (!n)
                    break;
                if ((size_t)n > u->expected - total) {
                    garlic_upload_fail(u, "verify-size", EIO);
                    break;
                }
                total += (size_t)n;
                crc = garlic_upload_crc(crc, buffer, (size_t)n);
            }
            if (!u->stage && (total != u->expected || crc != u->crc))
                garlic_upload_fail(u, "verify-content", EIO);
            if (close(check) < 0)
                garlic_upload_fail(u, "verify-close", errno);
        }
    }
    return u->stage ? -1 : 0;
}
