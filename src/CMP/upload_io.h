#ifndef GARLIC_UPLOAD_IO_H
#define GARLIC_UPLOAD_IO_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#define GARLIC_UPLOAD_BLOCK 65536u

typedef struct {
    size_t expected, received, written;
    int64_t actual_size;
    uint32_t crc;
    const char *stage;
    int error, sync_warning;
    size_t last_write_offset, last_write_request, write_calls;
    ssize_t last_write_result;
} garlic_upload_t;

int garlic_upload_write(int fd, const void *data, size_t size, garlic_upload_t *u);

typedef ssize_t (*garlic_upload_receive_fn)(void *context, void *buffer, size_t size);
/* TCP boundaries are unrelated to filesystem blocks. Keep each full PFS
 * block in one sequential write, including the body already read with the
 * HTTP headers. Write the last short block once, at EOF, without padding. */
int garlic_upload_receive(int fd, const void *initial, size_t initial_size, garlic_upload_t *u,
                          void *buffer, size_t capacity, garlic_upload_receive_fn receive,
                          void *context);

/* An unsupported per-file flush is not evidence of a failed write. In that
 * case use the existing global sync and verify the closed file's length and
 * CRC before accepting it. Actual I/O/capacity/close errors remain fatal.
 * EINVAL is eligible only after fstat proves this is the complete regular file.
 * The save is still sealed by the existing native unmount before download. */
int garlic_upload_finish(int fd, const char *path, garlic_upload_t *u, void *buffer,
                         size_t capacity);
#endif
