/* CMP normal generated-image key handling. This does not add the removed
 * standalone key-only HTTP action. Extracted without algorithm changes. */
#include "native_key.h"
#include "ps5param.h"
#include "internal/save_format.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#define MAX_PATH_LEN CMP_NATIVE_KEY_PATH_BYTES

#define GARLIC_KEY_OPERATION_RESULT_OFFSET 0x80u
#define GARLIC_KEY_IOCTL_BYTES 0x84u

/* Native ioctl ABI: sealed 96B, candidate 32B, then a separate result word.
 * This is consistent with ioctl 0xc0845302's encoded 132-byte argument size.
 * The result word is diagnostic; no firmware-specific meaning is assumed. */
typedef struct {
    uint8_t sealed[CMP_PFS_SEALED_KEY_BYTES];
    uint8_t candidate[32];
    uint32_t operation_result;
} garlic_key_ioctl_layout_t;
_Static_assert(offsetof(garlic_key_ioctl_layout_t, candidate) == 0x60, "pfsmgr candidate offset");
_Static_assert(offsetof(garlic_key_ioctl_layout_t, operation_result) ==
                   GARLIC_KEY_OPERATION_RESULT_OFFSET,
               "pfsmgr result offset");
_Static_assert(sizeof(garlic_key_ioctl_layout_t) == GARLIC_KEY_IOCTL_BYTES, "pfsmgr argument size");

/* Non-secret native status, kept separate from candidate key bytes. */
typedef struct {
    const char *stage;
    int native_called;
    int native_result;
    int native_errno;
    uint32_t operation_result;
    int operation_result_available;
} garlic_key_native_status_t;

static garlic_key_capture_t g_mount_key_capture;
static int g_mount_key_valid;
static char g_mount_key_image[MAX_PATH_LEN];
static uint64_t g_mount_key_image_size;

/* Native key unwrapping for normal image capture and mounting. */
/* This ioctl returns candidate unwrapped material, not proven native-v2
 * filesystem AES keys. It accepts the sealed blob directly, with no mount. */
static int save_key_native_unwrap(void *context, uint8_t *buffer, size_t capacity) {
    garlic_key_native_status_t local = {0};
    garlic_key_native_status_t *status = context ? context : &local;
    memset(status, 0, sizeof(*status));
    status->stage = "argument";
    status->native_result = -1;
    if (!buffer || capacity < GARLIC_KEY_NATIVE_BYTES) {
        status->native_errno = EINVAL;
        return -EINVAL;
    }
    /* Match the normal mount path: this native ioctl uses a heap buffer.
     * Do not pass the portable key-core's stack buffer to the PS5 driver. */
    status->stage = "allocate";
    uint8_t *native = malloc(GARLIC_KEY_NATIVE_BYTES);
    if (!native) {
        status->native_errno = ENOMEM;
        return -ENOMEM;
    }
    memset(native, 0, GARLIC_KEY_NATIVE_BYTES);
    memcpy(native, buffer, GARLIC_KEY_SEALED_BYTES);
    memset(buffer + 0x60, 0, 32);
    ps5param_elevate();
    status->stage = "open";
    int fd = open("/dev/pfsmgr", O_RDWR);
    if (fd < 0) {
        int error = errno ? errno : EIO;
        status->native_errno = error;
        garlic_key_wipe(native, GARLIC_KEY_NATIVE_BYTES);
        free(native);
        return -error;
    }
    status->stage = "ioctl";
    status->native_called = 1;
    errno = 0;
    int result = ioctl(fd, 0xc0845302, native);
    int error = errno;
    status->native_result = result;
    status->native_errno = result < 0 ? error : 0;
    if (result >= 0) {
        memcpy(&status->operation_result, native + GARLIC_KEY_OPERATION_RESULT_OFFSET, 4);
        status->operation_result_available = 1;
    }
    int closed = close(fd), close_error = errno;
    if (result < 0) {
        garlic_key_wipe(native, GARLIC_KEY_NATIVE_BYTES);
        free(native);
        return -(error ? error : EIO);
    }
    if (closed < 0) {
        status->stage = "close";
        status->native_errno = close_error ? close_error : EIO;
        garlic_key_wipe(native, GARLIC_KEY_NATIVE_BYTES);
        free(native);
        return -status->native_errno;
    }
    memcpy(buffer + 0x60, native + 0x60, 32);
    status->stage = "complete";
    garlic_key_wipe(native, GARLIC_KEY_NATIVE_BYTES);
    free(native);
    return 0;
}
int save_key_capture_image(const char *image, garlic_key_capture_t *capture,
                           uint64_t *source_size) {
    uint8_t header[GARLIC_KEY_HEADER_BYTES];
    struct stat st;
    int fd = open(image, O_RDONLY);
    if (fd < 0)
        return -1;
    int ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size >= (off_t)sizeof(header);
    size_t got = 0;
    while (ok && got < sizeof(header)) {
        ssize_t n = pread(fd, header + got, sizeof(header) - got, (off_t)got);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            ok = 0;
            break;
        }
        got += (size_t)n;
    }
    if (close(fd) < 0)
        ok = 0;
    if (!ok)
        return -1;
    int result = garlic_key_capture(header, sizeof(header), (uint64_t)st.st_size,
                                    save_key_native_unwrap, NULL, capture);
    if (result == 0 && source_size)
        *source_size = (uint64_t)st.st_size;
    return result;
}

/* Clearing one cache owner invalidates the association before wiping its
 * captured key material. Callers use the same existing save mutex. */
void save_key_clear_cache(void) {
    g_mount_key_valid = 0;
    g_mount_key_image[0] = 0;
    g_mount_key_image_size = 0;
    garlic_key_wipe(&g_mount_key_capture, sizeof(g_mount_key_capture));
}

int save_key_cached_image(const char *image, garlic_key_capture_t *capture, uint64_t *source_size) {
    if (!image || !capture || !g_mount_key_valid || strcmp(g_mount_key_image, image))
        return 0;
    *capture = g_mount_key_capture;
    if (source_size)
        *source_size = g_mount_key_image_size;
    return 1;
}

/* Hash the original backing bytes before native mount/metadata writes can
 * change superblock/ICV fields. Keep the key snapshot scoped to that image. */
void save_key_cache_image(const char *image) {
    save_key_clear_cache();
    if (save_key_capture_image(image, &g_mount_key_capture, &g_mount_key_image_size) == 0) {
        snprintf(g_mount_key_image, sizeof(g_mount_key_image), "%s", image);
        g_mount_key_valid = 1;
    }
}
