/* CMP native PFS rebuilding. Extracted from CMP Rebuild4 without algorithm
 * changes; platform services are supplied through the private bridge. */
#include "pfs_rebuild.h"
#include "internal/pfs_rebuild_bridge.h"
#include "internal/save_format.h"
#include "metadata_layout.h"
#include "ps5param.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

/* Keep this implementation-local alias out of integration headers. */
#define MAX_PATH_LEN CMP_PATH_BYTES

/* Physical-SFO creation provenance is separate from the mount cache: native
 * unmount clears that cache before finalization. Bind the source profile to
 * this exact file and sealed key so reused temporary names cannot inherit it. */
typedef struct {
    int active;
    char path[MAX_PATH_LEN];
    dev_t device;
    ino_t inode;
    uint8_t sealed_key[CMP_PFS_SEALED_KEY_BYTES];
    chives_geometry_t geometry;
} legacy_creation_t;
static legacy_creation_t g_legacy_creation;
static void legacy_creation_clear(void) {
    memset(&g_legacy_creation, 0, sizeof(g_legacy_creation));
}
static int legacy_geometry_equal(const chives_geometry_t *a, const chives_geometry_t *b) {
    return a->version == b->version && a->is_ps4 == b->is_ps4 &&
           a->block_size_bytes == b->block_size_bytes && a->block_count == b->block_count &&
           a->original_image_size_bytes == b->original_image_size_bytes &&
           a->backup_header_count == b->backup_header_count && a->mode_raw == b->mode_raw &&
           a->has_fs_ext == b->has_fs_ext && a->fs_ext == b->fs_ext;
}
static int legacy_image_identity(const char *path, struct stat *st,
                                 uint8_t key[CMP_PFS_SEALED_KEY_BYTES]) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    int ok = fstat(fd, st) == 0 && S_ISREG(st->st_mode);
    size_t done = 0;
    while (ok && done < CMP_PFS_SEALED_KEY_BYTES) {
        ssize_t n = pread(fd, key + done, CMP_PFS_SEALED_KEY_BYTES - done,
                          (off_t)(CMP_PFS_SEALED_KEY_OFFSET + done));
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            ok = 0;
            break;
        }
        done += (size_t)n;
    }
    if (close(fd) < 0)
        ok = 0;
    return ok && !memcmp(key, "pfsSKKey", 8) ? 0 : -1;
}
static int legacy_protected_region_empty(const char *image) {
    uint8_t bytes[4096];
    int fd = open(image, O_RDONLY | O_NOFOLLOW);
    if (fd < 0)
        return 0;
    off_t offset = CMP_PS5PARAM_IMAGE_OFFSET;
    int ok = 1;
    while (offset < CMP_LEGACY_BLANK_GUARD_END && ok) {
        size_t length = (size_t)(CMP_LEGACY_BLANK_GUARD_END - offset);
        if (length > sizeof(bytes))
            length = sizeof(bytes);
        ssize_t n = pread(fd, bytes, length, offset);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            ok = 0;
            break;
        }
        for (ssize_t i = 0; i < n; i++)
            if (bytes[i]) {
                ok = 0;
                break;
            }
        offset += n;
    }
    if (close(fd) < 0)
        ok = 0;
    return ok;
}
static int legacy_creation_record(const char *path, const chives_geometry_t *expected) {
    chives_geometry_t actual;
    struct stat st;
    uint8_t key[CMP_PFS_SEALED_KEY_BYTES];
    if (!path || strlen(path) >= sizeof(g_legacy_creation.path) ||
        chives_read_image(path, &actual) < 0 || !garlic_legacy_geometry_matches(&actual) ||
        !legacy_geometry_equal(expected, &actual) || !legacy_protected_region_empty(path) ||
        legacy_image_identity(path, &st, key) < 0)
        return -1;
    g_legacy_creation.geometry = actual;
    g_legacy_creation.device = st.st_dev;
    g_legacy_creation.inode = st.st_ino;
    memcpy(g_legacy_creation.sealed_key, key, sizeof(key));
    snprintf(g_legacy_creation.path, sizeof(g_legacy_creation.path), "%s", path);
    g_legacy_creation.active = 1;
    return 0;
}
static int legacy_creation_matches(const char *path, const chives_geometry_t *actual) {
    struct stat st;
    uint8_t key[CMP_PFS_SEALED_KEY_BYTES];
    return g_legacy_creation.active && path && !strcmp(path, g_legacy_creation.path) &&
           legacy_geometry_equal(actual, &g_legacy_creation.geometry) &&
           legacy_image_identity(path, &st, key) == 0 && st.st_dev == g_legacy_creation.device &&
           st.st_ino == g_legacy_creation.inode &&
           !memcmp(key, g_legacy_creation.sealed_key, sizeof(key));
}

/* Experimental 13.60 native CoW conversion: /dev/pfsctldev,
 * ioctl 0x80109115 {path, uint32 data_blocks, uint32 system_blocks}.
 * The kernel creates CoW metadata, writes fs_ext, updates ICV/auth and signs.
 * Never pwrite a guessed value into the authenticated header. */
int chives_ppr_create(CreateOpt *opt, const char *path, uint64_t size,
                      const chives_geometry_t *expected) {
    legacy_creation_clear();
    if (!g_pprCreate)
        return -ENOSYS;
    if (opt->blockSize != CMP_PFS_NATIVE_BLOCK_BYTES)
        return g_pprCreate(opt, path, 0, size);
    if (expected && garlic_legacy_geometry_matches(expected) &&
        expected->original_image_size_bytes == size) {
        logprintf("[GarlicMgr] Physical-SFO create: data=%llu system=0; no CoW conversion\n",
                  (unsigned long long)expected->block_count);
        int ret = g_pprCreate(opt, path, 0, size);
        if (ret != 0)
            return ret < 0 ? ret : -EIO;
        if (legacy_creation_record(path, expected) < 0)
            return -EIO;
        /* The final uploaded SFO is checked only after all edits and native
         * unmount. Formatting by itself never authorizes publication. */
        return 0;
    }
    if (!expected || !expected->has_fs_ext || !expected->fs_ext ||
        !chives_geometry_valid(expected) || expected->block_count > UINT32_MAX ||
        expected->block_count * (uint64_t)expected->block_size_bytes != size) {
        logprintf(
            "[GarlicMgr] CoW rebuild needs original header fs_ext; re-export chives.json or include PS5IMAGE. No half-size guess used.\n");
        return -EINVAL;
    }
    uint32_t system_blocks = expected->fs_ext;
    uint32_t data_blocks = (uint32_t)(expected->block_count - system_blocks);
    if (data_blocks < 2 || expected->backup_header_count != 1)
        return -EINVAL;
    uint64_t data_size = (uint64_t)data_blocks * CMP_PFS_NATIVE_BLOCK_BYTES;
    logprintf("[GarlicMgr] CoW create: data=%u system=%u total=%llu expected fs_ext=0x%x\n",
              data_blocks, system_blocks, (unsigned long long)expected->block_count, system_blocks);
    int ret = g_pprCreate(opt, path, 0, data_size);
    if (ret != 0)
        return ret < 0 ? ret : -EIO;
    chives_geometry_t before;
    if (chives_read_image(path, &before) < 0 ||
        before.block_size_bytes != CMP_PFS_NATIVE_BLOCK_BYTES ||
        before.block_count != data_blocks || !before.has_fs_ext || before.fs_ext != 0)
        return -EIO;
    struct {
        const char *path;
        uint32_t blocks, system_blocks;
    } arg = {path, data_blocks, system_blocks};
    _Static_assert(sizeof(arg) == 16, "CoW ioctl ABI");
    int fd = open("/dev/pfsctldev", O_RDONLY);
    if (fd < 0)
        return -errno;
    errno = 0;
    ret = ioctl(fd, CMP_PFS_COW_CONVERT_IOCTL, &arg);
    int saved_errno = errno;
    close(fd);
    logprintf("[GarlicMgr] Native CoW conversion: ret=%d errno=%d\n", ret, saved_errno);
    if (ret != 0)
        return saved_errno ? -saved_errno : -EIO;
    if (chives_verify_created(path, expected) < 0)
        return -EIO;
    return 0;
}

/* A freshly rebuilt save must have protected metadata unless its source
 * explicitly identifies the validated physical-SFO profile. Choose the
 * layout before writing; a failed protected write is never a fallback. */
static int legacy_verify_physical_sfo(const char *image, const uint8_t *sfo, uint32_t size,
                                      const chives_geometry_t *expected) {
    if (g_mounted) {
        ps5param_set_error("Physical-SFO verification requires an unmounted image");
        return -EBUSY;
    }
    if (mount_by_path_at_checked(image, "/data/mount_sd", 1, 1) < 0) {
        ps5param_set_error("Physical-SFO native verification mount failed");
        return -EIO;
    }
    uint8_t check[CMP_PS5PARAM_BLOB_BYTES];
    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "%s/sce_sys/param.sfo", g_mount_point);
    int n = read_sfo_file(path, check, sizeof(check) - CMP_PS5PARAM_HEADER_BYTES);
    int ok = n == (int)size && !memcmp(check, sfo, size);
    /* Even a comparison failure must release the native mount. A failed
     * unmount leaves tracked ownership intact for safe cleanup/retry. */
    if (unmount_save() < 0) {
        ps5param_set_error("Physical-SFO verification unmount failed; output withheld");
        return -EIO;
    }
    chives_geometry_t actual;
    if (!ok || chives_read_image(image, &actual) < 0 || !legacy_geometry_equal(&actual, expected) ||
        !legacy_protected_region_empty(image)) {
        ps5param_set_error(
            "Physical-SFO read-back or image-layout verification failed; output withheld");
        return -EIO;
    }
    logprintf(
        "[GarlicMgr] Physical-SFO finalized: exact native remount read-back (%u B), fs_ext=0; protected metadata unused\n",
        size);
    return 0;
}
int finalize_ps5_sfo(const char *image, const uint8_t *sfo, uint32_t size, int fresh) {
    chives_geometry_t actual;
    int result = -EINVAL;
    ps5param_clear_warning();
    ps5param_clear_error();
    if (chives_read_image(image, &actual) < 0) {
        ps5param_set_error("Cannot read PS5 image geometry; output withheld");
    } else if (fresh && g_legacy_creation.active && !legacy_creation_matches(image, &actual)) {
        ps5param_set_error("Physical-SFO creation identity changed; output withheld");
    } else if (actual.has_fs_ext && actual.fs_ext == 0) {
        if ((fresh && !legacy_creation_matches(image, &actual)) ||
            !garlic_legacy_sfo_matches(&actual, sfo, size) ||
            !legacy_protected_region_empty(image)) {
            ps5param_set_error(
                "Zero fs_ext does not match the source-bound physical-SFO profile; output withheld");
        } else
            result = legacy_verify_physical_sfo(image, sfo, size, &actual);
    } else {
        result = ps5param_write_sfo(image, sfo, size);
    }
    legacy_creation_clear();
    return result;
}
