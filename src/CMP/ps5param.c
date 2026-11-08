/* CMP protected-metadata addition extracted from Rebuild4.
 * Native ioctl selection, fallback order, readback and cache behavior are
 * unchanged. This is a separately compiled translation unit. */
#include "ps5param.h"
#include "internal/ps5param_bridge.h"
#include "internal/save_format.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <ps5/kernel.h>

static char g_ps5param_error[CMP_PS5PARAM_ERROR_BYTES];
static char g_ps5param_warning[CMP_PS5PARAM_ERROR_BYTES];
/* Real PS5 param.sfo recovered from the encrypted PS5PARAM blob in the image
 * header (offset 0xC00) before the image is mounted. CoW PS5 saves can store
 * only a zero placeholder at sce_sys/param.sfo inside PFS, making the blob
 * their real metadata. Validated physical-SFO saves use their file instead. */
static uint8_t g_mount_real_sfo[CMP_PS5PARAM_BLOB_BYTES];
static uint32_t g_mount_real_sfo_len = 0;
static char g_mount_real_sfo_image[CMP_PS5PARAM_PATH_BYTES];

_Static_assert(CMP_PS5PARAM_SFO_BYTES == CMP_PS5PARAM_BLOB_BYTES, "protected-SFO cache capacity");

const uint8_t *ps5param_cache_data(void) {
    return g_mount_real_sfo;
}
uint32_t ps5param_cache_size(void) {
    return g_mount_real_sfo_len;
}
const char *ps5param_cache_image(void) {
    return g_mount_real_sfo_image;
}

int ps5param_cache_replace(const uint8_t *sfo, uint32_t size) {
    if (!sfo_bytes_valid(sfo, size) || size > CMP_PS5PARAM_MAX_SFO_BYTES)
        return -EINVAL;
    memcpy(g_mount_real_sfo, sfo, size);
    g_mount_real_sfo_len = size;
    return 0;
}

const char *ps5param_error(void) {
    return g_ps5param_error;
}
const char *ps5param_warning(void) {
    return g_ps5param_warning;
}
void ps5param_clear_error(void) {
    g_ps5param_error[0] = 0;
}
void ps5param_clear_warning(void) {
    g_ps5param_warning[0] = 0;
}
void ps5param_set_error(const char *format, ...) {
    va_list arguments;
    va_start(arguments, format);
    vsnprintf(g_ps5param_error, sizeof(g_ps5param_error), format, arguments);
    va_end(arguments);
}

int sfo_bytes_valid(const uint8_t *buf, size_t size) {
    if (!buf || size < CMP_SFO_HEADER_BYTES || memcmp(buf, "\0PSF", 4))
        return 0;
    uint32_t keys, data, count;
    memcpy(&keys, buf + 8, 4);
    memcpy(&data, buf + 12, 4);
    memcpy(&count, buf + 16, 4);
    if (!count || count > (size - CMP_SFO_HEADER_BYTES) / 16 ||
        keys < CMP_SFO_HEADER_BYTES + (uint64_t)count * 16 || keys >= data || data > size)
        return 0;
    for (uint32_t i = 0; i < count; i++) {
        const uint8_t *entry = buf + CMP_SFO_HEADER_BYTES + i * 16;
        uint16_t key;
        uint32_t len, capacity, offset;
        memcpy(&key, entry, 2);
        memcpy(&len, entry + 4, 4);
        memcpy(&capacity, entry + 8, 4);
        memcpy(&offset, entry + 12, 4);
        uint64_t kp = (uint64_t)keys + key, vp = (uint64_t)data + offset;
        if (kp >= data || !memchr(buf + kp, 0, data - kp) || len > capacity || vp > size ||
            capacity > size - vp)
            return 0;
    }
    return 1;
}
void ps5param_clear_cache(void) {
    g_mount_real_sfo_len = 0;
    g_mount_real_sfo_image[0] = 0;
    save_key_clear_cache();
}
int ps5param_cached_for_mount(const char *base) {
    const char *image = g_local_copy[0] ? g_local_copy : g_mounted_path;
    return g_mounted && base && !strcmp(base, g_mount_point) &&
           !strcmp(image, g_mount_real_sfo_image) &&
           sfo_bytes_valid(g_mount_real_sfo, g_mount_real_sfo_len);
}
int ps5param_is_sfo_name(const char *name) {
    return name && !strcmp(name, "sce_sys/param.sfo");
}

/* ── PS5PARAM blob I/O ─────────────────────────────────────────────
 * PS5 (ppr) saves keep the real param.sfo in an encrypted 0x8000-byte blob
 * in the image header at 0xC00; the in-PFS sce_sys/param.sfo is only a
 * 3072-byte zero placeholder.  The kernel exposes the blob through
 * /dev/pfsctldev (pfs_param_read_nm / pfs_param_write_nm), which decrypts it
 * with the save's sealed key via SBL and verifies/regenerates the ICV.
 * Blob layout: 'PS5PARAM' u64 | u32 ver=0 | u32 sfo_size | u32 sfo_off=20 | SFO
 */
#define PFSCTL_PARAM_READ 0xC0189111u
#define PFSCTL_PARAM_WRITE 0x80189112u
#define PFSCTL_PARAM_READ2 0xC0209116u /* newer pair (uses *out) */
#define PFSCTL_PARAM_WRITE2 0x80209118u

typedef struct {
    const char *path;
    void *buf;
    uint32_t size;
    uint32_t pad;
    uint64_t *out;
} pfs_param_arg_t;

void ps5param_elevate(void) {
    kernel_set_ucred_authid(getpid(), 0x4800000000000010ULL);
    uint8_t caps[16];
    kernel_get_ucred_caps(getpid(), caps);
    caps[7] |= 0x40;
    kernel_set_ucred_caps(getpid(), caps);
    setuid(0);
}

/* Which /dev node serves the param ioctls is not certain on every firmware,
 * so probe a list of candidates and cache the first one that answers a read
 * with a valid PS5PARAM blob (or accepts a write).  Every open() errno and
 * ioctl result is logged once, and /dev entries containing "pfs" are listed
 * once so the real node can be identified from the console log. */
static const char *g_param_devs[] = {"/dev/pfsctl", "/dev/pfsmgr",    "/dev/devpfs.ctl",
                                     "/dev/pfs",    "/dev/pfsctldev", NULL};
static int g_param_dev_idx = -1; /* cached winner */
static int g_param_logged_open[8];
static int g_param_scanned = 0;

static void ps5param_scan_dev(void) {
    if (g_param_scanned)
        return;
    g_param_scanned = 1;
    DIR *d = opendir("/dev");
    if (!d) {
        logprintf("[GarlicMgr] PS5PARAM: opendir(/dev) failed errno=%d\n", errno);
        return;
    }
    struct dirent *e;
    char line[768];
    line[0] = 0;
    size_t len = 0;
    while ((e = readdir(d)) != NULL) {
        if (!strstr(e->d_name, "pfs") && !strstr(e->d_name, "PFS"))
            continue;
        int n = snprintf(line + len, sizeof(line) - len, " %s", e->d_name);
        if (n < 0 || (size_t)n >= sizeof(line) - len)
            break;
        len += (size_t)n;
    }
    closedir(d);
    logprintf("[GarlicMgr] PS5PARAM: /dev nodes matching 'pfs':%s\n", len ? line : " (none)");
}

static int ps5param_blob_magic_ok(const uint8_t *blob) {
    uint64_t m;
    memcpy(&m, blob, 8);
    return m == CMP_PS5PARAM_MAGIC;
}

/* /dev param ioctl.  wr=0 reads the decrypted blob, wr=1 writes it.
 * Returns 0 on success (for reads: ioctl succeeded; caller checks magic),
 * or -errno.  Reads only "win" (cache the device) on a valid PS5PARAM magic;
 * a node that answers with an empty buffer is remembered as a soft success
 * and returned only if no other node/command produces a real blob. */
static int ps5param_ioctl(const char *img, uint8_t *blob, uint32_t size, int wr) {
    ps5param_scan_dev();
    unsigned cmds[2];
    if (wr) {
        cmds[0] = PFSCTL_PARAM_WRITE;
        cmds[1] = PFSCTL_PARAM_WRITE2;
    } else {
        cmds[0] = PFSCTL_PARAM_READ;
        cmds[1] = PFSCTL_PARAM_READ2;
    }

    int soft_ok = 0; /* read ioctl succeeded but blob empty */
    int last_errno = 0, any_open = 0;
    int recognized_errno = 0, recognized_di = -1;
    unsigned recognized_cmd = 0;
    int ndev = 0;
    while (g_param_devs[ndev])
        ndev++;

    for (int k = 0; k < ndev; k++) {
        int start = g_param_dev_idx >= 0 ? g_param_dev_idx : ndev - 1;
        int di = (start + k) % ndev;
        /* /dev/pfsctldev is created with mode 0400 (S_IRUSR): O_RDWR hits
         * EACCES even as uid 0 on PS5's prison-restricted kernel.  Try
         * O_RDONLY first — ioctl() works regardless of open mode — then
         * fall back to O_RDWR in case another node needs it. */
        int fd = open(g_param_devs[di], O_RDONLY);
        if (fd < 0 && errno == EACCES)
            fd = open(g_param_devs[di], O_RDWR);
        if (fd < 0) {
            int oe = errno;
            if (!g_param_logged_open[di]) {
                g_param_logged_open[di] = 1;
                logprintf("[GarlicMgr] PS5PARAM: open(%s) failed errno=%d\n", g_param_devs[di], oe);
            }
            if (!last_errno)
                last_errno = oe;
            continue;
        }
        any_open = 1;
        if (!g_param_logged_open[di]) {
            g_param_logged_open[di] = 1;
            logprintf("[GarlicMgr] PS5PARAM: open(%s) OK\n", g_param_devs[di]);
        }
        for (int ci = 0; ci < 2; ci++) {
            unsigned cmd = cmds[ci];
            uint64_t out = 0;
            pfs_param_arg_t a;
            memset(&a, 0, sizeof(a));
            a.path = img;
            a.buf = blob;
            a.size = size;
            a.out = &out;
            if (!wr)
                memset(blob, 0, size);
            errno = 0;
            int r = ioctl(fd, cmd, &a);
            int ie = errno;
            logprintf("[GarlicMgr] PS5PARAM: %s %s cmd=%08x ret=%d errno=%d\n", g_param_devs[di],
                      wr ? "write" : "read", cmd, r, r < 0 ? ie : 0);
            if (r < 0) {
                last_errno = ie ? ie : EIO;
                int old_unsupported = recognized_errno == ENOTSUP || recognized_errno == EOPNOTSUPP;
                int new_unsupported = last_errno == ENOTSUP || last_errno == EOPNOTSUPP;
                if (wr && ie != ENOTTY &&
                    (!recognized_errno ||
                     (recognized_di == di && old_unsupported && !new_unsupported))) {
                    recognized_errno = last_errno;
                    recognized_di = di;
                    recognized_cmd = cmd;
                }
                continue;
            }
            if (wr) {
                close(fd);
                g_param_dev_idx = di;
                return 0;
            }
            if (ps5param_blob_magic_ok(blob)) {
                close(fd);
                g_param_dev_idx = di;
                return 0;
            }
            logprintf(
                "[GarlicMgr] PS5PARAM: %s accepted read but no PS5PARAM magic "
                "(first 16: %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x)\n",
                g_param_devs[di], blob[0], blob[1], blob[2], blob[3], blob[4], blob[5], blob[6],
                blob[7], blob[8], blob[9], blob[10], blob[11], blob[12], blob[13], blob[14],
                blob[15]);
            soft_ok = 1;
        }
        close(fd);
        if (wr && recognized_errno && (di == g_param_dev_idx || di == ndev - 1))
            break;
    }
    if (soft_ok) {
        memset(blob, 0, size);
        return 0;
    } /* "no blob" */
    if (!any_open)
        logprintf("[GarlicMgr] PS5PARAM: no candidate /dev node could be opened\n");
    int error = recognized_errno ? recognized_errno : (last_errno ? last_errno : EIO);
    if (wr)
        snprintf(g_ps5param_error, sizeof(g_ps5param_error),
                 "PS5PARAM write failed: device=%s command=0x%08x errno=%d (%s)",
                 recognized_di >= 0 ? g_param_devs[recognized_di] : "no supported device",
                 recognized_cmd, error, strerror(error));
    return -error;
}

/* returns SFO size > 0, 0 = no blob (PS4/not present), < 0 = error */
int ps5param_read_sfo(const char *img, uint8_t *sfo, uint32_t sfomax) {
    if (!img || !img[0] || !sfo || sfomax < CMP_PS5PARAM_HEADER_BYTES)
        return -1;
    static uint8_t blob[CMP_PS5PARAM_BLOB_BYTES];
    memset(blob, 0, sizeof(blob));
    ps5param_elevate();
    int r = ps5param_ioctl(img, blob, sizeof(blob), 0);
    if (r < 0)
        return r;

    uint64_t magic;
    uint32_t ver, sz, off;
    memcpy(&magic, blob, 8);
    memcpy(&ver, blob + 8, 4);
    memcpy(&sz, blob + 12, 4);
    memcpy(&off, blob + 16, 4);
    if (magic != CMP_PS5PARAM_MAGIC)
        return 0;
    if (ver != 0 || sz == 0 || sz > sfomax || off < CMP_PS5PARAM_HEADER_BYTES ||
        (uint64_t)off + sz > sizeof(blob)) {
        logprintf("[GarlicMgr] PS5PARAM: bad blob header ver=%u size=%u off=%u\n", ver, sz, off);
        return CMP_PS5PARAM_ERR_BAD_BLOB;
    }
    if (!sfo_bytes_valid(blob + off, sz))
        return CMP_PS5PARAM_ERR_BAD_SFO;
    memcpy(sfo, blob + off, sz);
    return (int)sz;
}

int ps5param_write_sfo(const char *img, const uint8_t *sfo, uint32_t sz) {
    g_ps5param_error[0] = 0;
    if (!img || !img[0] || !sfo_bytes_valid(sfo, sz) || sz > CMP_PS5PARAM_MAX_SFO_BYTES) {
        snprintf(g_ps5param_error, sizeof(g_ps5param_error),
                 "Invalid or oversized PS5 param.sfo input");
        return -EINVAL;
    }
    static uint8_t blob[CMP_PS5PARAM_BLOB_BYTES];
    memset(blob, 0, sizeof(blob));
    uint64_t magic = CMP_PS5PARAM_MAGIC;
    uint32_t ver = 0, off = CMP_PS5PARAM_HEADER_BYTES;
    memcpy(blob, &magic, 8);
    memcpy(blob + 8, &ver, 4);
    memcpy(blob + 12, &sz, 4);
    memcpy(blob + 16, &off, 4);
    memcpy(blob + CMP_PS5PARAM_HEADER_BYTES, sfo, sz);

    ps5param_elevate();
    g_ps5param_error[0] = 0;
    int r = ps5param_ioctl(img, blob, sizeof(blob), 1);
    if (r == 0) {
        static uint8_t check[CMP_PS5PARAM_BLOB_BYTES];
        int n = ps5param_read_sfo(img, check, sizeof(check));
        if (n <= 0) {
            snprintf(g_ps5param_error, sizeof(g_ps5param_error),
                     "PS5PARAM read-back failed after a successful write (result=%d)", n);
            return -EIO;
        }
        size_t common = (size_t)n < sz ? (size_t)n : sz;
        size_t first = 0;
        while (first < common && check[first] == sfo[first])
            first++;
        int equal = first == common;
        if (equal && (size_t)n > common)
            for (size_t i = common; i < (size_t)n; i++)
                if (check[i]) {
                    equal = 0;
                    first = i;
                    break;
                }
        if (equal && sz > common)
            for (size_t i = common; i < sz; i++)
                if (sfo[i]) {
                    equal = 0;
                    first = i;
                    break;
                }
        if (!equal) {
            snprintf(g_ps5param_error, sizeof(g_ps5param_error),
                     "PS5PARAM read-back differs at byte %zu (written=%u read=%d)", first, sz, n);
            return -EIO;
        }
    }
    return r;
}

/* Read the blob before mounting: avoids racing the active PFS mount and
 * keeps the real metadata available to every later handler. */
void ps5param_capture_for_image(const char *img) {
    ps5param_clear_cache();
    if (!img || !img[0])
        return;
    struct stat st;
    if (stat(img, &st) < 0 || !S_ISREG(st.st_mode))
        return;
    int r = ps5param_read_sfo(img, g_mount_real_sfo, sizeof(g_mount_real_sfo));
    if (r > 0) {
        g_mount_real_sfo_len = (uint32_t)r;
        snprintf(g_mount_real_sfo_image, sizeof(g_mount_real_sfo_image), "%s", img);
        logprintf("[GarlicMgr] PS5PARAM: cached real param.sfo (%d B) from %s\n", r, img);
    } else if (r < 0) {
        logprintf("[GarlicMgr] PS5PARAM: no blob read from %s (%d)\n", img, r);
    }
}
