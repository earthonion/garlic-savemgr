/*
 * Garlic SaveMgr for PS5 - save decrypt/encrypt/browse with embedded web UI
 * Open http://<ps5-ip>:8082/ in any browser — no local app needed
 * by earthonion
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dlfcn.h>

#include <ps5/kernel.h>

/* ── SDK imports ────────────────────────────────────────────────── */
typedef struct { uint8_t reserved; char *budgetid; } MountOpt;
typedef struct { uint8_t dummy; } UmountOpt;

int sceFsInitMountSaveDataOpt(MountOpt *opt);
int sceFsMountSaveData(MountOpt *opt, const char *path, const char *mount, uint8_t *key);
int sceFsInitUmountSaveDataOpt(UmountOpt *opt);
int sceFsUmountSaveData(UmountOpt *opt, const char *mount, int handle, int ignore);

typedef struct { int blockSize; uint8_t flags[2]; } CreateOpt;
int sceFsInitCreatePfsSaveDataOpt(CreateOpt *opt);
int sceFsCreatePfsSaveDataImage(CreateOpt *opt, const char *path, int x, uint64_t size, uint8_t *key);
/* sceFsCreatePprPfsSaveDataImage - loaded via dlsym at runtime */
typedef int (*PprCreateFn)(CreateOpt *opt, const char *path, int x, uint64_t size, uint8_t *key);
static PprCreateFn g_pprCreate = NULL;
int sceFsUfsAllocateSaveData(int fd, uint64_t size, uint64_t flags, int ext);

int sceUserServiceInitialize(void*);

typedef struct { char unused[45]; char message[3075]; } notify_request_t;
int sceKernelSendNotificationRequest(int, notify_request_t*, size_t, int);

/* ── Constants ──────────────────────────────────────────────────── */
#define PORT            8082
#define MOUNT_BASE      "/data/save_mnt"
#define BUF_SIZE        (512 * 1024)
#define MAX_REQ         8192
#define MAX_PATH_LEN    1024

static char g_iobuf[BUF_SIZE];

/* ── Save entry ─────────────────────────────────────────────────── */
typedef struct {
    char path[MAX_PATH_LEN];     /* full path to save image file */
    char title_id[32];           /* e.g. PPSA01234 */
    char save_name[256];         /* save file name (varies per game) */
    char dir_name[256];          /* for mount point naming */
} save_entry_t;

static save_entry_t *g_saves = NULL;
static int g_save_count = 0;
static int g_save_cap = 0;

static save_entry_t *save_alloc(void) {
    if (g_save_count >= g_save_cap) {
        int newcap = g_save_cap ? g_save_cap * 2 : 64;
        save_entry_t *p = realloc(g_saves, newcap * sizeof(save_entry_t));
        if (!p) return NULL;
        g_saves = p;
        g_save_cap = newcap;
    }
    return &g_saves[g_save_count++];
}
static char g_mounted_path[MAX_PATH_LEN] = {0};
static char g_mount_point[MAX_PATH_LEN] = {0};
static int g_mounted = 0;
static char g_local_copy[MAX_PATH_LEN] = {0};

/* ── Notification ───────────────────────────────────────────────── */
static void notify(const char *fmt, ...) {
    notify_request_t req;
    memset(&req, 0, sizeof(req));
    va_list a; va_start(a, fmt);
    vsnprintf(req.message, sizeof(req.message), fmt, a);
    va_end(a);
    sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
    printf("[GarlicMgr] %s\n", req.message);
}

/* ── Save discovery ─────────────────────────────────────────────── */
static void scan_title_dir(const char *title_path, const char *title_id) {
    DIR *d = opendir(title_path);
    if (!d) return;

    struct dirent *ent;
    while ((ent = readdir(d))) {
        if (ent->d_name[0] == '.') continue;

        char filepath[MAX_PATH_LEN];
        snprintf(filepath, sizeof(filepath), "%s/%s", title_path, ent->d_name);

        struct stat st;
        if (stat(filepath, &st) == 0 && S_ISREG(st.st_mode)) {
            save_entry_t *s = save_alloc();
            if (!s) break;
            snprintf(s->path, sizeof(s->path), "%s", filepath);
            snprintf(s->title_id, sizeof(s->title_id), "%s", title_id);
            snprintf(s->save_name, sizeof(s->save_name), "%s", ent->d_name);
            snprintf(s->dir_name, sizeof(s->dir_name), "%s_%s", title_id, ent->d_name);
        }
    }
    closedir(d);
}

static void scan_savedata_prospero(const char *prospero_path) {
    DIR *d = opendir(prospero_path);
    if (!d) return;

    struct dirent *ent;
    while ((ent = readdir(d))) {
        if (ent->d_name[0] == '.') continue;

        char title_path[MAX_PATH_LEN];
        snprintf(title_path, sizeof(title_path), "%s/%s", prospero_path, ent->d_name);

        struct stat st;
        if (stat(title_path, &st) == 0 && S_ISDIR(st.st_mode))
            scan_title_dir(title_path, ent->d_name);
    }
    closedir(d);
}

static void scan_saves(void) {
    g_save_count = 0;

    /* /user/home/<userid>/savedata_prospero/<TitleId>/<savefile> */
    DIR *home = opendir("/user/home");
    if (home) {
        struct dirent *ue;
        while ((ue = readdir(home))) {
            if (ue->d_name[0] == '.') continue;
            char prospero[MAX_PATH_LEN];
            snprintf(prospero, sizeof(prospero), "/user/home/%s/savedata_prospero", ue->d_name);
            scan_savedata_prospero(prospero);
        }
        closedir(home);
    }

    /* /data/save_files/ for manually placed saves */
    DIR *d = opendir("/data/save_files");
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d))) {
            if (ent->d_name[0] == '.') continue;
            char filepath[MAX_PATH_LEN];
            snprintf(filepath, sizeof(filepath), "/data/save_files/%s", ent->d_name);
            struct stat st;
            if (stat(filepath, &st) == 0 && S_ISREG(st.st_mode)) {
                save_entry_t *s = save_alloc();
                if (!s) break;
                snprintf(s->path, sizeof(s->path), "%s", filepath);
                snprintf(s->title_id, sizeof(s->title_id), "manual");
                snprintf(s->save_name, sizeof(s->save_name), "%s", ent->d_name);
                snprintf(s->dir_name, sizeof(s->dir_name), "manual_%s", ent->d_name);
            }
        }
        closedir(d);
    }
}

/* ── Recursive delete helper ────────────────────────────────────── */
static void delete_recursive(const char *path) {
    DIR *d = opendir(path);
    if (!d) return;
    struct dirent *ent;
    while ((ent = readdir(d))) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) continue;
        char fp[MAX_PATH_LEN];
        snprintf(fp, sizeof(fp), "%s/%s", path, ent->d_name);
        struct stat st;
        if (stat(fp, &st) < 0) continue;
        if (S_ISDIR(st.st_mode)) {
            delete_recursive(fp);
            rmdir(fp);
        } else {
            unlink(fp);
        }
    }
    closedir(d);
}

/* ── Copy file helper ───────────────────────────────────────────── */
static int copy_file(const char *src, const char *dst) {
    int sfd = open(src, O_RDONLY);
    if (sfd < 0) return -1;
    int dfd = open(dst, O_CREAT | O_WRONLY | O_TRUNC, 0755);
    if (dfd < 0) { close(sfd); return -2; }
    char *buf = g_iobuf;
    ssize_t n;
    while ((n = read(sfd, buf, BUF_SIZE)) > 0)
        write(dfd, buf, n);
    close(sfd);
    close(dfd);
    return 0;
}

/* ── Mount / unmount ────────────────────────────────────────────── */
static int mount_save(int idx) {
    if (g_mounted) return -1;
    if (idx < 0 || idx >= g_save_count) return -2;

    save_entry_t *s = &g_saves[idx];

    /* Set authid — same as save-mounter, nothing else */
    kernel_set_ucred_authid(getpid(), 0x4800000000000010ULL);

    /*
     * If save is NOT on /data/, copy there first.
     * Direct mount from savedata_prospero causes EPIPE.
     */
    const char *mount_src = s->path;
    g_local_copy[0] = 0;
    int is_on_data = (strncmp(s->path, "/data/", 6) == 0);

    if (!is_on_data) {
        snprintf(g_local_copy, sizeof(g_local_copy), "/data/save_files/%s", s->save_name);
        printf("[GarlicMgr] Copying %s -> %s\n", s->path, g_local_copy);
        mkdir("/data/save_files", 0777);
        if (copy_file(s->path, g_local_copy) < 0) {
            printf("[GarlicMgr] Copy failed (errno %d: %s)\n", errno, strerror(errno));
            return -3;
        }
        chmod(g_local_copy, 0755);
        mount_src = g_local_copy;
        struct stat cst;
        if (stat(g_local_copy, &cst) == 0)
            printf("[GarlicMgr] Copy OK (%lld bytes)\n", (long long)cst.st_size);
        else
            printf("[GarlicMgr] Copy OK but stat failed\n");

        /* Verify copy matches source */
        struct stat sst;
        if (stat(s->path, &sst) == 0)
            printf("[GarlicMgr] Source was %lld bytes\n", (long long)sst.st_size);
    }

    /* Read sealed key at 0x800 and decrypt via pfsmgr — same as save-mounter */
    struct {
        uint8_t key[0x60];
        uint8_t hash[0x20];
        uint32_t result;
    } pfsbuf;

    int fd = open(mount_src, O_RDONLY);
    if (fd < 0) {
        printf("[GarlicMgr] Cannot open %s (errno %d: %s)\n", mount_src, errno, strerror(errno));
        return -4;
    }
    int ret = pread(fd, pfsbuf.key, 0x60, 0x800);
    close(fd);
    if (ret != 0x60) {
        printf("[GarlicMgr] Failed to read sealed key (ret=%d)\n", ret);
        return -5;
    }

    int pfsmgr = open("/dev/pfsmgr", 2);
    if (pfsmgr < 0) {
        printf("[GarlicMgr] Cannot open /dev/pfsmgr\n");
        return -6;
    }
    ret = ioctl(pfsmgr, 0xc0845302, &pfsbuf);
    close(pfsmgr);
    printf("[GarlicMgr] ioctl ret=%d result=0x%08x\n", ret, pfsbuf.result);
    printf("[GarlicMgr] Hash: ");
    for (int i = 0; i < 0x20; i++) printf("%02x", pfsbuf.hash[i]);
    printf("\n");
    if (ret < 0) {
        printf("[GarlicMgr] ioctl failed (ret=%d), using zeroed key\n", ret);
        memset(pfsbuf.hash, 0, sizeof(pfsbuf.hash));
    }

    snprintf(g_mount_point, sizeof(g_mount_point), "/data/mount_sd");
    mkdir(g_mount_point, 0777);

    MountOpt mopt;
    memset(&mopt, 0, sizeof(mopt));
    sceFsInitMountSaveDataOpt(&mopt);
    mopt.budgetid = "system";

    /* Restore default SIGPIPE handler before mount — EPIPE may be related */
    signal(SIGPIPE, SIG_DFL);

    ret = sceFsMountSaveData(&mopt, mount_src, g_mount_point, pfsbuf.hash);

    /* Re-ignore SIGPIPE for socket operations */
    signal(SIGPIPE, SIG_IGN);

    if (ret >= 0) {
        printf("[GarlicMgr] Mounted OK (handle=%d)\n", ret);
        snprintf(g_mounted_path, sizeof(g_mounted_path), "%s", s->path);
        g_mounted = 1;
        return 0;
    }
    printf("[GarlicMgr] Mount failed (0x%x, errno=%d: %s)\n", ret, errno, strerror(errno));

    /* Don't delete copy — leave for debugging */
    return ret;
}

static int unmount_save(void) {
    if (!g_mounted) return -1;

    UmountOpt uopt;
    memset(&uopt, 0, sizeof(uopt));
    sceFsInitUmountSaveDataOpt(&uopt);
    sceFsUmountSaveData(&uopt, g_mount_point, 0, 0);
    sync();

    /* Copy modified save back to original location */
    if (g_local_copy[0] && g_mounted_path[0]) {
        printf("[GarlicMgr] Copying back %s -> %s\n", g_local_copy, g_mounted_path);
        copy_file(g_local_copy, g_mounted_path);
        unlink(g_local_copy);
    }

    g_mounted = 0;
    g_mounted_path[0] = 0;
    g_mount_point[0] = 0;
    g_local_copy[0] = 0;
    return 0;
}

/* ── Mount by path (for uploaded files already on /data/) ──────── */
static int mount_by_path(const char *path) {
    if (g_mounted) unmount_save();

    kernel_set_ucred_authid(getpid(), 0x4800000000000010ULL);

    struct {
        uint8_t key[0x60];
        uint8_t hash[0x20];
        uint32_t result;
    } pfsbuf;

    int fd = open(path, O_RDONLY);
    if (fd < 0) { printf("[GarlicMgr] mount_by_path: cannot open %s\n", path); return -1; }
    int ret = pread(fd, pfsbuf.key, 0x60, 0x800);
    close(fd);
    if (ret != 0x60) return -2;

    int pfsmgr = open("/dev/pfsmgr", 2);
    if (pfsmgr < 0) return -3;
    ret = ioctl(pfsmgr, 0xc0845302, &pfsbuf);
    close(pfsmgr);
    if (ret < 0) memset(pfsbuf.hash, 0, sizeof(pfsbuf.hash));

    snprintf(g_mount_point, sizeof(g_mount_point), "/data/mount_sd");
    mkdir(g_mount_point, 0777);

    MountOpt mopt;
    memset(&mopt, 0, sizeof(mopt));
    sceFsInitMountSaveDataOpt(&mopt);
    mopt.budgetid = "system";

    signal(SIGPIPE, SIG_DFL);
    ret = sceFsMountSaveData(&mopt, path, g_mount_point, pfsbuf.hash);
    signal(SIGPIPE, SIG_IGN);

    if (ret >= 0) {
        printf("[GarlicMgr] mount_by_path: mounted %s (handle=%d)\n", path, ret);
        snprintf(g_mounted_path, sizeof(g_mounted_path), "%s", path);
        g_local_copy[0] = 0;
        g_mounted = 1;
        return 0;
    }
    printf("[GarlicMgr] mount_by_path: failed 0x%x\n", ret);
    return ret;
}

/* ── CRC32 ─────────────────────────────────────────────────────── */
static uint32_t crc_tab[256];
static void init_crc(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++) c = (c >> 1) ^ (c & 1 ? 0xEDB88320 : 0);
        crc_tab[i] = c;
    }
}
static uint32_t calc_crc(const uint8_t *buf, size_t len) {
    uint32_t c = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++) c = crc_tab[(c ^ buf[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFF;
}

/* ── Zip streaming (download) ──────────────────────────────────── */
typedef struct { char name[512]; uint32_t crc; uint32_t size; uint32_t offset; } zip_entry_t;
#define MAX_ZIP_ENTRIES 4096

static void collect_files(const char *base, const char *prefix,
                          zip_entry_t *entries, int *count) {
    char dirpath[MAX_PATH_LEN];
    if (prefix[0])
        snprintf(dirpath, sizeof(dirpath), "%s/%s", base, prefix);
    else
        snprintf(dirpath, sizeof(dirpath), "%s", base);

    DIR *d = opendir(dirpath);
    if (!d) return;

    struct dirent *ent;
    while ((ent = readdir(d)) && *count < MAX_ZIP_ENTRIES) {
        if (ent->d_name[0] == '.') continue;
        char relpath[MAX_PATH_LEN];
        if (prefix[0])
            snprintf(relpath, sizeof(relpath), "%s/%s", prefix, ent->d_name);
        else
            snprintf(relpath, sizeof(relpath), "%s", ent->d_name);
        char fullpath[MAX_PATH_LEN];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", base, relpath);
        struct stat st;
        if (stat(fullpath, &st) < 0) continue;
        if (S_ISDIR(st.st_mode)) {
            collect_files(base, relpath, entries, count);
        } else if (S_ISREG(st.st_mode)) {
            zip_entry_t *e = &entries[*count];
            snprintf(e->name, sizeof(e->name), "%s", relpath);
            e->size = (uint32_t)st.st_size;
            e->crc = 0;
            e->offset = 0;
            (*count)++;
        }
    }
    closedir(d);
}

static void zip_send(int sock, const char *base) {
    zip_entry_t *entries = malloc(MAX_ZIP_ENTRIES * sizeof(zip_entry_t));
    if (!entries) return;
    int count = 0;
    collect_files(base, "", entries, &count);

    uint32_t offset = 0;
    for (int i = 0; i < count; i++) {
        zip_entry_t *e = &entries[i];
        e->offset = offset;
        uint16_t nlen = strlen(e->name);

        char fullpath[MAX_PATH_LEN];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", base, e->name);
        int fd = open(fullpath, O_RDONLY);
        uint8_t *fdata = NULL;
        if (fd >= 0 && e->size > 0) {
            fdata = malloc(e->size);
            if (fdata) { ssize_t r = read(fd, fdata, e->size); (void)r; }
            close(fd);
        } else if (fd >= 0) { close(fd); }
        e->crc = fdata ? calc_crc(fdata, e->size) : 0;

        uint8_t lh[30]; memset(lh, 0, 30);
        lh[0]=0x50; lh[1]=0x4b; lh[2]=0x03; lh[3]=0x04;
        lh[4]=20;
        memcpy(lh+14, &e->crc, 4);
        memcpy(lh+18, &e->size, 4);
        memcpy(lh+22, &e->size, 4);
        memcpy(lh+26, &nlen, 2);
        send(sock, lh, 30, 0);
        send(sock, e->name, nlen, 0);
        if (fdata) { send(sock, fdata, e->size, 0); free(fdata); }
        offset += 30 + nlen + e->size;
    }

    uint32_t cd_offset = offset;
    for (int i = 0; i < count; i++) {
        zip_entry_t *e = &entries[i];
        uint16_t nlen = strlen(e->name);
        uint8_t cd[46]; memset(cd, 0, 46);
        cd[0]=0x50; cd[1]=0x4b; cd[2]=0x01; cd[3]=0x02;
        cd[4]=20; cd[6]=20;
        memcpy(cd+16, &e->crc, 4);
        memcpy(cd+20, &e->size, 4);
        memcpy(cd+24, &e->size, 4);
        memcpy(cd+28, &nlen, 2);
        memcpy(cd+42, &e->offset, 4);
        send(sock, cd, 46, 0);
        send(sock, e->name, nlen, 0);
        offset += 46 + nlen;
    }
    uint32_t cd_size = offset - cd_offset;

    uint8_t ecd[22]; memset(ecd, 0, 22);
    ecd[0]=0x50; ecd[1]=0x4b; ecd[2]=0x05; ecd[3]=0x06;
    uint16_t cnt16 = (uint16_t)count;
    memcpy(ecd+8, &cnt16, 2);
    memcpy(ecd+10, &cnt16, 2);
    memcpy(ecd+12, &cd_size, 4);
    memcpy(ecd+16, &cd_offset, 4);
    send(sock, ecd, 22, 0);
    free(entries);
}

/* ── Zip extraction (upload) ────────────────────────────────────── */
static int extract_zip(const char *dest, const uint8_t *data, size_t len) {
    size_t off = 0;
    int count = 0;

    while (off + 30 <= len) {
        if (data[off]!=0x50 || data[off+1]!=0x4b ||
            data[off+2]!=0x03 || data[off+3]!=0x04) break;

        uint16_t compression = 0, name_len = 0, extra_len = 0;
        uint32_t comp_size = 0, uncomp_size = 0;
        memcpy(&compression, data + off + 8, 2);
        memcpy(&comp_size, data + off + 18, 4);
        memcpy(&uncomp_size, data + off + 22, 4);
        memcpy(&name_len, data + off + 26, 2);
        memcpy(&extra_len, data + off + 28, 2);

        char name[MAX_PATH_LEN] = {0};
        uint16_t copy_len = name_len < MAX_PATH_LEN - 1 ? name_len : (uint16_t)(MAX_PATH_LEN - 1);
        memcpy(name, data + off + 30, copy_len);
        off += 30 + name_len + extra_len;

        if (compression != 0) {
            printf("[GarlicMgr] Skipping compressed entry: %s\n", name);
            off += comp_size;
            continue;
        }

        if (name[0] && name[strlen(name)-1] == '/') {
            char dirpath[MAX_PATH_LEN];
            snprintf(dirpath, sizeof(dirpath), "%s/%s", dest, name);
            mkdir(dirpath, 0777);
        } else {
            char filepath[MAX_PATH_LEN];
            snprintf(filepath, sizeof(filepath), "%s/%s", dest, name);
            char *slash = filepath;
            while ((slash = strchr(slash + 1, '/')) != NULL) {
                *slash = 0; mkdir(filepath, 0777); *slash = '/';
            }
            int fd = open(filepath, O_CREAT | O_WRONLY | O_TRUNC, 0644);
            if (fd >= 0) {
                size_t to_write = uncomp_size;
                if (off + to_write > len) to_write = len - off;
                write(fd, data + off, to_write);
                close(fd);
                count++;
            }
        }
        off += comp_size;
    }
    return count;
}

/* ── File listing as JSON ───────────────────────────────────────── */
static int json_list_dir(char *out, size_t max, const char *base, const char *prefix) {
    char dirpath[MAX_PATH_LEN];
    if (prefix[0])
        snprintf(dirpath, sizeof(dirpath), "%s/%s", base, prefix);
    else
        snprintf(dirpath, sizeof(dirpath), "%s", base);

    DIR *d = opendir(dirpath);
    if (!d) return 0;

    int pos = 0, first = 1;
    struct dirent *ent;
    while ((ent = readdir(d))) {
        if (ent->d_name[0] == '.') continue;
        char fullpath[MAX_PATH_LEN];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", dirpath, ent->d_name);
        struct stat st;
        if (stat(fullpath, &st) < 0) continue;

        char relpath[MAX_PATH_LEN];
        if (prefix[0])
            snprintf(relpath, sizeof(relpath), "%s/%s", prefix, ent->d_name);
        else
            snprintf(relpath, sizeof(relpath), "%s", ent->d_name);

        if (!first) {
            if (out && pos < (int)max - 1) out[pos] = ',';
            pos++;
        }
        first = 0;
        pos += snprintf(out ? out + pos : NULL, out ? max - pos : 0,
            "{\"name\":\"%s\",\"dir\":%s,\"size\":%lld}",
            relpath, S_ISDIR(st.st_mode) ? "true" : "false", (long long)st.st_size);
        if (S_ISDIR(st.st_mode)) {
            if (out && pos < (int)max - 1) out[pos] = ',';
            pos++;
            pos += json_list_dir(out ? out + pos : NULL, out ? max - pos : 0, base, relpath);
        }
    }
    closedir(d);
    return pos;
}

/* ── Robust recv (retries on EINTR) ─────────────────────────────── */
static ssize_t recv_all(int sock, void *buf, size_t len) {
    while (1) {
        ssize_t r = recv(sock, buf, len, 0);
        if (r < 0 && errno == EINTR) continue;
        return r;
    }
}

/* ── HTTP helpers ───────────────────────────────────────────────── */
static void http_send(int sock, const char *status_line, const char *content_type,
                      const char *body, int body_len) {
    char hdr[1024];
    int hlen = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %d\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Content-Type\r\n"
        "Connection: close\r\n"
        "\r\n",
        status_line, content_type, body_len);
    send(sock, hdr, hlen, 0);
    if (body && body_len > 0)
        send(sock, body, body_len, 0);
}

static void http_json(int sock, const char *json) {
    http_send(sock, "200 OK", "application/json", json, strlen(json));
}

/* ── Embedded Web UI (generated from src/ui.html via xxd -i) ──── */
#include "ui.h"

/* ── Request handler ────────────────────────────────────────────── */
static void handle_request(int sock) {
    char req[MAX_REQ];
    int n = recv(sock, req, sizeof(req) - 1, 0);
    if (n <= 0) return;
    req[n] = 0;

    char method[8] = {0}, url[2048] = {0};
    sscanf(req, "%7s %2047s", method, url);

    /* Handle Expect: 100-continue for large uploads */
    if (strcasestr(req, "Expect: 100-continue"))
        send(sock, "HTTP/1.1 100 Continue\r\n\r\n", 25, 0);

    /* CORS preflight */
    if (strcmp(method, "OPTIONS") == 0) {
        http_send(sock, "204 No Content", "text/plain", NULL, 0);
        return;
    }

    /* GET / → embedded web UI */
    if (strcmp(method, "GET") == 0 && (strcmp(url, "/") == 0 || strcmp(url, "/index.html") == 0)) {
        http_send(sock, "200 OK", "text/html", (const char *)src_ui_html, src_ui_html_len);
        return;
    }

    /* GET /api/file_exists?name=... */
    if (strcmp(method, "GET") == 0 && strncmp(url, "/api/file_exists", 16) == 0) {
        if (!g_mounted) { http_json(sock, "{\"exists\":false}"); return; }
        char fname[512] = {0};
        char *np = strstr(url, "name=");
        if (np) {
            strncpy(fname, np + 5, sizeof(fname) - 1);
            char *r = fname, *w = fname;
            while (*r) {
                if (*r == '%' && r[1] && r[2]) {
                    char hex[3] = {r[1], r[2], 0};
                    *w++ = (char)strtol(hex, NULL, 16);
                    r += 3;
                } else { *w++ = *r++; }
            }
            *w = 0;
        }
        char filepath[MAX_PATH_LEN];
        snprintf(filepath, sizeof(filepath), "%s/%s", g_mount_point, fname);
        struct stat st;
        int exists = (stat(filepath, &st) == 0 && S_ISREG(st.st_mode));
        char json[128];
        snprintf(json, sizeof(json), "{\"exists\":%s}", exists ? "true" : "false");
        http_json(sock, json);
        return;
    }

    /* GET /api/download_file?name=<path> -> download single file from mounted save */
    if (strcmp(method, "GET") == 0 && strncmp(url, "/api/download_file", 18) == 0) {
        if (!g_mounted) { http_json(sock, "{\"error\":\"No save mounted\"}"); return; }
        char fname[512] = {0};
        char *np = strstr(url, "name=");
        if (np) {
            strncpy(fname, np + 5, sizeof(fname) - 1);
            char *r = fname, *w = fname;
            while (*r && *r != '&') {
                if (*r == '%' && r[1] && r[2]) {
                    char hex[3] = {r[1], r[2], 0};
                    *w++ = (char)strtol(hex, NULL, 16);
                    r += 3;
                } else { *w++ = *r++; }
            }
            *w = 0;
        }
        if (!fname[0]) { http_json(sock, "{\"error\":\"Missing name\"}"); return; }
        char filepath[MAX_PATH_LEN];
        snprintf(filepath, sizeof(filepath), "%s/%s", g_mount_point, fname);
        struct stat st;
        if (stat(filepath, &st) < 0 || !S_ISREG(st.st_mode)) {
            http_json(sock, "{\"error\":\"File not found\"}"); return;
        }
        int fd = open(filepath, O_RDONLY);
        if (fd < 0) { http_json(sock, "{\"error\":\"Cannot read file\"}"); return; }
        /* Use just the filename for download */
        const char *basename = strrchr(fname, '/');
        basename = basename ? basename + 1 : fname;
        char hdr[1024];
        int hlen = snprintf(hdr, sizeof(hdr),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/octet-stream\r\n"
            "Content-Disposition: attachment; filename=\"%s\"\r\n"
            "Content-Length: %lld\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Connection: close\r\n\r\n", basename, (long long)st.st_size);
        send(sock, hdr, hlen, 0);
        char *buf = g_iobuf;
        ssize_t nr;
        while ((nr = read(fd, buf, BUF_SIZE)) > 0)
            send(sock, buf, nr, 0);
        close(fd);
        return;
    }

    /* GET /api/delete_file?name=<path> -> delete file from mounted save */
    if (strcmp(method, "GET") == 0 && strncmp(url, "/api/delete_file", 16) == 0) {
        if (!g_mounted) { http_json(sock, "{\"error\":\"No save mounted\"}"); return; }
        char fname[512] = {0};
        char *np = strstr(url, "name=");
        if (np) {
            strncpy(fname, np + 5, sizeof(fname) - 1);
            char *r = fname, *w = fname;
            while (*r && *r != '&') {
                if (*r == '%' && r[1] && r[2]) {
                    char hex[3] = {r[1], r[2], 0};
                    *w++ = (char)strtol(hex, NULL, 16);
                    r += 3;
                } else { *w++ = *r++; }
            }
            *w = 0;
        }
        if (!fname[0]) { http_json(sock, "{\"error\":\"Missing name\"}"); return; }
        char filepath[MAX_PATH_LEN];
        snprintf(filepath, sizeof(filepath), "%s/%s", g_mount_point, fname);
        if (unlink(filepath) < 0) {
            http_json(sock, "{\"error\":\"Delete failed\"}"); return;
        }
        sync();
        printf("[GarlicMgr] Deleted %s\n", fname);
        http_json(sock, "{\"ok\":true}");
        return;
    }

    /* GET /api/files → file listing of mounted save */
    if (strcmp(method, "GET") == 0 && strcmp(url, "/api/files") == 0) {
        if (!g_mounted) { http_json(sock, "{\"files\":[]}"); return; }
        int need = snprintf(NULL, 0, "{\"files\":[");
        need += json_list_dir(NULL, 0, g_mount_point, "");
        need += snprintf(NULL, 0, "]}");
        char *json = malloc(need + 1);
        if (!json) { http_json(sock, "{\"error\":\"Out of memory\"}"); return; }
        int pos = snprintf(json, need + 1, "{\"files\":[");
        pos += json_list_dir(json + pos, need + 1 - pos, g_mount_point, "");
        snprintf(json + pos, need + 1 - pos, "]}");
        http_json(sock, json);
        free(json);
        return;
    }

    /* GET /api/icon -> serve icon0.png from mounted save */
    if (strcmp(method, "GET") == 0 && strncmp(url, "/api/icon", 9) == 0) {
        if (!g_mounted) { http_send(sock, "404 Not Found", "text/plain", "No mount", 8); return; }
        char icon_path[MAX_PATH_LEN];
        snprintf(icon_path, sizeof(icon_path), "%s/sce_sys/icon0.png", g_mount_point);
        struct stat st;
        if (stat(icon_path, &st) < 0) {
            http_send(sock, "404 Not Found", "text/plain", "No icon", 7); return;
        }
        int fd = open(icon_path, O_RDONLY);
        if (fd < 0) { http_send(sock, "500 Error", "text/plain", "Open fail", 9); return; }
        char hdr[512];
        int hlen = snprintf(hdr, sizeof(hdr),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: image/png\r\n"
            "Content-Length: %lld\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Cache-Control: no-cache\r\n"
            "Connection: close\r\n\r\n", (long long)st.st_size);
        send(sock, hdr, hlen, 0);
        char *buf = g_iobuf;
        ssize_t nr;
        while ((nr = read(fd, buf, BUF_SIZE)) > 0)
            send(sock, buf, nr, 0);
        close(fd);
        return;
    }

    /* GET /api/saves */
    if (strcmp(method, "GET") == 0 && strcmp(url, "/api/saves") == 0) {
        scan_saves();
        int need = snprintf(NULL, 0, "{\"saves\":[");
        for (int i = 0; i < g_save_count; i++) {
            if (i > 0) need++; /* comma */
            need += snprintf(NULL, 0,
                "{\"title_id\":\"%s\",\"save_name\":\"%s\",\"path\":\"%s\",\"dir\":\"%s\"}",
                g_saves[i].title_id, g_saves[i].save_name, g_saves[i].path, g_saves[i].dir_name);
        }
        need += snprintf(NULL, 0, "]}");
        char *json = malloc(need + 1);
        if (!json) { http_json(sock, "{\"error\":\"Out of memory\"}"); return; }
        int pos = snprintf(json, need + 1, "{\"saves\":[");
        for (int i = 0; i < g_save_count; i++) {
            if (i > 0) json[pos++] = ',';
            pos += snprintf(json + pos, need + 1 - pos,
                "{\"title_id\":\"%s\",\"save_name\":\"%s\",\"path\":\"%s\",\"dir\":\"%s\"}",
                g_saves[i].title_id, g_saves[i].save_name, g_saves[i].path, g_saves[i].dir_name);
        }
        snprintf(json + pos, need + 1 - pos, "]}");
        http_json(sock, json);
        free(json);
        return;
    }

    /* GET /api/mount?idx=N */
    if (strcmp(method, "GET") == 0 && strncmp(url, "/api/mount", 10) == 0) {
        if (g_mounted) unmount_save();

        int idx = -1;
        char *p = strstr(url, "idx=");
        if (p) idx = atoi(p + 4);

        int ret = mount_save(idx);
        if (ret < 0) {
            char json[256];
            snprintf(json, sizeof(json), "{\"error\":\"Mount failed: %d (0x%x)\"}", ret, ret);
            http_json(sock, json);
            return;
        }

        /* Read param.sfo: account ID (8B @ 0x1B8), save title (0x20B @ 0x5DC), title ID (9B @ 0xB20) */
        char acct_id[20] = {0};
        char save_title[64] = {0};
        char sfo_title_id[16] = {0};
        char sfo_path[MAX_PATH_LEN];
        snprintf(sfo_path, sizeof(sfo_path), "%s/sce_sys/param.sfo", g_mount_point);
        int sfo_fd = open(sfo_path, O_RDONLY);
        if (sfo_fd >= 0) {
            uint8_t aid[8];
            if (pread(sfo_fd, aid, 8, 0x1B8) == 8)
                snprintf(acct_id, sizeof(acct_id), "0x%02X%02X%02X%02X%02X%02X%02X%02X",
                    aid[0],aid[1],aid[2],aid[3],aid[4],aid[5],aid[6],aid[7]);
            char raw_title[0x21] = {0};
            if (pread(sfo_fd, raw_title, 0x20, 0x5DC) > 0) {
                raw_title[0x20] = 0;
                int tp = 0;
                for (int ti = 0; raw_title[ti] && tp < (int)sizeof(save_title) - 2; ti++) {
                    char ch = raw_title[ti];
                    if (ch == '"' || ch == '\\') { save_title[tp++] = '\\'; }
                    if (ch >= 0x20) save_title[tp++] = ch;
                }
                save_title[tp] = 0;
            }
            if (pread(sfo_fd, sfo_title_id, 9, 0xB20) > 0)
                sfo_title_id[9] = 0;
            close(sfo_fd);
        }

        const char *tid = sfo_title_id[0] ? sfo_title_id : g_saves[idx].title_id;
        int need = snprintf(NULL, 0,
            "{\"title_id\":\"%s\",\"save_name\":\"%s\",\"mount\":\"%s\","
            "\"account_id\":\"%s\",\"save_title\":\"%s\",\"files\":[",
            tid, g_saves[idx].save_name, g_mount_point, acct_id, save_title);
        need += json_list_dir(NULL, 0, g_mount_point, "");
        need += snprintf(NULL, 0, "]}");
        char *json = malloc(need + 1);
        if (!json) { http_json(sock, "{\"error\":\"Out of memory\"}"); return; }
        int pos = snprintf(json, need + 1,
            "{\"title_id\":\"%s\",\"save_name\":\"%s\",\"mount\":\"%s\","
            "\"account_id\":\"%s\",\"save_title\":\"%s\",\"files\":[",
            tid, g_saves[idx].save_name, g_mount_point, acct_id, save_title);
        pos += json_list_dir(json + pos, need + 1 - pos, g_mount_point, "");
        snprintf(json + pos, need + 1 - pos, "]}");
        http_json(sock, json);
        free(json);
        return;
    }

    /* GET /api/download_raw?idx=N -> stream raw save image (no mount needed) */
    if (strcmp(method, "GET") == 0 && strncmp(url, "/api/download_raw", 17) == 0) {
        scan_saves();
        int idx = -1;
        char *p = strstr(url, "idx=");
        if (p) idx = atoi(p + 4);
        if (idx < 0 || idx >= g_save_count) {
            http_json(sock, "{\"error\":\"Invalid index\"}");
            return;
        }
        save_entry_t *s = &g_saves[idx];
        /* Escalate to read savedata_prospero */
        pid_t rpid = getpid();
        kernel_set_ucred_uid(rpid, 0);
        kernel_set_ucred_authid(rpid, 0x4800000000000010ULL);

        struct stat st;
        if (stat(s->path, &st) < 0) {
            http_json(sock, "{\"error\":\"File not found\"}");
            return;
        }
        int fd = open(s->path, O_RDONLY);
        if (fd < 0) {
            http_json(sock, "{\"error\":\"Cannot open file\"}");
            return;
        }
        char hdr[512];
        int hlen = snprintf(hdr, sizeof(hdr),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/octet-stream\r\n"
            "Content-Disposition: attachment; filename=\"%s\"\r\n"
            "Content-Length: %lld\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Connection: close\r\n"
            "\r\n", s->save_name, (long long)st.st_size);
        send(sock, hdr, hlen, 0);
        char *buf = g_iobuf;
        ssize_t nr;
        while ((nr = read(fd, buf, BUF_SIZE)) > 0)
            send(sock, buf, nr, 0);
        close(fd);
        return;
    }

    /* GET /api/download -> tar stream */
    if (strcmp(method, "GET") == 0 && strcmp(url, "/api/download") == 0) {
        if (!g_mounted) { http_json(sock, "{\"error\":\"No save mounted\"}"); return; }
        char hdr[512];
        int hlen = snprintf(hdr, sizeof(hdr),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/zip\r\n"
            "Content-Disposition: attachment; filename=\"save.zip\"\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Connection: close\r\n"
            "\r\n");
        send(sock, hdr, hlen, 0);
        zip_send(sock, g_mount_point);
        return;
    }

    /* GET /api/dump_usb?idx=N -> copy raw save to /mnt/usb0/saves/<titleid>/ with progress */
    if (strcmp(method, "GET") == 0 && strncmp(url, "/api/dump_usb", 13) == 0) {
        scan_saves();
        int idx = -1;
        char *p = strstr(url, "idx=");
        if (p) idx = atoi(p + 4);
        if (idx < 0 || idx >= g_save_count) {
            http_json(sock, "{\"error\":\"Invalid index\"}"); return;
        }
        save_entry_t *s = &g_saves[idx];
        pid_t rpid = getpid();
        kernel_set_ucred_uid(rpid, 0);
        kernel_set_ucred_authid(rpid, 0x4800000000000010ULL);

        struct stat sst;
        if (stat(s->path, &sst) < 0) {
            http_json(sock, "{\"error\":\"Source file not found\"}"); return;
        }

        mkdir("/mnt/usb0/saves", 0777);
        char title_dir[MAX_PATH_LEN];
        snprintf(title_dir, sizeof(title_dir), "/mnt/usb0/saves/%s", s->title_id);
        mkdir(title_dir, 0777);

        char dst[MAX_PATH_LEN];
        snprintf(dst, sizeof(dst), "%s/%s", title_dir, s->save_name);

        int sfd = open(s->path, O_RDONLY);
        if (sfd < 0) {
            http_json(sock, "{\"error\":\"Cannot open source - is USB inserted?\"}"); return;
        }
        int dfd = open(dst, O_CREAT | O_WRONLY | O_TRUNC, 0755);
        if (dfd < 0) {
            close(sfd);
            http_json(sock, "{\"error\":\"Cannot create dest - is USB inserted?\"}"); return;
        }

        /* Stream progress as newline-delimited JSON */
        char hdr[512];
        int hlen = snprintf(hdr, sizeof(hdr),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/x-ndjson\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Connection: close\r\n\r\n");
        send(sock, hdr, hlen, 0);

        char *buf = g_iobuf;
        ssize_t nr;
        size_t copied = 0;
        long long total = (long long)sst.st_size;
        int last_pct = -1;
        while ((nr = read(sfd, buf, BUF_SIZE)) > 0) {
            write(dfd, buf, nr);
            copied += nr;
            int pct = total > 0 ? (int)(copied * 100 / total) : 100;
            if (pct != last_pct) {
                last_pct = pct;
                char prog[128];
                int plen = snprintf(prog, sizeof(prog),
                    "{\"progress\":%d,\"copied\":%zu,\"total\":%lld}\n", pct, copied, total);
                send(sock, prog, plen, 0);
            }
        }
        close(sfd);
        close(dfd);

        char done[512];
        int dlen = snprintf(done, sizeof(done),
            "{\"ok\":true,\"path\":\"%s/%s\",\"size\":%lld}\n",
            title_dir, s->save_name, total);
        send(sock, done, dlen, 0);
        return;
    }

    /* GET /api/unmount */
    if (strcmp(method, "GET") == 0 && strcmp(url, "/api/unmount") == 0) {
        int ret = unmount_save();
        char json[128];
        snprintf(json, sizeof(json), "{\"ok\":%s}", ret == 0 ? "true" : "false");
        http_json(sock, json);
        return;
    }

    /* GET /api/shutdown */
    if (strcmp(method, "GET") == 0 && strcmp(url, "/api/shutdown") == 0) {
        if (g_mounted) unmount_save();
        /* Clean up all known mount points */
        UmountOpt uclean;
        memset(&uclean, 0, sizeof(uclean));
        sceFsInitUmountSaveDataOpt(&uclean);
        sceFsUmountSaveData(&uclean, "/data/mount_sd", 0, 0);
        sync();
        http_json(sock, "{\"ok\":true}");
        close(sock);
        notify("Garlic SaveMgr: Shutting down");
        kill(getpid(), SIGKILL);
        return;
    }

    /* GET /api/status */
    if (strcmp(method, "GET") == 0 && strcmp(url, "/api/status") == 0) {
        char json[512];
        snprintf(json, sizeof(json),
            "{\"mounted\":%s,\"mount_point\":\"%s\",\"save_path\":\"%s\"}",
            g_mounted ? "true" : "false", g_mount_point, g_mounted_path);
        http_json(sock, json);
        return;
    }

    /* POST /api/decrypt_upload -> upload encrypted .bin, get decrypted .zip */
    if (strcmp(method, "POST") == 0 && strcmp(url, "/api/decrypt_upload") == 0) {
        size_t clen = 0;
        char *cl = strcasestr(req, "Content-Length:");
        if (cl) clen = strtoul(cl + 15, NULL, 10);
        if (clen == 0 || clen > (size_t)2 * 1024 * 1024 * 1024) {
            http_json(sock, "{\"error\":\"Invalid size\"}"); return;
        }
        char *body_start = strstr(req, "\r\n\r\n");
        if (!body_start) { http_json(sock, "{\"error\":\"Bad request\"}"); return; }
        body_start += 4;
        size_t body_in_buf = n - (body_start - req);

        mkdir("/data/save_files", 0777);
        const char *tmp = "/data/save_files/_tmp_dec";
        int fd = open(tmp, O_CREAT | O_WRONLY | O_TRUNC, 0755);
        if (fd < 0) { http_json(sock, "{\"error\":\"Cannot create temp file\"}"); return; }
        if (body_in_buf > clen) body_in_buf = clen;
        write(fd, body_start, body_in_buf);
        size_t received = body_in_buf;
        while (received < clen) {
            char *buf = g_iobuf;
            size_t want = BUF_SIZE < (clen - received) ? BUF_SIZE : (clen - received);
            ssize_t r = recv_all(sock, buf, want);
            if (r <= 0) break;
            write(fd, buf, r);
            received += r;
        }
        close(fd);
        printf("[GarlicMgr] decrypt_upload: received %zu bytes\n", received);

        int ret = mount_by_path(tmp);
        if (ret < 0) {
            unlink(tmp);
            char json[128];
            snprintf(json, sizeof(json), "{\"error\":\"Mount failed: %d\"}", ret);
            http_json(sock, json); return;
        }

        char hdr[512];
        int hlen = snprintf(hdr, sizeof(hdr),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/zip\r\n"
            "Content-Disposition: attachment; filename=\"decrypted.zip\"\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Connection: close\r\n\r\n");
        send(sock, hdr, hlen, 0);
        zip_send(sock, g_mount_point);

        unmount_save();
        unlink(tmp);
        return;
    }

    /* POST /api/encrypt_upload?aid=<optional hex> -> upload .zip, get encrypted save */
    if (strcmp(method, "POST") == 0 && strncmp(url, "/api/encrypt_upload", 19) == 0) {
        size_t clen = 0;
        char *cl = strcasestr(req, "Content-Length:");
        if (cl) clen = strtoul(cl + 15, NULL, 10);
        if (clen == 0 || clen > (size_t)2 * 1024 * 1024 * 1024) {
            http_json(sock, "{\"error\":\"Invalid size\"}"); return;
        }
        char *body_start = strstr(req, "\r\n\r\n");
        if (!body_start) { http_json(sock, "{\"error\":\"Bad request\"}"); return; }
        body_start += 4;
        size_t body_in_buf = n - (body_start - req);

        uint8_t *tar_data = malloc(clen);
        if (!tar_data) { http_json(sock, "{\"error\":\"Out of memory\"}"); return; }
        if (body_in_buf > clen) body_in_buf = clen;
        memcpy(tar_data, body_start, body_in_buf);
        size_t received = body_in_buf;
        while (received < clen) {
            ssize_t r = recv_all(sock, tar_data + received, clen - received);
            if (r <= 0) break;
            received += r;
        }
        printf("[GarlicMgr] encrypt_upload: received %zu bytes zip\n", received);

        mkdir("/data/save_files", 0777);
        const char *tmp = "/data/save_files/_tmp_enc";
        unlink(tmp);
        kernel_set_ucred_authid(getpid(), 0x4800000000000010ULL);

        /* Size: data + 25% overhead + 4MB, min 32MB, aligned to 32K */
        uint64_t img_size = clen + (clen / 4) + (4 * 1024 * 1024);
        if (img_size < 32 * 1024 * 1024)
            img_size = 32 * 1024 * 1024;
        img_size = ((img_size + 32767) / 32768) * 32768;

        /* Step 1: Create file and allocate space (same as mkpfs) */
        int imgfd = open(tmp, O_CREAT | O_TRUNC | O_RDWR, 0777);
        if (imgfd < 0) {
            free(tar_data);
            http_json(sock, "{\"error\":\"Cannot create temp file\"}"); return;
        }
        int ret = sceFsUfsAllocateSaveData(imgfd, img_size, 0, 0);
        if (ret < 0) {
            printf("[GarlicMgr] UfsAllocate failed (0x%x), using ftruncate\n", ret);
            if (ftruncate(imgfd, img_size) < 0) {
                close(imgfd); free(tar_data); unlink(tmp);
                http_json(sock, "{\"error\":\"Cannot allocate image\"}"); return;
            }
        }
        close(imgfd);
        printf("[GarlicMgr] Created image file %llu bytes\n", (unsigned long long)img_size);

        /* Step 2: Format as PFS with compression */
        CreateOpt copt;
        memset(&copt, 0, sizeof(copt));
        sceFsInitCreatePfsSaveDataOpt(&copt);
        copt.flags[1] = 0x02;
        uint8_t ckey[0x20] = {0};
        if (!g_pprCreate) {
            free(tar_data); unlink(tmp);
            http_json(sock, "{\"error\":\"PprCreate not available\"}"); return;
        }
        ret = g_pprCreate(&copt, tmp, 0, img_size, ckey);
        printf("[GarlicMgr] PprCreate returned 0x%x\n", ret);
        if (ret < 0) {
            free(tar_data); unlink(tmp);
            char json[128];
            snprintf(json, sizeof(json), "{\"error\":\"Format PFS failed: 0x%x\"}", ret);
            http_json(sock, json); return;
        }
        printf("[GarlicMgr] Formatted PFS image OK\n");

        /* Step 3: Mount with zeroed key directly (no ioctl needed) */
        if (g_mounted) unmount_save();
        snprintf(g_mount_point, sizeof(g_mount_point), "/data/mount_sd");
        mkdir(g_mount_point, 0777);
        MountOpt emopt;
        memset(&emopt, 0, sizeof(emopt));
        sceFsInitMountSaveDataOpt(&emopt);
        emopt.budgetid = "system";
        signal(SIGPIPE, SIG_DFL);
        ret = sceFsMountSaveData(&emopt, tmp, g_mount_point, ckey);
        signal(SIGPIPE, SIG_IGN);
        if (ret < 0) {
            free(tar_data); unlink(tmp);
            char json[128];
            snprintf(json, sizeof(json), "{\"error\":\"Mount failed: 0x%x\"}", ret);
            http_json(sock, json); return;
        }
        snprintf(g_mounted_path, sizeof(g_mounted_path), "%s", tmp);
        g_local_copy[0] = 0;
        g_mounted = 1;
        printf("[GarlicMgr] Mounted new PFS (handle=%d)\n", ret);

        /* Step 4: Extract zip into mounted PFS */
        int files = extract_zip(g_mount_point, tar_data, received);
        free(tar_data);
        sync();
        printf("[GarlicMgr] Extracted %d files for encrypt\n", files);

        /* Optional: patch account ID in param.sfo */
        char *ap = strstr(url, "aid=");
        if (ap) {
            char aid_hex[64] = {0};
            strncpy(aid_hex, ap + 4, sizeof(aid_hex) - 1);
            char *rp2 = aid_hex, *wp2 = aid_hex;
            while (*rp2 && *rp2 != '&') {
                if (*rp2 == '%' && rp2[1] && rp2[2]) {
                    char hx[3] = {rp2[1], rp2[2], 0};
                    *wp2++ = (char)strtol(hx, NULL, 16);
                    rp2 += 3;
                } else { *wp2++ = *rp2++; }
            }
            *wp2 = 0;
            char *hs = aid_hex;
            if (hs[0] == '0' && (hs[1] == 'x' || hs[1] == 'X')) hs += 2;
            if (strlen(hs) == 16) {
                uint8_t new_aid[8];
                for (int i = 0; i < 8; i++) {
                    char bh[3] = {hs[i*2], hs[i*2+1], 0};
                    new_aid[i] = (uint8_t)strtol(bh, NULL, 16);
                }
                char sfo_path[MAX_PATH_LEN];
                snprintf(sfo_path, sizeof(sfo_path), "%s/sce_sys/param.sfo", g_mount_point);
                int sfo_fd = open(sfo_path, O_RDWR);
                if (sfo_fd >= 0) {
                    pwrite(sfo_fd, new_aid, 8, 0x1B8);
                    close(sfo_fd);
                    sync();
                    printf("[GarlicMgr] encrypt: patched account ID\n");
                }
            }
        }

        unmount_save();

        struct stat est;
        if (stat(tmp, &est) < 0) {
            unlink(tmp);
            http_json(sock, "{\"error\":\"Encrypted image not found\"}"); return;
        }
        char json[128];
        snprintf(json, sizeof(json), "{\"ok\":true,\"size\":%lld}", (long long)est.st_size);
        http_json(sock, json);
        return;
    }

    /* GET /api/encrypt_download?name=<optional> -> serve the encrypted file */
    if (strcmp(method, "GET") == 0 && strncmp(url, "/api/encrypt_download", 21) == 0) {
        const char *tmp = "/data/save_files/_tmp_enc";
        struct stat est;
        if (stat(tmp, &est) < 0) {
            http_json(sock, "{\"error\":\"No encrypted file\"}"); return;
        }
        int fd = open(tmp, O_RDONLY);
        if (fd < 0) {
            http_json(sock, "{\"error\":\"Cannot read file\"}"); return;
        }
        char dlname[512] = "encrypted_save";
        char *np = strstr(url, "name=");
        if (np) {
            strncpy(dlname, np + 5, sizeof(dlname) - 1);
            dlname[sizeof(dlname) - 1] = 0;
            /* URL-decode */
            char *r = dlname, *w = dlname;
            while (*r && *r != '&') {
                if (*r == '%' && r[1] && r[2]) {
                    char hex[3] = {r[1], r[2], 0};
                    *w++ = (char)strtol(hex, NULL, 16);
                    r += 3;
                } else { *w++ = *r++; }
            }
            *w = 0;
        }
        char hdr[1024];
        int hlen = snprintf(hdr, sizeof(hdr),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/octet-stream\r\n"
            "Content-Disposition: attachment; filename=\"%s\"\r\n"
            "Content-Length: %lld\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Connection: close\r\n\r\n", dlname, (long long)est.st_size);
        send(sock, hdr, hlen, 0);
        char *buf = g_iobuf;
        ssize_t nr;
        while ((nr = read(fd, buf, BUF_SIZE)) > 0)
            send(sock, buf, nr, 0);
        close(fd);
        unlink(tmp);
        return;
    }

    /* GET /api/resign_download?name=<optional> -> serve the resigned file */
    if (strcmp(method, "GET") == 0 && strncmp(url, "/api/resign_download", 20) == 0) {
        const char *tmp = "/data/save_files/_tmp_resign";
        struct stat rst;
        if (stat(tmp, &rst) < 0) {
            http_json(sock, "{\"error\":\"No resigned file\"}"); return;
        }
        int fd = open(tmp, O_RDONLY);
        if (fd < 0) {
            http_json(sock, "{\"error\":\"Cannot read file\"}"); return;
        }
        char dlname[512] = "resigned_save";
        char *np = strstr(url, "name=");
        if (np) {
            strncpy(dlname, np + 5, sizeof(dlname) - 1);
            dlname[sizeof(dlname) - 1] = 0;
            char *r = dlname, *w = dlname;
            while (*r && *r != '&') {
                if (*r == '%' && r[1] && r[2]) {
                    char hex[3] = {r[1], r[2], 0};
                    *w++ = (char)strtol(hex, NULL, 16);
                    r += 3;
                } else { *w++ = *r++; }
            }
            *w = 0;
        }
        char hdr[1024];
        int hlen = snprintf(hdr, sizeof(hdr),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/octet-stream\r\n"
            "Content-Disposition: attachment; filename=\"%s\"\r\n"
            "Content-Length: %lld\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Connection: close\r\n\r\n", dlname, (long long)rst.st_size);
        send(sock, hdr, hlen, 0);
        char *buf = g_iobuf;
        ssize_t nr;
        while ((nr = read(fd, buf, BUF_SIZE)) > 0)
            send(sock, buf, nr, 0);
        close(fd);
        unlink(tmp);
        return;
    }

    /* POST /api/upload_file?name=<path> -> write raw file into mounted save */
    if (strcmp(method, "POST") == 0 && strncmp(url, "/api/upload_file", 16) == 0) {
        if (!g_mounted) { http_json(sock, "{\"error\":\"No save mounted\"}"); return; }

        char fname[512] = {0};
        char *np = strstr(url, "name=");
        if (np) {
            strncpy(fname, np + 5, sizeof(fname) - 1);
            /* URL-decode %xx sequences */
            char *r = fname, *w = fname;
            while (*r) {
                if (*r == '%' && r[1] && r[2]) {
                    char hex[3] = {r[1], r[2], 0};
                    *w++ = (char)strtol(hex, NULL, 16);
                    r += 3;
                } else { *w++ = *r++; }
            }
            *w = 0;
        }
        if (!fname[0]) { http_json(sock, "{\"error\":\"Missing name param\"}"); return; }

        size_t clen = 0;
        char *cl = strcasestr(req, "Content-Length:");
        if (cl) clen = strtoul(cl + 15, NULL, 10);
        if (clen > (size_t)2 * 1024 * 1024 * 1024) {
            http_json(sock, "{\"error\":\"File too large\"}"); return;
        }

        char *body_start = strstr(req, "\r\n\r\n");
        if (!body_start) { http_json(sock, "{\"error\":\"Bad request\"}"); return; }
        body_start += 4;
        size_t body_in_buf = n - (body_start - req);

        char filepath[MAX_PATH_LEN];
        snprintf(filepath, sizeof(filepath), "%s/%s", g_mount_point, fname);

        /* Create parent dirs */
        char *slash = filepath + strlen(g_mount_point) + 1;
        while ((slash = strchr(slash, '/')) != NULL) {
            *slash = 0; mkdir(filepath, 0777); *slash = '/'; slash++;
        }

        int fd = open(filepath, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (fd < 0) {
            char json[256];
            snprintf(json, sizeof(json), "{\"error\":\"Cannot create %s\"}", fname);
            http_json(sock, json); return;
        }

        if (body_in_buf > clen) body_in_buf = clen;
        write(fd, body_start, body_in_buf);
        size_t received = body_in_buf;
        while (received < clen) {
            char *buf = g_iobuf;
            size_t want = BUF_SIZE < (clen - received) ? BUF_SIZE : (clen - received);
            ssize_t r = recv_all(sock, buf, want);
            if (r <= 0) break;
            write(fd, buf, r);
            received += r;
        }
        close(fd);
        sync();

        char json[256];
        snprintf(json, sizeof(json), "{\"ok\":true,\"name\":\"%s\",\"size\":%zu}", fname, received);
        http_json(sock, json);
        return;
    }

    /* POST /api/upload -> zip extract into mounted save */
    if (strcmp(method, "POST") == 0 && strcmp(url, "/api/upload") == 0) {
        if (!g_mounted) { http_json(sock, "{\"error\":\"No save mounted\"}"); return; }

        size_t clen = 0;
        char *cl = strcasestr(req, "Content-Length:");
        if (cl) clen = strtoul(cl + 15, NULL, 10);
        if (clen == 0 || clen > (size_t)2 * 1024 * 1024 * 1024) {
            http_json(sock, "{\"error\":\"Invalid content length\"}");
            return;
        }

        char *body_start = strstr(req, "\r\n\r\n");
        if (!body_start) { http_json(sock, "{\"error\":\"Bad request\"}"); return; }
        body_start += 4;
        size_t body_in_buf = n - (body_start - req);

        uint8_t *body = malloc(clen);
        if (!body) { http_json(sock, "{\"error\":\"Out of memory\"}"); return; }

        if (body_in_buf > clen) body_in_buf = clen;
        memcpy(body, body_start, body_in_buf);
        size_t received = body_in_buf;

        while (received < clen) {
            ssize_t r = recv_all(sock, body + received, clen - received);
            if (r <= 0) break;
            received += r;
        }

        int files = extract_zip(g_mount_point, body, received);
        free(body);
        sync();

        char json[128];
        snprintf(json, sizeof(json), "{\"files\":%d}", files);
        http_json(sock, json);
        return;
    }

    /* GET /api/create_pfs?size=<bytes> -> create fresh PFS image, mount it */
    if (strcmp(method, "GET") == 0 && strncmp(url, "/api/create_pfs", 15) == 0) {
        if (g_mounted) unmount_save();
        kernel_set_ucred_authid(getpid(), 0x4800000000000010ULL);

        /* Parse optional size (default 256MB) */
        uint64_t img_size = 256 * 1024 * 1024;
        char *sp = strstr(url, "size=");
        if (sp) {
            uint64_t req_size = strtoull(sp + 5, NULL, 10);
            if (req_size > 0) {
                /* Add 25% overhead + 4MB, min 32MB */
                img_size = req_size + (req_size / 4) + (4 * 1024 * 1024);
                if (img_size < 32 * 1024 * 1024)
                    img_size = 32 * 1024 * 1024;
            }
        }
        img_size = ((img_size + 32767) / 32768) * 32768;

        mkdir("/data/save_files", 0777);
        const char *tmp = "/data/save_files/_tmp_enc";
        unlink(tmp);

        int imgfd = open(tmp, O_CREAT | O_TRUNC | O_RDWR, 0777);
        if (imgfd < 0) {
            http_json(sock, "{\"error\":\"Cannot create temp file\"}"); return;
        }
        int ret = sceFsUfsAllocateSaveData(imgfd, img_size, 0, 0);
        if (ret < 0) {
            printf("[GarlicMgr] UfsAllocate failed (0x%x), using ftruncate\n", ret);
            if (ftruncate(imgfd, img_size) < 0) {
                close(imgfd); unlink(tmp);
                http_json(sock, "{\"error\":\"Cannot allocate image\"}"); return;
            }
        }
        close(imgfd);
        printf("[GarlicMgr] create_pfs: image %llu bytes\n", (unsigned long long)img_size);

        CreateOpt copt;
        memset(&copt, 0, sizeof(copt));
        sceFsInitCreatePfsSaveDataOpt(&copt);
        copt.flags[1] = 0x02;
        uint8_t ckey[0x20] = {0};
        if (!g_pprCreate) {
            unlink(tmp);
            http_json(sock, "{\"error\":\"PprCreate not available\"}"); return;
        }
        ret = g_pprCreate(&copt, tmp, 0, img_size, ckey);
        if (ret < 0) {
            unlink(tmp);
            char json[128];
            snprintf(json, sizeof(json), "{\"error\":\"Format PFS failed: 0x%x\"}", ret);
            http_json(sock, json); return;
        }
        printf("[GarlicMgr] create_pfs: formatted OK\n");

        snprintf(g_mount_point, sizeof(g_mount_point), "/data/mount_sd");
        mkdir(g_mount_point, 0777);
        MountOpt emopt;
        memset(&emopt, 0, sizeof(emopt));
        sceFsInitMountSaveDataOpt(&emopt);
        emopt.budgetid = "system";
        signal(SIGPIPE, SIG_DFL);
        ret = sceFsMountSaveData(&emopt, tmp, g_mount_point, ckey);
        signal(SIGPIPE, SIG_IGN);
        if (ret < 0) {
            unlink(tmp);
            char json[128];
            snprintf(json, sizeof(json), "{\"error\":\"Mount failed: 0x%x\"}", ret);
            http_json(sock, json); return;
        }
        snprintf(g_mounted_path, sizeof(g_mounted_path), "%s", tmp);
        g_local_copy[0] = 0;
        g_mounted = 1;
        printf("[GarlicMgr] create_pfs: mounted at %s\n", g_mount_point);

        http_json(sock, "{\"ok\":true}");
        return;
    }

    /* GET /api/mount_copy?idx=N -> copy save, mount, clear contents */
    if (strcmp(method, "GET") == 0 && strncmp(url, "/api/mount_copy", 15) == 0) {
        if (g_mounted) unmount_save();

        int idx = -1;
        char *p = strstr(url, "idx=");
        if (p) idx = atoi(p + 4);
        if (idx < 0 || idx >= g_save_count) {
            http_json(sock, "{\"error\":\"Invalid index\"}"); return;
        }

        save_entry_t *s = &g_saves[idx];
        kernel_set_ucred_authid(getpid(), 0x4800000000000010ULL);

        /* Copy save to temp location */
        const char *tmp = "/data/save_files/_tmp_newenc";
        mkdir("/data/save_files", 0777);
        if (copy_file(s->path, tmp) < 0) {
            http_json(sock, "{\"error\":\"Copy failed\"}"); return;
        }
        chmod(tmp, 0755);

        /* Mount the copy */
        int ret = mount_by_path(tmp);
        if (ret < 0) {
            unlink(tmp);
            char json[128];
            snprintf(json, sizeof(json), "{\"error\":\"Mount failed: %d\"}", ret);
            http_json(sock, json); return;
        }

        /* Delete all contents */
        delete_recursive(g_mount_point);
        sync();
        printf("[GarlicMgr] mount_copy: cleared contents\n");

        /* Return empty file list */
        char json[1024];
        snprintf(json, sizeof(json), "{\"files\":[]}");
        http_json(sock, json);
        return;
    }

    /* GET /api/download_new?aid=<optional hex> -> patch aid, unmount, stream encrypted */
    if (strcmp(method, "GET") == 0 && strncmp(url, "/api/download_new", 17) == 0) {
        if (!g_mounted) {
            http_json(sock, "{\"error\":\"No save mounted\"}"); return;
        }

        /* Optional account ID patching */
        char *ap = strstr(url, "aid=");
        if (ap) {
            char aid_hex[64] = {0};
            strncpy(aid_hex, ap + 4, sizeof(aid_hex) - 1);
            char *rp = aid_hex, *wp = aid_hex;
            while (*rp && *rp != '&') {
                if (*rp == '%' && rp[1] && rp[2]) {
                    char hex[3] = {rp[1], rp[2], 0};
                    *wp++ = (char)strtol(hex, NULL, 16);
                    rp += 3;
                } else { *wp++ = *rp++; }
            }
            *wp = 0;
            char *hs = aid_hex;
            if (hs[0] == '0' && (hs[1] == 'x' || hs[1] == 'X')) hs += 2;
            if (strlen(hs) == 16) {
                uint8_t new_aid[8];
                for (int i = 0; i < 8; i++) {
                    char bh[3] = {hs[i*2], hs[i*2+1], 0};
                    new_aid[i] = (uint8_t)strtol(bh, NULL, 16);
                }
                char sfo_path[MAX_PATH_LEN];
                snprintf(sfo_path, sizeof(sfo_path), "%s/sce_sys/param.sfo", g_mount_point);
                int sfo_fd = open(sfo_path, O_RDWR);
                if (sfo_fd >= 0) {
                    pwrite(sfo_fd, new_aid, 8, 0x1B8);
                    close(sfo_fd);
                    sync();
                    printf("[GarlicMgr] download_new: patched account ID\n");
                }
            }
        }

        /* Save path before unmount clears it */
        char tmp_path[MAX_PATH_LEN];
        snprintf(tmp_path, sizeof(tmp_path), "%s", g_mounted_path);
        unmount_save();

        struct stat st;
        if (stat(tmp_path, &st) < 0) {
            unlink(tmp_path);
            http_json(sock, "{\"error\":\"File not found\"}"); return;
        }
        int fd = open(tmp_path, O_RDONLY);
        if (fd < 0) {
            unlink(tmp_path);
            http_json(sock, "{\"error\":\"Cannot read file\"}"); return;
        }
        char dlname[512] = "new_save";
        char *np = strstr(url, "name=");
        if (np) {
            strncpy(dlname, np + 5, sizeof(dlname) - 1);
            dlname[sizeof(dlname) - 1] = 0;
            char *r = dlname, *w = dlname;
            while (*r && *r != '&') {
                if (*r == '%' && r[1] && r[2]) {
                    char hex[3] = {r[1], r[2], 0};
                    *w++ = (char)strtol(hex, NULL, 16);
                    r += 3;
                } else { *w++ = *r++; }
            }
            *w = 0;
        }
        char hdr[1024];
        int hlen = snprintf(hdr, sizeof(hdr),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/octet-stream\r\n"
            "Content-Disposition: attachment; filename=\"%s\"\r\n"
            "Content-Length: %lld\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Connection: close\r\n\r\n", dlname, (long long)st.st_size);
        send(sock, hdr, hlen, 0);
        char *buf = g_iobuf;
        ssize_t nr;
        while ((nr = read(fd, buf, BUF_SIZE)) > 0)
            send(sock, buf, nr, 0);
        close(fd);
        unlink(tmp_path);
        return;
    }

    /* POST /api/resign?aid=<hex> -> upload encrypted, change account id, download */
    if (strcmp(method, "POST") == 0 && strncmp(url, "/api/resign", 11) == 0) {
        /* Parse account ID from query string */
        char aid_hex[64] = {0};
        char *ap = strstr(url, "aid=");
        if (ap) {
            strncpy(aid_hex, ap + 4, sizeof(aid_hex) - 1);
            char *rp = aid_hex, *wp = aid_hex;
            while (*rp && *rp != '&') {
                if (*rp == '%' && rp[1] && rp[2]) {
                    char hex[3] = {rp[1], rp[2], 0};
                    *wp++ = (char)strtol(hex, NULL, 16);
                    rp += 3;
                } else { *wp++ = *rp++; }
            }
            *wp = 0;
        }
        /* Strip 0x prefix if present */
        char *hex_str = aid_hex;
        if (hex_str[0] == '0' && (hex_str[1] == 'x' || hex_str[1] == 'X'))
            hex_str += 2;
        if (strlen(hex_str) != 16) {
            http_json(sock, "{\"error\":\"Account ID must be 16 hex chars (e.g. 0x0000000000000000)\"}");
            return;
        }
        uint8_t new_aid[8];
        for (int i = 0; i < 8; i++) {
            char byte_hex[3] = {hex_str[i*2], hex_str[i*2+1], 0};
            new_aid[i] = (uint8_t)strtol(byte_hex, NULL, 16);
        }

        /* Receive body */
        size_t clen = 0;
        char *cl = strcasestr(req, "Content-Length:");
        if (cl) clen = strtoul(cl + 15, NULL, 10);
        if (clen == 0 || clen > (size_t)2 * 1024 * 1024 * 1024) {
            http_json(sock, "{\"error\":\"Invalid size\"}"); return;
        }
        char *body_start = strstr(req, "\r\n\r\n");
        if (!body_start) { http_json(sock, "{\"error\":\"Bad request\"}"); return; }
        body_start += 4;
        size_t body_in_buf = n - (body_start - req);

        mkdir("/data/save_files", 0777);
        const char *tmp = "/data/save_files/_tmp_resign";
        int fd = open(tmp, O_CREAT | O_WRONLY | O_TRUNC, 0755);
        if (fd < 0) { http_json(sock, "{\"error\":\"Cannot create temp file\"}"); return; }
        if (body_in_buf > clen) body_in_buf = clen;
        write(fd, body_start, body_in_buf);
        size_t received = body_in_buf;
        while (received < clen) {
            char *buf = g_iobuf;
            size_t want = BUF_SIZE < (clen - received) ? BUF_SIZE : (clen - received);
            ssize_t r = recv_all(sock, buf, want);
            if (r <= 0) break;
            write(fd, buf, r);
            received += r;
        }
        close(fd);
        printf("[GarlicMgr] resign: received %zu bytes\n", received);

        /* Mount the save */
        int ret = mount_by_path(tmp);
        if (ret < 0) {
            unlink(tmp);
            char json[128];
            snprintf(json, sizeof(json), "{\"error\":\"Mount failed: %d\"}", ret);
            http_json(sock, json); return;
        }

        /* Patch account ID in param.sfo at offset 0x1B8 */
        char sfo_path[MAX_PATH_LEN];
        snprintf(sfo_path, sizeof(sfo_path), "%s/sce_sys/param.sfo", g_mount_point);
        int sfo_fd = open(sfo_path, O_RDWR);
        if (sfo_fd < 0) {
            unmount_save(); unlink(tmp);
            http_json(sock, "{\"error\":\"Cannot open param.sfo\"}"); return;
        }
        if (pwrite(sfo_fd, new_aid, 8, 0x1B8) != 8) {
            close(sfo_fd); unmount_save(); unlink(tmp);
            http_json(sock, "{\"error\":\"Failed to write account ID\"}"); return;
        }
        close(sfo_fd);
        sync();
        printf("[GarlicMgr] resign: patched account ID to %s\n", aid_hex);

        /* Unmount (re-encrypts) */
        unmount_save();

        /* Return JSON, file available via GET /api/resign_download */
        struct stat st;
        if (stat(tmp, &st) < 0) {
            unlink(tmp);
            http_json(sock, "{\"error\":\"Resigned file not found\"}"); return;
        }
        char json[128];
        snprintf(json, sizeof(json), "{\"ok\":true,\"size\":%lld}", (long long)st.st_size);
        http_json(sock, json);
        return;
    }

    /* 404 */
    http_send(sock, "404 Not Found", "application/json", "{\"error\":\"Not found\"}", 20);
}

/* ── Main ───────────────────────────────────────────────────────── */
int main(void) {
    sceUserServiceInitialize(0);
    kernel_set_ucred_authid(getpid(), 0x4800000000000010ULL);
    signal(SIGPIPE, SIG_IGN);
    init_crc();

    /* Try to load sceFsCreatePprPfsSaveDataImage via dlsym */
    void *vsh = dlopen("libSceFsInternalForVsh.sprx", RTLD_LAZY);
    if (vsh) {
        g_pprCreate = (PprCreateFn)dlsym(vsh, "sceFsCreatePprPfsSaveDataImage");
        printf("[GarlicMgr] PprCreate: %s\n", g_pprCreate ? "available" : "not found");
    }

    /* Force unmount any stale mounts from previous runs */
    struct stat st0;
    if (stat("/data/mount_sd", &st0) == 0) {
        UmountOpt u0; memset(&u0, 0, sizeof(u0));
        sceFsInitUmountSaveDataOpt(&u0);
        sceFsUmountSaveData(&u0, "/data/mount_sd", 0, 0);
    }

    printf("=== Garlic SaveMgr for PS5 by earthonion ===\n");
    notify("Garlic SaveMgr: port %d", PORT);

    int srvfd = socket(AF_INET, SOCK_STREAM, 0);
    if (srvfd < 0) { perror("socket"); return 1; }
    setsockopt(srvfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(PORT);

    if (bind(srvfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(srvfd); return 1;
    }
    if (listen(srvfd, 5) < 0) {
        perror("listen"); close(srvfd); return 1;
    }

    printf("Listening on port %d\n", PORT);

    while (1) {
        struct sockaddr_in client;
        socklen_t clen = sizeof(client);
        int conn = accept(srvfd, (struct sockaddr*)&client, &clen);
        if (conn < 0) continue;
        int rcvbuf = 1024 * 1024;
        setsockopt(conn, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
        setsockopt(conn, SOL_SOCKET, SO_SNDBUF, &rcvbuf, sizeof(rcvbuf));
        handle_request(conn);
        close(conn);
    }

    return 0;
}
