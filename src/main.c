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
#include "sqlite3.h"

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
int sceUserServiceGetForegroundUser(int *user_id);

typedef struct { char unused[45]; char message[3075]; } notify_request_t;
int sceKernelSendNotificationRequest(int, notify_request_t*, size_t, int);

/* ── Constants ──────────────────────────────────────────────────── */
#define PORT            8082
#define MOUNT_BASE      "/data/save_mnt"
#define BUF_SIZE        (512 * 1024)
#define MAX_REQ         8192
#define MAX_PATH_LEN    1024

static char g_iobuf[BUF_SIZE];

/* Ring log buffer for remote debug */
#define LOG_BUF_SIZE (32 * 1024)
static char g_logbuf[LOG_BUF_SIZE];
static int g_logpos = 0;
static void logprintf(const char *fmt, ...) {
    char tmp[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    printf("%s", tmp);
    if (n > 0) {
        for (int i = 0; i < n && g_logpos < LOG_BUF_SIZE - 1; i++)
            g_logbuf[g_logpos++] = tmp[i];
    }
}

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
static uint8_t g_sealed_key[96] = {0};
static int g_enc_ps4 = 0;

/* ── Title name lookup from app.db ──────────────────────────────── */
typedef struct {
    char title_id[32];
    char title_name[256];
} title_entry_t;

static title_entry_t *g_titles = NULL;
static int g_title_count = 0;
static int g_title_cap = 0;

static void load_app_db(void) {
    const char *db_path = "/system_data/priv/mms/app.db";
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        printf("[GarlicMgr] Cannot open app.db: %s\n", sqlite3_errmsg(db));
        if (db) sqlite3_close(db);
        return;
    }
    sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT titleId, titleName FROM tbl_contentinfo WHERE titleName IS NOT NULL";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        printf("[GarlicMgr] SQL error: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return;
    }
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *tid = (const char *)sqlite3_column_text(stmt, 0);
        const char *tname = (const char *)sqlite3_column_text(stmt, 1);
        if (!tid || !tname) continue;
        if (g_title_count >= g_title_cap) {
            int newcap = g_title_cap ? g_title_cap * 2 : 64;
            title_entry_t *p = realloc(g_titles, newcap * sizeof(title_entry_t));
            if (!p) break;
            g_titles = p;
            g_title_cap = newcap;
        }
        title_entry_t *t = &g_titles[g_title_count++];
        strncpy(t->title_id, tid, sizeof(t->title_id) - 1);
        strncpy(t->title_name, tname, sizeof(t->title_name) - 1);
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    printf("[GarlicMgr] Loaded %d title names from app.db\n", g_title_count);
}

static const char *lookup_title(const char *title_id) {
    for (int i = 0; i < g_title_count; i++) {
        if (strcmp(g_titles[i].title_id, title_id) == 0)
            return g_titles[i].title_name;
    }
    return NULL;
}

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

    /* Check if this is a PS4 savedata dir (contains sdimg_ files) */
    int is_ps4 = (strstr(title_path, "/savedata/") != NULL &&
                  strstr(title_path, "/savedata_prospero/") == NULL);

    struct dirent *ent;
    while ((ent = readdir(d))) {
        if (ent->d_name[0] == '.') continue;

        /* Skip .bin sealed key companions */
        int len = strlen(ent->d_name);
        if (len > 4 && strcmp(ent->d_name + len - 4, ".bin") == 0) continue;

        /* For PS4 dirs, only pick up sdimg_ files, skip backups */
        if (is_ps4) {
            if (strncmp(ent->d_name, "sdimg_", 6) != 0) continue;
            if (strncmp(ent->d_name, "sdimg_sce_bu_", 13) == 0) continue;
        }

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

    /* /user/home/<userid>/savedata_prospero/<TitleId>/<savefile> (PS5) */
    /* /user/home/<userid>/savedata/<TitleId>/sdimg_* (PS4) */
    DIR *home = opendir("/user/home");
    if (home) {
        struct dirent *ue;
        while ((ue = readdir(home))) {
            if (ue->d_name[0] == '.') continue;
            char prospero[MAX_PATH_LEN];
            snprintf(prospero, sizeof(prospero), "/user/home/%s/savedata_prospero", ue->d_name);
            scan_savedata_prospero(prospero);
            char ps4[MAX_PATH_LEN];
            snprintf(ps4, sizeof(ps4), "/user/home/%s/savedata", ue->d_name);
            scan_savedata_prospero(ps4);
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

    /* Check if PS4 save (sdimg_ prefix) */
    const char *bname = strrchr(s->path, '/');
    bname = bname ? bname + 1 : s->path;
    int is_ps4 = (strncmp(bname, "sdimg_", 6) == 0);

    /* Elevate credentials */
    kernel_set_ucred_authid(getpid(), 0x4800000000000010ULL);
    uint8_t ucaps[16];
    kernel_get_ucred_caps(getpid(), ucaps);
    ucaps[7] |= 0x40;
    kernel_set_ucred_caps(getpid(), ucaps);
    setuid(0);

    /*
     * If save is NOT on /data/, copy there first.
     * Direct mount from savedata_prospero causes EPIPE.
     */
    const char *mount_src = s->path;
    g_local_copy[0] = 0;
    int is_on_data = (strncmp(s->path, "/data/", 6) == 0);

    if (!is_on_data) {
        snprintf(g_local_copy, sizeof(g_local_copy), "/data/save_files/%s", s->save_name);
        logprintf("[GarlicMgr] Copying %s -> %s\n", s->path, g_local_copy);
        mkdir("/data/save_files", 0777);
        if (copy_file(s->path, g_local_copy) < 0) {
            logprintf("[GarlicMgr] Copy failed (errno %d: %s)\n", errno, strerror(errno));
            return -3;
        }
        chmod(g_local_copy, 0755);
        mount_src = g_local_copy;

        /* For PS4 saves, also copy the .bin sealed key */
        if (is_ps4) {
            const char *savename = bname + 6;
            char src_dir[MAX_PATH_LEN], src_bin[MAX_PATH_LEN], dst_bin[MAX_PATH_LEN];
            strncpy(src_dir, s->path, sizeof(src_dir) - 1);
            src_dir[sizeof(src_dir) - 1] = 0;
            char *sl = strrchr(src_dir, '/');
            if (sl) *(sl + 1) = 0;
            snprintf(src_bin, sizeof(src_bin), "%s%s.bin", src_dir, savename);
            snprintf(dst_bin, sizeof(dst_bin), "/data/save_files/%s.bin", savename);
            copy_file(src_bin, dst_bin);
            chmod(dst_bin, 0755);
            logprintf("[GarlicMgr] Copied .bin key %s -> %s\n", src_bin, dst_bin);
        }
    }

    /* Heap-allocate ioctl buffer — ioctl can corrupt stack beyond bounds */
    uint8_t *data = malloc(0x100);
    if (!data) return -10;
    memset(data, 0, 0x100);

    uint8_t decrypted_key[0x20];
    memset(decrypted_key, 0, sizeof(decrypted_key));
    int key_ok = 0;

    if (is_ps4) {
        /* PS4: read sealed key from companion .bin file */
        const char *savename = bname + 6;
        char dir[MAX_PATH_LEN];
        strncpy(dir, mount_src, sizeof(dir) - 1);
        dir[sizeof(dir) - 1] = 0;
        char *slash = strrchr(dir, '/');
        if (slash) *(slash + 1) = 0; else dir[0] = 0;

        char bin_path[MAX_PATH_LEN];
        snprintf(bin_path, sizeof(bin_path), "%s%s.bin", dir, savename);

        int fd = open(bin_path, O_RDONLY);
        if (fd < 0) {
            logprintf("[GarlicMgr] mount: cannot open sealed key %s (errno=%d)\n", bin_path, errno);
            free(data);
            return -4;
        }
        int r = read(fd, data, 0x60);
        close(fd);
        if (r != 0x60) {
            logprintf("[GarlicMgr] mount: short read on .bin (%d)\n", r);
            free(data);
            return -5;
        }
        logprintf("[GarlicMgr] mount: PS4 sealed key from %s (keyset=%d)\n",
               bin_path, (data[9] << 8) | data[8]);

        /* Decrypt PS4 sealed key via pfsmgr */
        int pfsmgr = open("/dev/pfsmgr", O_RDWR);
        if (pfsmgr >= 0) {
            int ret = ioctl(pfsmgr, 0xc0845302, data);
            close(pfsmgr);
            if (ret >= 0) {
                memcpy(decrypted_key, data + 0x60, 0x20);
                key_ok = 1;
                logprintf("[GarlicMgr] mount: PS4 key decrypted OK\n");
            } else {
                logprintf("[GarlicMgr] mount: PS4 key decrypt failed (ret=%d)\n", ret);
            }
        } else {
            logprintf("[GarlicMgr] mount: cannot open /dev/pfsmgr\n");
        }
    } else {
        /* PS5: read key from offset 0x800 in image */
        int fd = open(mount_src, O_RDONLY);
        if (fd < 0) { free(data); return -4; }
        int ret = pread(fd, data, 0x60, 0x800);
        close(fd);
        if (ret != 0x60) { free(data); return -5; }

        int pfsmgr = open("/dev/pfsmgr", 2);
        if (pfsmgr < 0) { free(data); return -6; }
        ret = ioctl(pfsmgr, 0xc0845302, data);
        close(pfsmgr);
        if (ret >= 0) {
            memcpy(decrypted_key, data + 0x60, 0x20);
            key_ok = 1;
        }
    }

    free(data);

    if (!key_ok) {
        logprintf("[GarlicMgr] mount: key decryption failed for %s\n", mount_src);
    }

    snprintf(g_mount_point, sizeof(g_mount_point), "/data/mount_sd");
    mkdir(g_mount_point, 0777);

    MountOpt mopt;
    memset(&mopt, 0, sizeof(mopt));
    sceFsInitMountSaveDataOpt(&mopt);
    mopt.budgetid = "system";

    signal(SIGPIPE, SIG_DFL);
    int ret = sceFsMountSaveData(&mopt, mount_src, g_mount_point, decrypted_key);
    signal(SIGPIPE, SIG_IGN);

    if (ret >= 0) {
        logprintf("[GarlicMgr] Mounted OK (handle=%d, key_ok=%d)\n", ret, key_ok);
        snprintf(g_mounted_path, sizeof(g_mounted_path), "%s", s->path);
        g_mounted = 1;
        return 0;
    }
    logprintf("[GarlicMgr] Mount failed (0x%x, key_ok=%d, errno=%d: %s)\n", ret, key_ok, errno, strerror(errno));
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

    /* Check if this is a PS4 save (sdimg_ prefix) */
    const char *bname = strrchr(path, '/');
    bname = bname ? bname + 1 : path;
    int is_ps4 = (strncmp(bname, "sdimg_", 6) == 0);

    kernel_set_ucred_authid(getpid(), 0x4800000000000010ULL);
    uint8_t caps[16];
    kernel_get_ucred_caps(getpid(), caps);
    caps[7] |= 0x40;
    kernel_set_ucred_caps(getpid(), caps);
    setuid(0);

    /* Heap-allocate ioctl buffer — ioctl can corrupt stack beyond bounds */
    uint8_t *data = malloc(0x100);
    if (!data) return -10;
    memset(data, 0, 0x100);

    uint8_t decrypted_key[0x20];
    memset(decrypted_key, 0, sizeof(decrypted_key));
    int key_ok = 0;

    if (is_ps4) {
        /* PS4: read sealed key from companion .bin file */
        const char *savename = bname + 6;
        char dir[MAX_PATH_LEN];
        strncpy(dir, path, sizeof(dir) - 1);
        dir[sizeof(dir) - 1] = 0;
        char *slash = strrchr(dir, '/');
        if (slash) *(slash + 1) = 0; else dir[0] = 0;

        char bin_path[MAX_PATH_LEN];
        snprintf(bin_path, sizeof(bin_path), "%s%s.bin", dir, savename);

        int fd = open(bin_path, O_RDONLY);
        if (fd < 0) {
            logprintf("[GarlicMgr] mount: cannot open sealed key %s\n", bin_path);
            free(data);
            return -1;
        }
        int r = read(fd, data, 0x60);
        close(fd);
        if (r != 0x60) {
            logprintf("[GarlicMgr] mount: short read on .bin (%d)\n", r);
            free(data);
            return -2;
        }
        logprintf("[GarlicMgr] mount: PS4 sealed key from %s (keyset=%d)\n",
               bin_path, (data[9] << 8) | data[8]);

        /* Decrypt PS4 sealed key via pfsmgr */
        int pfsmgr = open("/dev/pfsmgr", O_RDWR);
        if (pfsmgr >= 0) {
            int ret = ioctl(pfsmgr, 0xc0845302, data);
            close(pfsmgr);
            if (ret >= 0) {
                memcpy(decrypted_key, data + 0x60, 0x20);
                key_ok = 1;
                logprintf("[GarlicMgr] mount: PS4 key decrypted OK\n");
            } else {
                logprintf("[GarlicMgr] mount: PS4 key decrypt failed (ret=%d)\n", ret);
            }
        } else {
            logprintf("[GarlicMgr] mount: cannot open /dev/pfsmgr\n");
        }
    } else {
        /* PS5: read key from offset 0x800 in image */
        int fd = open(path, O_RDONLY);
        if (fd < 0) { free(data); return -1; }
        int ret = pread(fd, data, 0x60, 0x800);
        close(fd);
        if (ret != 0x60) { free(data); return -2; }

        int pfsmgr = open("/dev/pfsmgr", 2);
        if (pfsmgr < 0) { free(data); return -3; }
        ret = ioctl(pfsmgr, 0xc0845302, data);
        close(pfsmgr);
        if (ret >= 0) {
            memcpy(decrypted_key, data + 0x60, 0x20);
            key_ok = 1;
        }
    }

    free(data);

    if (!key_ok) {
        logprintf("[GarlicMgr] mount: key decryption failed for %s\n", path);
        /* Try mounting with zeroed key anyway */
    }

    snprintf(g_mount_point, sizeof(g_mount_point), "/data/mount_sd");
    mkdir(g_mount_point, 0777);

    MountOpt mopt;
    memset(&mopt, 0, sizeof(mopt));
    sceFsInitMountSaveDataOpt(&mopt);
    mopt.budgetid = "system";

    signal(SIGPIPE, SIG_DFL);
    int ret = sceFsMountSaveData(&mopt, path, g_mount_point, decrypted_key);
    signal(SIGPIPE, SIG_IGN);

    if (ret >= 0) {
        logprintf("[GarlicMgr] mount: mounted %s (handle=%d, key_ok=%d)\n", path, ret, key_ok);
        snprintf(g_mounted_path, sizeof(g_mounted_path), "%s", path);
        g_local_copy[0] = 0;
        g_mounted = 1;
        return 0;
    }
    logprintf("[GarlicMgr] mount: failed 0x%x (key_ok=%d)\n", ret, key_ok);
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

/* ── Zip streaming for specific files by path ──────────────────── */
typedef struct { const char *path; const char *name; } zip_file_t;

static void zip_send_files(int sock, const zip_file_t *files, int nfiles) {
    zip_entry_t *entries = malloc(nfiles * sizeof(zip_entry_t));
    if (!entries) return;

    uint32_t offset = 0;
    for (int i = 0; i < nfiles; i++) {
        zip_entry_t *e = &entries[i];
        snprintf(e->name, sizeof(e->name), "%s", files[i].name);

        struct stat st;
        if (stat(files[i].path, &st) < 0) { e->size = 0; e->crc = 0; e->offset = offset; continue; }
        e->size = (uint32_t)st.st_size;
        e->offset = offset;

        int fd = open(files[i].path, O_RDONLY);
        if (fd < 0) { e->crc = 0; continue; }

        /* Stream: compute CRC while sending */
        uint16_t nlen = strlen(e->name);
        /* Send local header with CRC=0, will use data descriptor */
        uint8_t lh[30]; memset(lh, 0, 30);
        lh[0]=0x50; lh[1]=0x4b; lh[2]=0x03; lh[3]=0x04;
        lh[4]=20;
        lh[6]=0x08; /* flag: data descriptor follows */
        memcpy(lh+18, &e->size, 4);
        memcpy(lh+22, &e->size, 4);
        memcpy(lh+26, &nlen, 2);
        send(sock, lh, 30, 0);
        send(sock, e->name, nlen, 0);

        uint32_t crc = 0xFFFFFFFF;
        char *buf = g_iobuf;
        ssize_t nr;
        while ((nr = read(fd, buf, BUF_SIZE)) > 0) {
            for (ssize_t j = 0; j < nr; j++) {
                crc ^= (uint8_t)buf[j];
                for (int k = 0; k < 8; k++)
                    crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
            }
            send(sock, buf, nr, 0);
        }
        close(fd);
        crc ^= 0xFFFFFFFF;
        e->crc = crc;

        /* Data descriptor */
        uint8_t dd[16];
        dd[0]=0x50; dd[1]=0x4b; dd[2]=0x07; dd[3]=0x08;
        memcpy(dd+4, &e->crc, 4);
        memcpy(dd+8, &e->size, 4);
        memcpy(dd+12, &e->size, 4);
        send(sock, dd, 16, 0);

        offset += 30 + nlen + e->size + 16;
    }

    uint32_t cd_offset = offset;
    for (int i = 0; i < nfiles; i++) {
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
    uint16_t cnt16 = (uint16_t)nfiles;
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
            if (i > 0) need++;
            const char *tname = lookup_title(g_saves[i].title_id);
            need += snprintf(NULL, 0,
                "{\"title_id\":\"%s\",\"save_name\":\"%s\",\"path\":\"%s\",\"dir\":\"%s\",\"title_name\":\"%s\"}",
                g_saves[i].title_id, g_saves[i].save_name, g_saves[i].path, g_saves[i].dir_name,
                tname ? tname : "");
        }
        need += snprintf(NULL, 0, "]}");
        need += 512; /* extra for JSON escaping */
        char *json = malloc(need + 1);
        if (!json) { http_json(sock, "{\"error\":\"Out of memory\"}"); return; }
        int pos = snprintf(json, need + 1, "{\"saves\":[");
        for (int i = 0; i < g_save_count; i++) {
            if (i > 0) json[pos++] = ',';
            const char *tname = lookup_title(g_saves[i].title_id);
            const char *stype = (strncmp(g_saves[i].save_name, "sdimg_", 6) == 0 &&
                                  strstr(g_saves[i].path, "/savedata/") != NULL &&
                                  strstr(g_saves[i].path, "/savedata_prospero/") == NULL) ? "ps4" : "ps5";
            pos += snprintf(json + pos, need + 1 - pos,
                "{\"title_id\":\"%s\",\"save_name\":\"%s\",\"path\":\"%s\",\"dir\":\"%s\",\"title_name\":\"%s\",\"type\":\"%s\"}",
                g_saves[i].title_id, g_saves[i].save_name, g_saves[i].path, g_saves[i].dir_name,
                tname ? tname : "", stype);
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

        /* Detect PS4 save for SFO offset differences */
        const char *mn = strrchr(g_saves[idx].save_name, '/');
        mn = mn ? mn + 1 : g_saves[idx].save_name;
        int sfo_ps4 = (strncmp(mn, "sdimg_", 6) == 0);

        /* Read param.sfo:
         * PS5: account_id 8B @ 0x1B8, save_title @ 0x5DC, title_id 9B @ 0xB20
         * PS4: account_id 8B @ 0x15C
         */
        char acct_id[20] = {0};
        char save_title[64] = {0};
        char sfo_title_id[16] = {0};
        char sfo_path[MAX_PATH_LEN];
        snprintf(sfo_path, sizeof(sfo_path), "%s/sce_sys/param.sfo", g_mount_point);
        int sfo_fd = open(sfo_path, O_RDONLY);
        if (sfo_fd >= 0) {
            uint8_t aid[8];
            int aid_off = sfo_ps4 ? 0x15C : 0x1B8;
            if (pread(sfo_fd, aid, 8, aid_off) == 8)
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
            if (!sfo_ps4 && pread(sfo_fd, sfo_title_id, 9, 0xB20) > 0)
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

    /* GET /api/log */
    if (strcmp(method, "GET") == 0 && strcmp(url, "/api/log") == 0) {
        g_logbuf[g_logpos] = 0;
        http_send(sock, "200 OK", "text/plain", g_logbuf, g_logpos);
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

    /* POST /api/upload_key -> upload PS4 .bin sealed key for decrypt */
    if (strcmp(method, "POST") == 0 && strcmp(url, "/api/upload_key") == 0) {
        size_t clen = 0;
        char *cl = strcasestr(req, "Content-Length:");
        if (cl) clen = strtoul(cl + 15, NULL, 10);
        if (clen == 0 || clen > 4096) {
            http_json(sock, "{\"error\":\"Invalid key size\"}"); return;
        }
        char *body_start = strstr(req, "\r\n\r\n");
        if (!body_start) { http_json(sock, "{\"error\":\"Bad request\"}"); return; }
        body_start += 4;
        size_t body_in_buf = n - (body_start - req);
        if (body_in_buf > clen) body_in_buf = clen;

        mkdir("/data/save_files", 0777);
        int fd = open("/data/save_files/_tmp_key.bin", O_CREAT | O_WRONLY | O_TRUNC, 0755);
        if (fd < 0) { http_json(sock, "{\"error\":\"Cannot create key file\"}"); return; }
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
        printf("[GarlicMgr] upload_key: received %zu bytes\n", received);
        http_json(sock, "{\"ok\":true}");
        return;
    }

    /* POST /api/decrypt_upload -> upload encrypted save, get decrypted .zip */
    if (strcmp(method, "POST") == 0 && strncmp(url, "/api/decrypt_upload", 19) == 0) {
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
        int is_ps4_dec = (strstr(url, "ps4=1") != NULL);
        const char *tmp = is_ps4_dec ? "/data/save_files/sdimg__tmp_dec" : "/data/save_files/_tmp_dec";
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
        printf("[GarlicMgr] decrypt_upload: received %zu bytes (ps4=%d)\n", received, is_ps4_dec);

        /* For PS4, rename uploaded key to match the expected .bin path */
        if (is_ps4_dec)
            rename("/data/save_files/_tmp_key.bin", "/data/save_files/_tmp_dec.bin");

        int ret = mount_by_path(tmp);
        if (ret < 0) {
            unlink(tmp);
            char json[128];
            snprintf(json, sizeof(json), "{\"error\":\"Mount failed: %d\"}", ret);
            http_json(sock, json); return;
        }

        /* Mount succeeded — return JSON with download URL instead of streaming zip
         * on the same connection (avoids browser XHR issues with large blob responses) */
        http_json(sock, "{\"ok\":true,\"download\":\"/api/download\"}");
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

    /* GET /api/resign_download?name=<optional>&ps4=1 -> serve the resigned file */
    if (strcmp(method, "GET") == 0 && strncmp(url, "/api/resign_download", 20) == 0) {
        int is_ps4 = (strstr(url, "ps4=1") != NULL);
        const char *tmp = is_ps4 ? "/data/save_files/sdimg__tmp_resign" : "/data/save_files/_tmp_resign";
        struct stat rst;
        if (stat(tmp, &rst) < 0) {
            http_json(sock, "{\"error\":\"No resigned file\"}"); return;
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

        if (is_ps4) {
            /* PS4: zip both sdimg_ image and .bin key */
            const char *bin_tmp = "/data/save_files/_tmp_resign.bin";
            char img_name[512], key_name[512], zip_name[512];
            /* Strip sdimg_ prefix from dlname if present for key naming */
            const char *base = dlname;
            if (strncmp(base, "sdimg_", 6) == 0) base += 6;
            snprintf(img_name, sizeof(img_name), "sdimg_%s", base);
            snprintf(key_name, sizeof(key_name), "%s.bin", base);
            snprintf(zip_name, sizeof(zip_name), "%s.zip", base);

            zip_file_t zfiles[2] = {
                { tmp,     img_name },
                { bin_tmp, key_name }
            };
            char hdr[1024];
            int hlen = snprintf(hdr, sizeof(hdr),
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/zip\r\n"
                "Content-Disposition: attachment; filename=\"%s\"\r\n"
                "Access-Control-Allow-Origin: *\r\n"
                "Connection: close\r\n\r\n", zip_name);
            send(sock, hdr, hlen, 0);
            zip_send_files(sock, zfiles, 2);
            unlink(tmp);
            unlink(bin_tmp);
        } else {
            int fd = open(tmp, O_RDONLY);
            if (fd < 0) {
                http_json(sock, "{\"error\":\"Cannot read file\"}"); return;
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
        }
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

    /* GET /api/create_pfs?size=<bytes>&ps4=1 -> create fresh PFS image, mount it */
    if (strcmp(method, "GET") == 0 && strncmp(url, "/api/create_pfs", 15) == 0) {
        if (g_mounted) unmount_save();
        kernel_set_ucred_authid(getpid(), 0x4800000000000010ULL);

        int is_ps4 = (strstr(url, "ps4=1") != NULL);
        g_enc_ps4 = is_ps4;

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

        uint8_t ckey[0x20] = {0};

        if (is_ps4) {
            /* PS4: generate sealed key, decrypt it, use non-Ppr create */
            uint8_t *kbuf = malloc(0x100);
            if (!kbuf) { http_json(sock, "{\"error\":\"Out of memory\"}"); return; }
            memset(kbuf, 0, 0x100);

            /* Try sbl_srv first, then pfsmgr for sealed key generation */
            int gen_ok = 0;
            int kfd = open("/dev/sbl_srv", O_RDWR);
            if (kfd >= 0) {
                if (ioctl(kfd, 0x40845303, kbuf) >= 0) gen_ok = 1;
                close(kfd);
            }
            if (!gen_ok) {
                memset(kbuf, 0, 0x100);
                kfd = open("/dev/pfsmgr", O_RDWR);
                if (kfd >= 0) {
                    if (ioctl(kfd, 0x40845303, kbuf) >= 0) gen_ok = 1;
                    close(kfd);
                }
            }
            if (!gen_ok) {
                free(kbuf);
                http_json(sock, "{\"error\":\"Cannot generate sealed key\"}"); return;
            }
            memcpy(g_sealed_key, kbuf, 96);
            printf("[GarlicMgr] create_pfs: PS4 sealed key generated (keyset=%d)\n",
                   (kbuf[9] << 8) | kbuf[8]);

            /* Decrypt sealed key via pfsmgr */
            memset(kbuf, 0, 0x100);
            memcpy(kbuf, g_sealed_key, 96);
            int pfsmgr = open("/dev/pfsmgr", O_RDWR);
            if (pfsmgr < 0) {
                free(kbuf);
                http_json(sock, "{\"error\":\"Cannot open pfsmgr\"}"); return;
            }
            int ret = ioctl(pfsmgr, 0xc0845302, kbuf);
            close(pfsmgr);
            if (ret < 0) {
                free(kbuf);
                http_json(sock, "{\"error\":\"Cannot decrypt sealed key\"}"); return;
            }
            memcpy(ckey, kbuf + 0x60, 0x20);
            free(kbuf);
            printf("[GarlicMgr] create_pfs: PS4 sealed key decrypted OK\n");
        }

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

        if (is_ps4) {
            /* PS4: use non-Ppr create with decrypted key */
            ret = sceFsCreatePfsSaveDataImage(&copt, tmp, 0, img_size, ckey);
        } else {
            /* PS5: use PprCreate with zeroed key + compression flag */
            copt.flags[1] = 0x02;
            if (!g_pprCreate) {
                unlink(tmp);
                http_json(sock, "{\"error\":\"PprCreate not available\"}"); return;
            }
            ret = g_pprCreate(&copt, tmp, 0, img_size, ckey);
        }
        if (ret < 0) {
            unlink(tmp);
            char json[128];
            snprintf(json, sizeof(json), "{\"error\":\"Format PFS failed: 0x%x\"}", ret);
            http_json(sock, json); return;
        }
        printf("[GarlicMgr] create_pfs: formatted OK (%s)\n", is_ps4 ? "PS4" : "PS5");

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
                    /* PS4: AID at 0x15C, PS5: AID at 0x1B8 */
                    pwrite(sfo_fd, new_aid, 8, g_enc_ps4 ? 0x15C : 0x1B8);
                    int local_uid = 0;
                    if (!g_enc_ps4 && sceUserServiceGetForegroundUser(&local_uid) == 0) {
                        uint32_t uid = (uint32_t)local_uid;
                        pwrite(sfo_fd, &uid, 4, 0x660);
                        printf("[GarlicMgr] download_new: patched user_id to 0x%x\n", uid);
                    }
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

        /* For PS4: write sealed key .bin companion file */
        if (g_enc_ps4) {
            const char *bin_tmp = "/data/save_files/_tmp_enc.bin";
            int bfd = open(bin_tmp, O_CREAT | O_WRONLY | O_TRUNC, 0644);
            if (bfd >= 0) {
                write(bfd, g_sealed_key, 96);
                close(bfd);
                printf("[GarlicMgr] download_new: wrote .bin sealed key\n");
            }
        }

        struct stat st;
        if (stat(tmp_path, &st) < 0) {
            unlink(tmp_path);
            http_json(sock, "{\"error\":\"File not found\"}"); return;
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

        if (g_enc_ps4) {
            /* PS4: zip both sdimg_ image and .bin key together */
            const char *bin_tmp = "/data/save_files/_tmp_enc.bin";
            char img_name[512], key_name[512], zip_name[512];
            snprintf(img_name, sizeof(img_name), "sdimg_%s", dlname);
            snprintf(key_name, sizeof(key_name), "%s.bin", dlname);
            snprintf(zip_name, sizeof(zip_name), "%s_ps4.zip", dlname);

            zip_file_t zfiles[2] = {
                { tmp_path, img_name },
                { bin_tmp,  key_name }
            };
            char hdr[1024];
            int hlen = snprintf(hdr, sizeof(hdr),
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/zip\r\n"
                "Content-Disposition: attachment; filename=\"%s\"\r\n"
                "Access-Control-Allow-Origin: *\r\n"
                "Connection: close\r\n\r\n", zip_name);
            send(sock, hdr, hlen, 0);
            zip_send_files(sock, zfiles, 2);
            unlink(tmp_path);
            unlink(bin_tmp);
        } else {
            /* PS5: stream raw image */
            int fd = open(tmp_path, O_RDONLY);
            if (fd < 0) {
                unlink(tmp_path);
                http_json(sock, "{\"error\":\"Cannot read file\"}"); return;
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
        }
        return;
    }

    /* POST /api/resign?aid=<hex>&ps4=1 -> upload encrypted, change account id, download */
    if (strcmp(method, "POST") == 0 && strncmp(url, "/api/resign", 11) == 0) {
        int is_ps4 = (strstr(url, "ps4=1") != NULL);

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
        /* PS4: name as sdimg_ so mount_by_path detects it */
        if (is_ps4) tmp = "/data/save_files/sdimg__tmp_resign";
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
        printf("[GarlicMgr] resign: received %zu bytes (ps4=%d)\n", received, is_ps4);

        /* For PS4: rename uploaded .bin key to match image name */
        if (is_ps4) {
            rename("/data/save_files/_tmp_key.bin", "/data/save_files/_tmp_resign.bin");
        }

        /* Mount the save */
        int ret = mount_by_path(tmp);
        if (ret < 0) {
            unlink(tmp);
            if (is_ps4) unlink("/data/save_files/_tmp_resign.bin");
            char json[128];
            snprintf(json, sizeof(json), "{\"error\":\"Mount failed: %d\"}", ret);
            http_json(sock, json); return;
        }

        /* Patch account ID in param.sfo */
        char sfo_path[MAX_PATH_LEN];
        snprintf(sfo_path, sizeof(sfo_path), "%s/sce_sys/param.sfo", g_mount_point);
        int sfo_fd = open(sfo_path, O_RDWR);
        if (sfo_fd < 0) {
            unmount_save(); unlink(tmp);
            if (is_ps4) unlink("/data/save_files/_tmp_resign.bin");
            http_json(sock, "{\"error\":\"Cannot open param.sfo\"}"); return;
        }
        /* PS4: AID at 0x15C, PS5: AID at 0x1B8 */
        off_t aid_offset = is_ps4 ? 0x15C : 0x1B8;
        if (pwrite(sfo_fd, new_aid, 8, aid_offset) != 8) {
            close(sfo_fd); unmount_save(); unlink(tmp);
            if (is_ps4) unlink("/data/save_files/_tmp_resign.bin");
            http_json(sock, "{\"error\":\"Failed to write account ID\"}"); return;
        }

        if (!is_ps4) {
            /* PS5 only: patch user_id (uint32_t) at offset 0x660 */
            char *up = strstr(url, "uid=");
            uint32_t uid = 0;
            int have_uid = 0;
            if (up) {
                char uid_hex[16] = {0};
                strncpy(uid_hex, up + 4, sizeof(uid_hex) - 1);
                char *rp2 = uid_hex, *wp2 = uid_hex;
                while (*rp2 && *rp2 != '&') {
                    if (*rp2 == '%' && rp2[1] && rp2[2]) {
                        char hx[3] = {rp2[1], rp2[2], 0};
                        *wp2++ = (char)strtol(hx, NULL, 16);
                        rp2 += 3;
                    } else { *wp2++ = *rp2++; }
                }
                *wp2 = 0;
                char *us = uid_hex;
                if (us[0] == '0' && (us[1] == 'x' || us[1] == 'X')) us += 2;
                uid = (uint32_t)strtoul(us, NULL, 16);
                have_uid = 1;
            }
            if (!have_uid) {
                int local_uid = 0;
                if (sceUserServiceGetForegroundUser(&local_uid) == 0) {
                    uid = (uint32_t)local_uid;
                    have_uid = 1;
                }
            }
            if (have_uid) {
                pwrite(sfo_fd, &uid, 4, 0x660);
                printf("[GarlicMgr] resign: patched user_id to 0x%x\n", uid);
            }
        }
        close(sfo_fd);
        sync();
        printf("[GarlicMgr] resign: patched account ID to %s (%s)\n", aid_hex, is_ps4 ? "PS4" : "PS5");

        /* Unmount (re-encrypts) */
        unmount_save();

        /* Return JSON, file available via GET /api/resign_download */
        struct stat st;
        if (stat(tmp, &st) < 0) {
            unlink(tmp);
            if (is_ps4) unlink("/data/save_files/_tmp_resign.bin");
            http_json(sock, "{\"error\":\"Resigned file not found\"}"); return;
        }
        char json[128];
        snprintf(json, sizeof(json), "{\"ok\":true,\"size\":%lld,\"ps4\":%s}",
                 (long long)st.st_size, is_ps4 ? "true" : "false");
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
    load_app_db();

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
