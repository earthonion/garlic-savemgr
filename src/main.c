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
 #include <ctype.h>
 #include <dirent.h>
 #include <signal.h>
 #include <time.h>
 #include <sys/stat.h>
 #include <sys/mount.h>
 #include <stdatomic.h>
 #include <sys/socket.h>
 #include <sys/ioctl.h>
 #include <sys/sysctl.h>
 #include <netinet/in.h>
 #include <netinet/tcp.h>
 #include <arpa/inet.h>
 #include <netdb.h>
 #include <sys/select.h>
 #include <dlfcn.h>
 #include <pthread.h>

 #include <ps5/kernel.h>
 #include "sqlite3.h"
 #include "CMP/ps5param.h"
 #include "CMP/pfs_rebuild.h"
 #include "CMP/lifecycle.h"
 #include "CMP/accounts.h"
 #include "CMP/native_key.h"
 #include "sfo_account.h"
 #include "CMP/chives.h"
 #include "CMP/metadata_layout.h"
 #include "CMP/key_capture.h"
 #include "CMP/save_usage.h"
 #include "CMP/upload_io.h"
 #include "CMP/transfer_control.h"
 #include "CMP/pfs_diagnostics.h"
 #include "CMP/instance_control.h"
#ifndef GARLIC_VERSION
#define GARLIC_VERSION "unversioned"
#endif

 /* ── SDK imports ────────────────────────────────────────────────── */

 int sceFsInitMountSaveDataOpt(MountOpt *opt);
 int sceFsMountSaveData(MountOpt *opt, const char *path, const char *mount, uint8_t *key);
 int sceFsInitUmountSaveDataOpt(UmountOpt *opt);
 int sceFsUmountSaveData(UmountOpt *opt, const char *mount, int handle, int ignore);

 int sceFsInitCreatePfsSaveDataOpt(CreateOpt *opt);
 int sceFsCreatePfsSaveDataImage(CreateOpt *opt, const char *path, int x, uint64_t size, uint8_t *key);
 /* sceFsCreatePprPfsSaveDataImage - loaded via dlsym at runtime */
 /* PPR creation generates/seals its own key; there is no key output argument. */
 PprCreateFn g_pprCreate = NULL;
 int sceFsUfsAllocateSaveData(int fd, uint64_t size, int flags, void *operation_control);

 int sceUserServiceInitialize(void*);
 int sceUserServiceGetForegroundUser(int *user_id);
 int sceSystemServiceGetAppIdOfRunningBigApp(void);
 void sceLncUtilGetAppTitleId(unsigned int app_id, char *title_id);

 /* Registry manager — for reading account ID */
 int sceRegMgrGetBin(int, void*, size_t);
 int sceRegMgrGetStr(int, char*, size_t);

 typedef struct { char unused[45]; char message[3075]; } notify_request_t;
 int sceKernelSendNotificationRequest(int, notify_request_t*, size_t, int);

 /* OpenPsId — 16-byte device-unique identifier used in PARAMS HMAC */
 typedef struct { uint8_t id[16]; } SceKernelOpenPsId;
 int sceKernelGetOpenPsId(SceKernelOpenPsId *id);
 int sceKernelGetOpenPsIdForSystem(SceKernelOpenPsId *id);

 int sceNetInit(void);
 int sceNetPoolCreate(const char *name, int size, int flags);

 /* ── Constants ──────────────────────────────────────────────────── */
 #define PORT            8082
 #define INSTANCE_HANDOVER_WAIT_MS (120u * 1000u)
 #define MOUNT_BASE      "/data/save_mnt"
 #define BUF_SIZE        (512 * 1024)
 #define MAX_REQ         8192
 #define MAX_PATH_LEN    1024
 #define CLOUD_CONFIG_PATH "/data/garlic/cloud.json"
 #define CLOUD_QUEUE_DIR "/data/garlic/cloud_queue"
 #define BACKUP_TMP_DIR "/data/garlic/tmp"
 #define BACKUP_DEFAULT_LOCAL_DIR "/data/garlic/backups"
 #define BACKUP_DEFAULT_USB_DIR "/mnt/usb0/garlic-backups"
 #define CLOUD_MAX_TITLES 64

 /* Mutex for state-mutating operations (mount/unmount/scan) */
 pthread_mutex_t g_mtx = PTHREAD_MUTEX_INITIALIZER;
 garlic_transfer_control_t g_transfer = GARLIC_TRANSFER_INITIALIZER;
 /* CMP shutdown state and pause helpers: CMP/lifecycle.c. */

 /* Separate mutex for log buffer */
 static pthread_mutex_t g_log_mtx = PTHREAD_MUTEX_INITIALIZER;
 /* Separate mutex for cloud job/status state */
 static pthread_mutex_t g_cloud_mtx = PTHREAD_MUTEX_INITIALIZER;

 /* Ring log buffer for remote debug */
 #define LOG_BUF_SIZE (32 * 1024)
 static char g_logbuf[LOG_BUF_SIZE];
 static int g_logpos = 0;
 void logprintf(const char *fmt, ...) {
     char tmp[1024] = {0};
     va_list ap;
     va_start(ap, fmt);
     int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
     va_end(ap);
     printf("%s", tmp);
     if (n > 0) {
         if ((size_t)n >= sizeof(tmp)) n = (int)sizeof(tmp) - 1;
         pthread_mutex_lock(&g_log_mtx);
         for (int i = 0; i < n && g_logpos < LOG_BUF_SIZE - 1; i++)
             g_logbuf[g_logpos++] = tmp[i];
         pthread_mutex_unlock(&g_log_mtx);
     }
 }

 /* ── Save entry ─────────────────────────────────────────────────── */
 typedef struct {
     char path[MAX_PATH_LEN];     /* full path to save image file */
     char title_id[32];           /* e.g. PPSA01234 */
     char save_name[256];         /* save file name (varies per game) */
     char dir_name[256];          /* for mount point naming */
     char user_id[16];            /* hex user id e.g. "10000000" */
     int is_ps4;                  /* 1 if PS4 save (byte 0x0 == 0x01) */
     int is_backup;               /* 1 if backup save (sdimg_sce_bu_) */
     int is_usb;                  /* 1 if save is on USB */
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
 char g_mounted_path[MAX_PATH_LEN] = {0};
 char g_mount_point[MAX_PATH_LEN] = {0};
 int g_mounted = 0;
 static int g_mounted_idx = -1;
 static char g_mount_error[512] = {0};
 char g_local_copy[MAX_PATH_LEN] = {0};
 static uint8_t g_sealed_key[96] = {0};
 static int g_enc_ps4 = 0;
 int g_owner_mount_active = 0;
 static int g_image_fresh = 0;

 /* Protected PS5PARAM cache and validation live in CMP/ps5param.c. */
 /* ── Server-side editor buffer ─────────────────────────────────── */
 static char g_ed_image[MAX_PATH_LEN];
 static char  g_ed_name[512] = {0};   /* file path relative to mount */
 static char *g_ed_buf = NULL;        /* file contents in memory */
 static size_t g_ed_size = 0;         /* buffer size */
 static int   g_ed_dirty = 0;        /* has unsaved edits */

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

 /* ── Account ID lookup via registry ─────────────────────────────── */
 static int get_account_id_for_user(const char *uid_hex, uint64_t *account_id) {
     /* Read username from /user/home/<uid>/username.dat */
     char upath[MAX_PATH_LEN];
     snprintf(upath, sizeof(upath), "/user/home/%s/username.dat", uid_hex);
     char username[17] = {0};
     int fd = open(upath, O_RDONLY);
     if (fd >= 0) {
         read(fd, username, 16);
         username[16] = 0;
         close(fd);
     }
     if (!username[0]) return -1;

     /* Iterate registry accounts 1-16, match by name */
     for (int i = 1; i <= 16; i++) {
         int key_name = (i - 1) * 65536 + 125829632;
         char reg_name[32] = {0};
         if (sceRegMgrGetStr(key_name, reg_name, sizeof(reg_name)) < 0) continue;
         if (!reg_name[0]) continue;
         if (strcmp(username, reg_name) == 0) {
             int key_aid = (i - 1) * 65536 + 125830400;
             uint64_t aid = 0;
             if (sceRegMgrGetBin(key_aid, &aid, sizeof(aid)) < 0) return -1;
             printf("[GarlicMgr] Registry: user '%s' = account %d, aid=%llx\n",
                    username, i, (unsigned long long)aid);
             *account_id = aid;
             return 0;
         }
     }
     printf("[GarlicMgr] Registry: no account found for user '%s'\n", username);
     return -1;
 }

 /* CMP Encrypt/Resign account selection lives in CMP/accounts.c. */

 /* ── Notification ───────────────────────────────────────────────── */
 void notify(const char *fmt, ...) {
     notify_request_t req;
     memset(&req, 0, sizeof(req));
     va_list a; va_start(a, fmt);
     vsnprintf(req.message, sizeof(req.message), fmt, a);
     va_end(a);
     sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
     printf("[GarlicMgr] %s\n", req.message);
 }

 /* ── Cloud backup config/status ────────────────────────────────── */
 typedef struct {
     char host[256];
     int port;
     char user[128];
     char pass[128];
     char remote_path[512];
     int use_tls;
 } cloud_ftp_config_t;

 typedef struct {
     char type[32];
     char project_id[128];
     char private_key_id[128];
     char private_key[4096];
     char client_email[256];
     char client_id[256];
     char auth_uri[256];
     char token_uri[256];
     char auth_provider_x509_cert_url[256];
     char client_x509_cert_url[512];
     char universe_domain[128];
 } cloud_service_account_t;

 typedef struct {
     char mode[32];
     char auth_mode[32];
     char folder_id[256];
     char client_id[256];
     char client_secret[256];
     char refresh_token[512];
     char access_token[2048];
     cloud_service_account_t service_account;
 } cloud_drive_config_t;

 typedef struct {
     int enabled;
     int poll_seconds;
     int settle_seconds;
     int queue_for_browser_drive;
 } cloud_auto_config_t;

 typedef struct {
     int enabled;
     char path[MAX_PATH_LEN];
 } cloud_file_target_t;

 typedef struct {
     cloud_file_target_t local;
     cloud_file_target_t usb;
     int ftp_enabled;
     int drive_enabled;
 } cloud_targets_config_t;

 typedef struct {
     int enabled;
     char provider[32];
     char watch_titles[CLOUD_MAX_TITLES][32];
     int watch_title_count;
     cloud_ftp_config_t ftp;
     cloud_drive_config_t drive;
     cloud_auto_config_t auto_backup;
     cloud_targets_config_t targets;
 } cloud_config_t;

 typedef struct {
     int running;
     int last_ok;
     int progress;
     char active[128];
     char last_error[256];
     char last_remote[512];
 } cloud_state_t;

 static cloud_state_t g_cloud_state = {0};
 static int g_net_ready = 0;
 static volatile sig_atomic_t g_resume_pending = 0;
 static volatile sig_atomic_t g_resume_signal = 0;

 static void handle_sigcont(int sig) {
     (void)sig;
     g_resume_signal = 1;
 }

 static const char *json_skip_ws(const char *p) {
     while (p && *p && isspace((unsigned char)*p)) p++;
     return p;
 }

 static const char *json_find_key(const char *json, const char *key) {
     char pat[64];
     snprintf(pat, sizeof(pat), "\"%s\"", key);
     const char *p = strstr(json, pat);
     if (!p) return NULL;
     p += strlen(pat);
     p = json_skip_ws(p);
     if (!p || *p != ':') return NULL;
     return json_skip_ws(p + 1);
 }

 static int json_parse_string(const char *p, char *out, size_t out_sz) {
     if (!p || *p != '"' || out_sz == 0) return -1;
     p++;
     size_t n = 0;
     while (*p && *p != '"') {
         char c = *p++;
         if (c == '\\' && *p) {
             c = *p++;
             if (c == 'n') c = '\n';
             else if (c == 'r') c = '\r';
             else if (c == 't') c = '\t';
         }
         if (n + 1 < out_sz) out[n++] = c;
     }
     out[n] = 0;
     return *p == '"' ? 0 : -1;
 }

 static int json_get_string(const char *json, const char *key, char *out, size_t out_sz) {
     const char *p = json_find_key(json, key);
     return json_parse_string(p, out, out_sz);
 }

 static int json_get_bool_default(const char *json, const char *key, int def) {
     const char *p = json_find_key(json, key);
     if (!p) return def;
     if (strncmp(p, "true", 4) == 0) return 1;
     if (strncmp(p, "false", 5) == 0) return 0;
     return def;
 }

 static int json_get_int_default(const char *json, const char *key, int def) {
     const char *p = json_find_key(json, key);
     if (!p) return def;
     return (int)strtol(p, NULL, 10);
 }

 static int json_get_object_string(const char *json, const char *obj, const char *key,
                                   char *out, size_t out_sz) {
     const char *p = json_find_key(json, obj);
     if (!p || *p != '{') return -1;
     return json_get_string(p, key, out, out_sz);
 }

 static int json_get_object_bool_default(const char *json, const char *obj,
                                         const char *key, int def) {
     const char *p = json_find_key(json, obj);
     if (!p || *p != '{') return def;
     return json_get_bool_default(p, key, def);
 }

 static int json_get_object_int_default(const char *json, const char *obj,
                                        const char *key, int def) {
     const char *p = json_find_key(json, obj);
     if (!p || *p != '{') return def;
     return json_get_int_default(p, key, def);
 }

 static void cloud_read_ftp_fields(const char *json, cloud_ftp_config_t *ftp) {
     if (json_get_object_string(json, "ftp", "host", ftp->host, sizeof(ftp->host)) != 0)
         json_get_string(json, "host", ftp->host, sizeof(ftp->host));
     ftp->port = json_get_object_int_default(json, "ftp", "port",
                                             json_get_int_default(json, "port", ftp->port));
     if (json_get_object_string(json, "ftp", "user", ftp->user, sizeof(ftp->user)) != 0)
         json_get_string(json, "user", ftp->user, sizeof(ftp->user));
     if (json_get_object_string(json, "ftp", "pass", ftp->pass, sizeof(ftp->pass)) != 0)
         json_get_string(json, "pass", ftp->pass, sizeof(ftp->pass));
     if (json_get_object_string(json, "ftp", "remote_path", ftp->remote_path, sizeof(ftp->remote_path)) != 0)
         json_get_string(json, "remote_path", ftp->remote_path, sizeof(ftp->remote_path));
     ftp->use_tls = json_get_object_bool_default(json, "ftp", "use_tls",
                                                 json_get_bool_default(json, "use_tls", ftp->use_tls));
 }

 static void cloud_read_drive_fields(const char *json, cloud_drive_config_t *drive) {
     if (json_get_object_string(json, "google_drive", "mode", drive->mode, sizeof(drive->mode)) != 0)
         json_get_string(json, "mode", drive->mode, sizeof(drive->mode));
     if (json_get_object_string(json, "google_drive", "auth_mode", drive->auth_mode, sizeof(drive->auth_mode)) != 0)
         json_get_string(json, "auth_mode", drive->auth_mode, sizeof(drive->auth_mode));
     if (json_get_object_string(json, "google_drive", "folder_id", drive->folder_id, sizeof(drive->folder_id)) != 0)
         json_get_string(json, "folder_id", drive->folder_id, sizeof(drive->folder_id));
     if (json_get_object_string(json, "google_drive", "client_id", drive->client_id, sizeof(drive->client_id)) != 0)
         json_get_string(json, "client_id", drive->client_id, sizeof(drive->client_id));
     if (json_get_object_string(json, "google_drive", "client_secret", drive->client_secret, sizeof(drive->client_secret)) != 0)
         json_get_string(json, "client_secret", drive->client_secret, sizeof(drive->client_secret));
     if (json_get_object_string(json, "google_drive", "refresh_token", drive->refresh_token, sizeof(drive->refresh_token)) != 0)
         json_get_string(json, "refresh_token", drive->refresh_token, sizeof(drive->refresh_token));
     if (json_get_object_string(json, "google_drive", "access_token", drive->access_token, sizeof(drive->access_token)) != 0)
         json_get_string(json, "access_token", drive->access_token, sizeof(drive->access_token));
 }

 static void cloud_read_backup_targets(const char *json, cloud_config_t *cfg) {
     const char *targets = json_find_key(json, "backup_targets");
     if (!targets || *targets != '{') {
         cfg->targets.ftp_enabled = (strcmp(cfg->provider, "ftp") == 0);
         cfg->targets.drive_enabled = (strcmp(cfg->provider, "google_drive") == 0);
         return;
     }
     cfg->targets.local.enabled = json_get_object_bool_default(targets, "local", "enabled", cfg->targets.local.enabled);
     if (json_get_object_string(targets, "local", "path", cfg->targets.local.path, sizeof(cfg->targets.local.path)) != 0 &&
         json_get_object_string(targets, "local", "folder", cfg->targets.local.path, sizeof(cfg->targets.local.path)) != 0) {
         /* Keep default local path. */
     }
     cfg->targets.usb.enabled = json_get_object_bool_default(targets, "usb", "enabled", cfg->targets.usb.enabled);
     if (json_get_object_string(targets, "usb", "path", cfg->targets.usb.path, sizeof(cfg->targets.usb.path)) != 0 &&
         json_get_object_string(targets, "usb", "folder", cfg->targets.usb.path, sizeof(cfg->targets.usb.path)) != 0) {
         /* Keep default USB path. */
     }
     cfg->targets.ftp_enabled = json_get_object_bool_default(targets, "ftp", "enabled", cfg->targets.ftp_enabled);
     cfg->targets.drive_enabled = json_get_object_bool_default(targets, "google_drive", "enabled", cfg->targets.drive_enabled);
 }

 static int json_get_watch_titles(const char *json, cloud_config_t *cfg) {
     const char *p = json_find_key(json, "watch_titles");
     if (!p || *p != '[') return 0;
     p++;
     while (*p && *p != ']' && cfg->watch_title_count < CLOUD_MAX_TITLES) {
         p = json_skip_ws(p);
         if (*p == '"') {
             if (json_parse_string(p, cfg->watch_titles[cfg->watch_title_count],
                                   sizeof(cfg->watch_titles[0])) == 0) {
                 cfg->watch_title_count++;
             }
             p++;
             while (*p && *p != '"') {
                 if (*p == '\\' && p[1]) p++;
                 p++;
             }
             if (*p == '"') p++;
         }
         while (*p && *p != ',' && *p != ']') p++;
         if (*p == ',') p++;
     }
     return 0;
 }

 static int is_redacted_secret(const char *s) {
     if (!s || !s[0]) return 1;
     return strcmp(s, "********") == 0 || strcmp(s, "__KEEP__") == 0;
 }

 static void json_escape(const char *in, char *out, size_t out_sz) {
     size_t n = 0;
     if (!out_sz) return;
     for (const unsigned char *p = (const unsigned char *)in; p && *p && n + 1 < out_sz; p++) {
         if ((*p == '"' || *p == '\\') && n + 2 < out_sz) {
             out[n++] = '\\';
             out[n++] = (char)*p;
         } else if (*p == '\n' && n + 2 < out_sz) {
             out[n++] = '\\';
             out[n++] = 'n';
         } else if (*p == '\r' && n + 2 < out_sz) {
             out[n++] = '\\';
             out[n++] = 'r';
         } else if (*p == '\t' && n + 2 < out_sz) {
             out[n++] = '\\';
             out[n++] = 't';
         } else if (*p >= 0x20) {
             out[n++] = (char)*p;
         }
     }
     out[n] = 0;
 }

 static int read_file_limited(const char *path, char **out, size_t max_len) {
     *out = NULL;
     int fd = open(path, O_RDONLY);
     if (fd < 0) return -1;
     struct stat st;
     if (fstat(fd, &st) < 0 || st.st_size <= 0 || (size_t)st.st_size > max_len) {
         close(fd);
         return -2;
     }
     char *buf = malloc((size_t)st.st_size + 1);
     if (!buf) { close(fd); return -3; }
     size_t got = 0;
     while (got < (size_t)st.st_size) {
         ssize_t r = read(fd, buf + got, (size_t)st.st_size - got);
         if (r <= 0) break;
         got += r;
     }
     close(fd);
     buf[got] = 0;
     *out = buf;
     return got == (size_t)st.st_size ? 0 : -4;
 }

 static int cloud_load_config(cloud_config_t *cfg, char *err, size_t err_sz) {
     memset(cfg, 0, sizeof(*cfg));
     snprintf(cfg->provider, sizeof(cfg->provider), "ftp");
     cfg->ftp.port = 21;
     snprintf(cfg->ftp.remote_path, sizeof(cfg->ftp.remote_path), "/");
     snprintf(cfg->drive.mode, sizeof(cfg->drive.mode), "browser");
     snprintf(cfg->drive.service_account.type, sizeof(cfg->drive.service_account.type), "service_account");
     snprintf(cfg->drive.service_account.token_uri, sizeof(cfg->drive.service_account.token_uri), "https://oauth2.googleapis.com/token");
     snprintf(cfg->drive.service_account.universe_domain, sizeof(cfg->drive.service_account.universe_domain), "googleapis.com");
     cfg->auto_backup.poll_seconds = 5;
     cfg->auto_backup.settle_seconds = 15;
     cfg->auto_backup.queue_for_browser_drive = 1;
    snprintf(cfg->targets.local.path, sizeof(cfg->targets.local.path), BACKUP_DEFAULT_LOCAL_DIR);
    snprintf(cfg->targets.usb.path, sizeof(cfg->targets.usb.path), BACKUP_DEFAULT_USB_DIR);

     char *json = NULL;
     int rr = read_file_limited(CLOUD_CONFIG_PATH, &json, 64 * 1024);
     if (rr < 0) {
         snprintf(err, err_sz, "Cannot read %s", CLOUD_CONFIG_PATH);
         return -1;
     }

     cfg->enabled = json_get_bool_default(json, "enabled", 0);
     json_get_string(json, "provider", cfg->provider, sizeof(cfg->provider));
     cfg->targets.ftp_enabled = (strcmp(cfg->provider, "ftp") == 0);
     cfg->targets.drive_enabled = (strcmp(cfg->provider, "google_drive") == 0);
     json_get_watch_titles(json, cfg);
     cloud_read_ftp_fields(json, &cfg->ftp);
     cloud_read_drive_fields(json, &cfg->drive);
     cloud_read_backup_targets(json, cfg);
     json_get_object_string(json, "service_account", "type", cfg->drive.service_account.type, sizeof(cfg->drive.service_account.type));
     json_get_object_string(json, "service_account", "project_id", cfg->drive.service_account.project_id, sizeof(cfg->drive.service_account.project_id));
     json_get_object_string(json, "service_account", "private_key_id", cfg->drive.service_account.private_key_id, sizeof(cfg->drive.service_account.private_key_id));
     json_get_object_string(json, "service_account", "private_key", cfg->drive.service_account.private_key, sizeof(cfg->drive.service_account.private_key));
     json_get_object_string(json, "service_account", "client_email", cfg->drive.service_account.client_email, sizeof(cfg->drive.service_account.client_email));
     json_get_object_string(json, "service_account", "client_id", cfg->drive.service_account.client_id, sizeof(cfg->drive.service_account.client_id));
     json_get_object_string(json, "service_account", "auth_uri", cfg->drive.service_account.auth_uri, sizeof(cfg->drive.service_account.auth_uri));
     json_get_object_string(json, "service_account", "token_uri", cfg->drive.service_account.token_uri, sizeof(cfg->drive.service_account.token_uri));
     json_get_object_string(json, "service_account", "auth_provider_x509_cert_url", cfg->drive.service_account.auth_provider_x509_cert_url, sizeof(cfg->drive.service_account.auth_provider_x509_cert_url));
     json_get_object_string(json, "service_account", "client_x509_cert_url", cfg->drive.service_account.client_x509_cert_url, sizeof(cfg->drive.service_account.client_x509_cert_url));
     json_get_object_string(json, "service_account", "universe_domain", cfg->drive.service_account.universe_domain, sizeof(cfg->drive.service_account.universe_domain));
     cfg->auto_backup.enabled = json_get_object_bool_default(json, "auto_backup", "enabled",
         json_get_bool_default(json, "auto_enabled", 0));
     cfg->auto_backup.poll_seconds = json_get_object_int_default(json, "auto_backup", "poll_seconds",
         json_get_int_default(json, "poll_seconds", cfg->auto_backup.poll_seconds));
     cfg->auto_backup.settle_seconds = json_get_object_int_default(json, "auto_backup", "settle_seconds",
         json_get_int_default(json, "settle_seconds", cfg->auto_backup.settle_seconds));
     cfg->auto_backup.queue_for_browser_drive = json_get_object_bool_default(json, "auto_backup", "queue_for_browser_drive",
         json_get_bool_default(json, "queue_for_browser_drive", cfg->auto_backup.queue_for_browser_drive));
     free(json);

     if (!cfg->enabled) return 0;
     if (strcmp(cfg->provider, "google_drive") != 0)
         snprintf(cfg->provider, sizeof(cfg->provider), "ftp");
     if (cfg->targets.ftp_enabled) {
         if (cfg->ftp.use_tls) {
             snprintf(err, err_sz, "FTP TLS is not supported in Phase 1");
             return -2;
         }
         if (!cfg->ftp.host[0] || !cfg->ftp.user[0] || !cfg->ftp.pass[0]) {
             snprintf(err, err_sz, "FTP host/user/pass are required");
             return -3;
         }
         if (cfg->ftp.port <= 0 || cfg->ftp.port > 65535) {
             snprintf(err, err_sz, "Invalid FTP port");
             return -4;
         }
     }
     if (cfg->targets.drive_enabled || strcmp(cfg->provider, "google_drive") == 0) {
         if (strcmp(cfg->drive.mode, "direct") != 0)
             snprintf(cfg->drive.mode, sizeof(cfg->drive.mode), "browser");
     }
     if (!cfg->ftp.remote_path[0])
         snprintf(cfg->ftp.remote_path, sizeof(cfg->ftp.remote_path), "/");
     if (!cfg->targets.local.path[0])
        snprintf(cfg->targets.local.path, sizeof(cfg->targets.local.path), BACKUP_DEFAULT_LOCAL_DIR);
     if (!cfg->targets.usb.path[0])
        snprintf(cfg->targets.usb.path, sizeof(cfg->targets.usb.path), BACKUP_DEFAULT_USB_DIR);
     if (cfg->auto_backup.poll_seconds < 2) cfg->auto_backup.poll_seconds = 2;
     if (cfg->auto_backup.settle_seconds < 3) cfg->auto_backup.settle_seconds = 3;
     return 0;
 }

 static int cloud_title_is_watched(const cloud_config_t *cfg, const char *title_id) {
     if (cfg->watch_title_count == 0) return 1;
     for (int i = 0; i < cfg->watch_title_count; i++)
         if (strcmp(cfg->watch_titles[i], title_id) == 0) return 1;
     return 0;
 }

 static int cloud_config_to_json(const cloud_config_t *cfg, char *out, size_t out_sz, int redact) {
     char provider[64], ftp_host[512], ftp_user[256], ftp_pass[256], ftp_path[1024];
     char drive_mode[64], auth_mode[64], folder_id[512], client_id[512], client_secret[512], refresh_token[1024], access_token[4096];
     char local_path[2048], usb_path[2048];
     char sa_type[80], sa_project[256], sa_key_id[256], sa_key[8192], sa_email[512], sa_client_id[512];
     char sa_auth_uri[512], sa_token_uri[512], sa_auth_cert[512], sa_client_cert[1024], sa_universe[256];
     json_escape(cfg->provider, provider, sizeof(provider));
     json_escape(cfg->ftp.host, ftp_host, sizeof(ftp_host));
     json_escape(cfg->ftp.user, ftp_user, sizeof(ftp_user));
     json_escape(redact && cfg->ftp.pass[0] ? "********" : cfg->ftp.pass, ftp_pass, sizeof(ftp_pass));
     json_escape(cfg->ftp.remote_path, ftp_path, sizeof(ftp_path));
     json_escape(cfg->drive.mode, drive_mode, sizeof(drive_mode));
     json_escape(cfg->drive.auth_mode, auth_mode, sizeof(auth_mode));
     json_escape(cfg->drive.folder_id, folder_id, sizeof(folder_id));
     json_escape(cfg->drive.client_id, client_id, sizeof(client_id));
     json_escape(redact && cfg->drive.client_secret[0] ? "********" : cfg->drive.client_secret,
                 client_secret, sizeof(client_secret));
     json_escape(redact && cfg->drive.refresh_token[0] ? "********" : cfg->drive.refresh_token,
                 refresh_token, sizeof(refresh_token));
     json_escape(redact && cfg->drive.access_token[0] ? "********" : cfg->drive.access_token,
                 access_token, sizeof(access_token));
     json_escape(cfg->targets.local.path, local_path, sizeof(local_path));
     json_escape(cfg->targets.usb.path, usb_path, sizeof(usb_path));
     json_escape(cfg->drive.service_account.type, sa_type, sizeof(sa_type));
     json_escape(cfg->drive.service_account.project_id, sa_project, sizeof(sa_project));
     json_escape(cfg->drive.service_account.private_key_id, sa_key_id, sizeof(sa_key_id));
     json_escape(redact && cfg->drive.service_account.private_key[0] ? "********" : cfg->drive.service_account.private_key,
                 sa_key, sizeof(sa_key));
     json_escape(cfg->drive.service_account.client_email, sa_email, sizeof(sa_email));
     json_escape(cfg->drive.service_account.client_id, sa_client_id, sizeof(sa_client_id));
     json_escape(cfg->drive.service_account.auth_uri, sa_auth_uri, sizeof(sa_auth_uri));
     json_escape(cfg->drive.service_account.token_uri, sa_token_uri, sizeof(sa_token_uri));
     json_escape(cfg->drive.service_account.auth_provider_x509_cert_url, sa_auth_cert, sizeof(sa_auth_cert));
     json_escape(cfg->drive.service_account.client_x509_cert_url, sa_client_cert, sizeof(sa_client_cert));
     json_escape(cfg->drive.service_account.universe_domain, sa_universe, sizeof(sa_universe));

     int pos = snprintf(out, out_sz,
         "{\n"
         "  \"enabled\": %s,\n"
         "  \"provider\": \"%s\",\n"
         "  \"watch_titles\": [",
         cfg->enabled ? "true" : "false", provider);
     for (int i = 0; i < cfg->watch_title_count && pos > 0 && pos < (int)out_sz; i++) {
         char tid[80];
         json_escape(cfg->watch_titles[i], tid, sizeof(tid));
         pos += snprintf(out + pos, out_sz - pos, "%s\"%s\"", i ? ", " : "", tid);
     }
     if (pos < 0 || pos >= (int)out_sz) return -1;
     pos += snprintf(out + pos, out_sz - pos,
         "],\n"
         "  \"ftp\": {\n"
         "    \"host\": \"%s\",\n"
         "    \"port\": %d,\n"
         "    \"user\": \"%s\",\n"
         "    \"pass\": \"%s\",\n"
         "    \"remote_path\": \"%s\",\n"
         "    \"use_tls\": %s\n"
         "  },\n"
         "  \"auto_backup\": {\n"
         "    \"enabled\": %s,\n"
         "    \"auto_enabled\": %s,\n"
         "    \"poll_seconds\": %d,\n"
         "    \"settle_seconds\": %d,\n"
         "    \"queue_for_browser_drive\": %s\n"
         "  },\n"
         "  \"backup_targets\": {\n"
         "    \"local\": { \"enabled\": %s, \"path\": \"%s\" },\n"
         "    \"usb\": { \"enabled\": %s, \"path\": \"%s\" },\n"
         "    \"ftp\": { \"enabled\": %s },\n"
         "    \"google_drive\": { \"enabled\": %s }\n"
         "  },\n"
         "  \"google_drive\": {\n"
         "    \"mode\": \"%s\",\n"
         "    \"auth_mode\": \"%s\",\n"
         "    \"folder_id\": \"%s\",\n"
         "    \"client_id\": \"%s\",\n"
         "    \"client_secret\": \"%s\",\n"
         "    \"refresh_token\": \"%s\",\n"
         "    \"access_token\": \"%s\",\n"
         "    \"service_account\": {\n"
         "      \"type\": \"%s\",\n"
         "      \"project_id\": \"%s\",\n"
         "      \"private_key_id\": \"%s\",\n"
         "      \"private_key\": \"%s\",\n"
         "      \"client_email\": \"%s\",\n"
         "      \"client_id\": \"%s\",\n"
         "      \"auth_uri\": \"%s\",\n"
         "      \"token_uri\": \"%s\",\n"
         "      \"auth_provider_x509_cert_url\": \"%s\",\n"
         "      \"client_x509_cert_url\": \"%s\",\n"
         "      \"universe_domain\": \"%s\"\n"
         "    }\n"
         "  }\n"
         "}\n",
         ftp_host, cfg->ftp.port, ftp_user, ftp_pass, ftp_path,
         cfg->ftp.use_tls ? "true" : "false",
         cfg->auto_backup.enabled ? "true" : "false",
         cfg->auto_backup.enabled ? "true" : "false",
         cfg->auto_backup.poll_seconds,
         cfg->auto_backup.settle_seconds,
         cfg->auto_backup.queue_for_browser_drive ? "true" : "false",
         cfg->targets.local.enabled ? "true" : "false", local_path,
         cfg->targets.usb.enabled ? "true" : "false", usb_path,
         cfg->targets.ftp_enabled ? "true" : "false",
         cfg->targets.drive_enabled ? "true" : "false",
         drive_mode, auth_mode, folder_id, client_id, client_secret, refresh_token, access_token,
         sa_type, sa_project, sa_key_id, sa_key, sa_email, sa_client_id,
         sa_auth_uri, sa_token_uri, sa_auth_cert, sa_client_cert, sa_universe);
     return (pos > 0 && pos < (int)out_sz) ? 0 : -1;
 }

 static void cloud_merge_secrets(cloud_config_t *dst, const cloud_config_t *old_cfg) {
     if (old_cfg) {
         if (is_redacted_secret(dst->ftp.pass))
             snprintf(dst->ftp.pass, sizeof(dst->ftp.pass), "%s", old_cfg->ftp.pass);
         if (is_redacted_secret(dst->drive.client_secret))
             snprintf(dst->drive.client_secret, sizeof(dst->drive.client_secret), "%s", old_cfg->drive.client_secret);
         if (is_redacted_secret(dst->drive.refresh_token))
             snprintf(dst->drive.refresh_token, sizeof(dst->drive.refresh_token), "%s", old_cfg->drive.refresh_token);
         if (is_redacted_secret(dst->drive.access_token))
             snprintf(dst->drive.access_token, sizeof(dst->drive.access_token), "%s", old_cfg->drive.access_token);
         if (is_redacted_secret(dst->drive.service_account.private_key))
             snprintf(dst->drive.service_account.private_key, sizeof(dst->drive.service_account.private_key), "%s", old_cfg->drive.service_account.private_key);
     }
 }

 static int cloud_parse_config_text(const char *json, cloud_config_t *cfg, char *err, size_t err_sz) {
     memset(cfg, 0, sizeof(*cfg));
     snprintf(cfg->provider, sizeof(cfg->provider), "ftp");
     snprintf(cfg->drive.mode, sizeof(cfg->drive.mode), "browser");
     snprintf(cfg->drive.service_account.type, sizeof(cfg->drive.service_account.type), "service_account");
     snprintf(cfg->drive.service_account.token_uri, sizeof(cfg->drive.service_account.token_uri), "https://oauth2.googleapis.com/token");
     snprintf(cfg->drive.service_account.universe_domain, sizeof(cfg->drive.service_account.universe_domain), "googleapis.com");
     cfg->ftp.port = 21;
     snprintf(cfg->ftp.remote_path, sizeof(cfg->ftp.remote_path), "/");
     cfg->auto_backup.poll_seconds = 5;
     cfg->auto_backup.settle_seconds = 15;
     cfg->auto_backup.queue_for_browser_drive = 1;
    snprintf(cfg->targets.local.path, sizeof(cfg->targets.local.path), BACKUP_DEFAULT_LOCAL_DIR);
    snprintf(cfg->targets.usb.path, sizeof(cfg->targets.usb.path), BACKUP_DEFAULT_USB_DIR);

     cfg->enabled = json_get_bool_default(json, "enabled", 0);
     json_get_string(json, "provider", cfg->provider, sizeof(cfg->provider));
     cfg->targets.ftp_enabled = (strcmp(cfg->provider, "ftp") == 0);
     cfg->targets.drive_enabled = (strcmp(cfg->provider, "google_drive") == 0);
     json_get_watch_titles(json, cfg);
     cloud_read_ftp_fields(json, &cfg->ftp);
     cloud_read_drive_fields(json, &cfg->drive);
     cloud_read_backup_targets(json, cfg);
     json_get_object_string(json, "service_account", "type", cfg->drive.service_account.type, sizeof(cfg->drive.service_account.type));
     json_get_object_string(json, "service_account", "project_id", cfg->drive.service_account.project_id, sizeof(cfg->drive.service_account.project_id));
     json_get_object_string(json, "service_account", "private_key_id", cfg->drive.service_account.private_key_id, sizeof(cfg->drive.service_account.private_key_id));
     json_get_object_string(json, "service_account", "private_key", cfg->drive.service_account.private_key, sizeof(cfg->drive.service_account.private_key));
     json_get_object_string(json, "service_account", "client_email", cfg->drive.service_account.client_email, sizeof(cfg->drive.service_account.client_email));
     json_get_object_string(json, "service_account", "client_id", cfg->drive.service_account.client_id, sizeof(cfg->drive.service_account.client_id));
     json_get_object_string(json, "service_account", "auth_uri", cfg->drive.service_account.auth_uri, sizeof(cfg->drive.service_account.auth_uri));
     json_get_object_string(json, "service_account", "token_uri", cfg->drive.service_account.token_uri, sizeof(cfg->drive.service_account.token_uri));
     json_get_object_string(json, "service_account", "auth_provider_x509_cert_url", cfg->drive.service_account.auth_provider_x509_cert_url, sizeof(cfg->drive.service_account.auth_provider_x509_cert_url));
     json_get_object_string(json, "service_account", "client_x509_cert_url", cfg->drive.service_account.client_x509_cert_url, sizeof(cfg->drive.service_account.client_x509_cert_url));
     json_get_object_string(json, "service_account", "universe_domain", cfg->drive.service_account.universe_domain, sizeof(cfg->drive.service_account.universe_domain));
     cfg->auto_backup.enabled = json_get_object_bool_default(json, "auto_backup", "enabled",
         json_get_bool_default(json, "auto_enabled", 0));
     cfg->auto_backup.poll_seconds = json_get_object_int_default(json, "auto_backup", "poll_seconds",
         json_get_int_default(json, "poll_seconds", cfg->auto_backup.poll_seconds));
     cfg->auto_backup.settle_seconds = json_get_object_int_default(json, "auto_backup", "settle_seconds",
         json_get_int_default(json, "settle_seconds", cfg->auto_backup.settle_seconds));
     cfg->auto_backup.queue_for_browser_drive = json_get_object_bool_default(json, "auto_backup", "queue_for_browser_drive",
         json_get_bool_default(json, "queue_for_browser_drive", cfg->auto_backup.queue_for_browser_drive));

     if (strcmp(cfg->provider, "google_drive") != 0)
         snprintf(cfg->provider, sizeof(cfg->provider), "ftp");
     if (strcmp(cfg->drive.mode, "direct") != 0)
         snprintf(cfg->drive.mode, sizeof(cfg->drive.mode), "browser");
     if (cfg->targets.ftp_enabled && (cfg->ftp.port <= 0 || cfg->ftp.port > 65535)) {
         snprintf(err, err_sz, "Invalid FTP port");
         return -1;
     }
     if (!cfg->ftp.remote_path[0])
         snprintf(cfg->ftp.remote_path, sizeof(cfg->ftp.remote_path), "/");
     if (!cfg->targets.local.path[0])
        snprintf(cfg->targets.local.path, sizeof(cfg->targets.local.path), BACKUP_DEFAULT_LOCAL_DIR);
     if (!cfg->targets.usb.path[0])
        snprintf(cfg->targets.usb.path, sizeof(cfg->targets.usb.path), BACKUP_DEFAULT_USB_DIR);
     if (cfg->auto_backup.poll_seconds < 2) cfg->auto_backup.poll_seconds = 2;
     if (cfg->auto_backup.settle_seconds < 3) cfg->auto_backup.settle_seconds = 3;
     return 0;
 }

 static int cloud_save_config(const cloud_config_t *cfg, char *err, size_t err_sz) {
     mkdir("/data", 0777);
     mkdir("/data/garlic", 0777);
     char json[32768];
     if (cloud_config_to_json(cfg, json, sizeof(json), 0) < 0) {
         snprintf(err, err_sz, "Config is too large");
         return -1;
     }
     int fd = open(CLOUD_CONFIG_PATH, O_CREAT | O_WRONLY | O_TRUNC, 0600);
     if (fd < 0) {
         snprintf(err, err_sz, "Cannot write %s", CLOUD_CONFIG_PATH);
         return -1;
     }
     size_t len = strlen(json), off = 0;
     while (off < len) {
         ssize_t wr = write(fd, json + off, len - off);
         if (wr <= 0) { close(fd); snprintf(err, err_sz, "Config write failed"); return -1; }
         off += wr;
     }
     close(fd);
     return 0;
 }

 static int cloud_reserve_job(const char *active,char *error,size_t cap) {
     pthread_mutex_lock(&g_cloud_mtx);
     if(g_cloud_state.running||garlic_lifecycle_stopping()){
         pthread_mutex_unlock(&g_cloud_mtx);
         snprintf(error,cap,"Cloud upload already running or Garlic SaveMgr is shutting down");return -1;
     }
     g_cloud_state.running = 1;
     g_cloud_state.progress = 0;
     g_cloud_state.last_ok = 0;
     g_cloud_state.last_error[0] = 0;
     snprintf(g_cloud_state.active, sizeof(g_cloud_state.active), "%s", active ? active : "Cloud upload");
     pthread_mutex_unlock(&g_cloud_mtx);return 0;
 }

 static void cloud_set_progress(int progress, const char *remote) {
     pthread_mutex_lock(&g_cloud_mtx);
     g_cloud_state.progress = progress;
     if (remote && remote[0])
         snprintf(g_cloud_state.last_remote, sizeof(g_cloud_state.last_remote), "%s", remote);
     pthread_mutex_unlock(&g_cloud_mtx);
 }

static void cloud_set_step(int progress, const char *active, const char *remote) {
    pthread_mutex_lock(&g_cloud_mtx);
    g_cloud_state.progress = progress;
    if (active && active[0])
        snprintf(g_cloud_state.active, sizeof(g_cloud_state.active), "%s", active);
    if (remote && remote[0])
        snprintf(g_cloud_state.last_remote, sizeof(g_cloud_state.last_remote), "%s", remote);
    pthread_mutex_unlock(&g_cloud_mtx);
}

 static void cloud_set_done(int ok, const char *message, const char *remote) {
     pthread_mutex_lock(&g_cloud_mtx);
     g_cloud_state.running = 0;
     g_cloud_state.progress = ok ? 100 : g_cloud_state.progress;
     g_cloud_state.last_ok = ok;
     if (ok) {
         g_cloud_state.last_error[0] = 0;
     } else {
         snprintf(g_cloud_state.last_error, sizeof(g_cloud_state.last_error), "%s",
                  message ? message : "Cloud upload failed");
     }
     if (remote && remote[0])
         snprintf(g_cloud_state.last_remote, sizeof(g_cloud_state.last_remote), "%s", remote);
     pthread_mutex_unlock(&g_cloud_mtx);
 }

 static void url_param_decode(const char *src, char *dst, size_t dst_sz) {
     size_t n = 0;
     if (!dst_sz) return;
     while (src && *src && *src != '&' && n + 1 < dst_sz) {
         if (*src == '%' && src[1] && src[2]) {
             char hex[3] = {src[1], src[2], 0};
             dst[n++] = (char)strtol(hex, NULL, 16);
             src += 3;
         } else if (*src == '+') {
             dst[n++] = ' ';
             src++;
         } else {
             dst[n++] = *src++;
         }
     }
     dst[n] = 0;
 }

 static void sanitize_filename(char *s) {
     for (char *p = s; p && *p; p++) {
         if (*p == '/' || *p == '\\' || *p == ':' || *p == '*' || *p == '?' ||
             *p == '"' || *p == '<' || *p == '>' || *p == '|' ||
             *p == '\r' || *p == '\n') {
             *p = '_';
         }
     }
 }

 /* ── Minimal passive FTP client ────────────────────────────────── */
 typedef struct {
     int ctrl;
     char last[512];
     char ctrl_host[64]; /* peer IP of control connection (for PASV NAT fix) */
 } ftp_client_t;

 static int send_all_fd(int fd, const void *buf, size_t len) {
     const char *p = (const char *)buf;
     while (len > 0) {
         ssize_t n = send(fd, p, len, 0);
         if (n < 0 && errno == EINTR) continue;
         if (n <= 0) return -1;
         p += n;
         len -= (size_t)n;
     }
     return 0;
 }

 static int net_init_once(void) {
     if (g_net_ready) return 0;
     if (sceNetInit() != 0) return -1;
     if (sceNetPoolCreate("garlic_net", 128 * 1024, 0) < 0) return -2;
     g_net_ready = 1;
     return 0;
 }

 static int tcp_connect_host(const char *host, int port, char *err, size_t err_sz) {
     if (!g_net_ready) {
         int nr = net_init_once();
         if (nr < 0) {
             snprintf(err, err_sz, "PS5 network init failed (%d); outbound FTP needs sceNetInit", nr);
             return -1;
         }
     }

     int fd = socket(AF_INET, SOCK_STREAM, 0);
     if (fd < 0) {
         snprintf(err, err_sz, "socket failed: %s", strerror(errno));
         return -1;
     }

     struct sockaddr_in addr;
     memset(&addr, 0, sizeof(addr));
     addr.sin_family = AF_INET;
     addr.sin_port = htons((uint16_t)port);
     addr.sin_addr.s_addr = inet_addr(host);
     if (addr.sin_addr.s_addr == INADDR_NONE) {
         struct hostent *he = gethostbyname(host);
         if (!he || !he->h_addr_list || !he->h_addr_list[0]) {
             snprintf(err, err_sz, "Cannot resolve FTP host %s", host);
             close(fd);
             return -1;
         }
         memcpy(&addr.sin_addr, he->h_addr_list[0], sizeof(addr.sin_addr));
     }

     int flags = fcntl(fd, F_GETFL, 0);
     if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);

     int cr = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
     if (cr < 0 && errno != EINPROGRESS) {
         snprintf(err, err_sz, "connect to %s:%d failed: %s", host, port, strerror(errno));
         close(fd);
         return -1;
     }
     if (cr != 0) {
         fd_set wfds;
         FD_ZERO(&wfds);
         FD_SET(fd, &wfds);
         struct timeval tv = { .tv_sec = 30, .tv_usec = 0 };
         if (select(fd + 1, NULL, &wfds, NULL, &tv) <= 0) {
             snprintf(err, err_sz, "connect to %s:%d timed out after 30s", host, port);
             close(fd);
             return -1;
         }
         int soerr = 0;
         socklen_t slen = sizeof(soerr);
         getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen);
         if (soerr != 0) {
             snprintf(err, err_sz, "connect to %s:%d failed: %s", host, port, strerror(soerr));
             close(fd);
             return -1;
         }
     }
     if (flags >= 0) fcntl(fd, F_SETFL, flags);
     return fd;
 }

 static int ftp_read_line(int fd, char *line, size_t line_sz) {
     size_t n = 0;
     while (n + 1 < line_sz) {
         char c;
         ssize_t r = recv(fd, &c, 1, 0);
         if (r < 0 && errno == EINTR) continue;
         if (r <= 0) return -1;
         line[n++] = c;
         if (c == '\n') break;
     }
     line[n] = 0;
     return (int)n;
 }

 static int ftp_read_response(ftp_client_t *ftp) {
     char line[512];
     int code = -1, multiline = 0;
     char first_code[4] = {0};

     while (ftp_read_line(ftp->ctrl, line, sizeof(line)) > 0) {
         snprintf(ftp->last, sizeof(ftp->last), "%s", line);
         if (isdigit((unsigned char)line[0]) &&
             isdigit((unsigned char)line[1]) &&
             isdigit((unsigned char)line[2])) {
             if (code < 0) {
                 code = atoi(line);
                 memcpy(first_code, line, 3);
                 first_code[3] = 0;
                 multiline = (line[3] == '-');
                 if (!multiline) return code;
             } else if (multiline && strncmp(line, first_code, 3) == 0 && line[3] == ' ') {
                 return code;
             }
         }
     }
     return -1;
 }

 static int ftp_cmd(ftp_client_t *ftp, const char *cmd, char *err, size_t err_sz) {
     char line[768];
     int n = snprintf(line, sizeof(line), "%s\r\n", cmd);
     if (n <= 0 || n >= (int)sizeof(line) || send_all_fd(ftp->ctrl, line, (size_t)n) < 0) {
         snprintf(err, err_sz, "FTP command send failed");
         return -1;
     }
     int code = ftp_read_response(ftp);
     if (code < 0) snprintf(err, err_sz, "FTP response read failed");
     return code;
 }

 static int ftp_arg_has_crlf(const char *arg) {
     if (!arg) return 0;
     for (const char *p = arg; *p; p++)
         if (*p == '\r' || *p == '\n') return 1;
     return 0;
 }

 static int ftp_cmd_arg(ftp_client_t *ftp, const char *verb, const char *arg,
                        char *err, size_t err_sz) {
     if (ftp_arg_has_crlf(arg)) {
         snprintf(err, err_sz, "FTP command argument contains CR/LF");
         return -1;
     }
     if (send_all_fd(ftp->ctrl, verb, strlen(verb)) < 0 ||
         send_all_fd(ftp->ctrl, " ", 1) < 0 ||
         send_all_fd(ftp->ctrl, arg ? arg : "", strlen(arg ? arg : "")) < 0 ||
         send_all_fd(ftp->ctrl, "\r\n", 2) < 0) {
         snprintf(err, err_sz, "FTP command send failed");
         return -1;
     }
     int code = ftp_read_response(ftp);
     if (code < 0) snprintf(err, err_sz, "FTP response read failed");
     return code;
 }

 static int ftp_connect_login(ftp_client_t *ftp, const cloud_ftp_config_t *cfg,
                              char *err, size_t err_sz) {
     memset(ftp, 0, sizeof(*ftp));
     ftp->ctrl = -1;

     ftp->ctrl = tcp_connect_host(cfg->host, cfg->port, err, err_sz);
     if (ftp->ctrl < 0) return -1;

     int code = ftp_read_response(ftp);
     if (code != 220) {
         snprintf(err, err_sz, "FTP greeting failed: %.120s", ftp->last);
         close(ftp->ctrl); ftp->ctrl = -1;
         return -1;
     }

     code = ftp_cmd_arg(ftp, "USER", cfg->user, err, err_sz);
     if (code == 331) {
         code = ftp_cmd_arg(ftp, "PASS", cfg->pass, err, err_sz);
     }
     if (code != 230) {
         snprintf(err, err_sz, "FTP login failed: %.120s (password length %zu)",
                  ftp->last, strlen(cfg->pass));
         close(ftp->ctrl); ftp->ctrl = -1;
         return -1;
     }

     code = ftp_cmd(ftp, "TYPE I", err, err_sz);
     if (code != 200) {
         snprintf(err, err_sz, "FTP binary mode failed: %.120s", ftp->last);
         close(ftp->ctrl); ftp->ctrl = -1;
         return -1;
     }

     struct sockaddr_in peer;
     socklen_t plen = sizeof(peer);
     if (getpeername(ftp->ctrl, (struct sockaddr *)&peer, &plen) == 0)
         inet_ntop(AF_INET, &peer.sin_addr, ftp->ctrl_host, sizeof(ftp->ctrl_host));
     else
         snprintf(ftp->ctrl_host, sizeof(ftp->ctrl_host), "%s", cfg->host);
     return 0;
 }

 static void ftp_close(ftp_client_t *ftp) {
     if (ftp->ctrl >= 0) {
         char err[64];
         ftp_cmd(ftp, "QUIT", err, sizeof(err));
         close(ftp->ctrl);
         ftp->ctrl = -1;
     }
 }

 static void ftp_clean_segment(char *seg) {
     for (char *p = seg; *p; p++) {
         if (*p == '\r' || *p == '\n') *p = '_';
     }
 }

 static int ftp_cwd_mkdirs(ftp_client_t *ftp, const char *path, char *err, size_t err_sz) {
     char tmp[512];
     snprintf(tmp, sizeof(tmp), "%s", path && path[0] ? path : "/");

     if (tmp[0] == '/') {
         int code = ftp_cmd(ftp, "CWD /", err, err_sz);
         if (code >= 400) {
             snprintf(err, err_sz, "FTP CWD / failed: %.120s", ftp->last);
             return -1;
         }
     }

     char *p = tmp;
     while (*p == '/') p++;
     while (*p) {
         char *slash = strchr(p, '/');
         if (slash) *slash = 0;
         if (p[0]) {
             ftp_clean_segment(p);
             char cmd[600];
             snprintf(cmd, sizeof(cmd), "CWD %s", p);
             int code = ftp_cmd(ftp, cmd, err, err_sz);
             if (code >= 400) {
                 snprintf(cmd, sizeof(cmd), "MKD %s", p);
                 code = ftp_cmd(ftp, cmd, err, err_sz);
                 if (code >= 400 && code != 550) {
                     snprintf(err, err_sz, "FTP MKD failed: %.120s", ftp->last);
                     return -1;
                 }
                 snprintf(cmd, sizeof(cmd), "CWD %s", p);
                 code = ftp_cmd(ftp, cmd, err, err_sz);
                 if (code >= 400) {
                     snprintf(err, err_sz, "FTP CWD failed: %.120s", ftp->last);
                     return -1;
                 }
             }
         }
         if (!slash) break;
         p = slash + 1;
         while (*p == '/') p++;
     }
     return 0;
 }

 static int ftp_pasv_connect(ftp_client_t *ftp, char *err, size_t err_sz) {
     int code = ftp_cmd(ftp, "PASV", err, err_sz);
     if (code != 227) {
         snprintf(err, err_sz, "FTP PASV failed: %.120s", ftp->last);
         return -1;
     }

     int h1, h2, h3, h4, p1, p2;
     char *lp = strchr(ftp->last, '(');
     if (!lp || sscanf(lp, "(%d,%d,%d,%d,%d,%d)", &h1, &h2, &h3, &h4, &p1, &p2) != 6) {
         snprintf(err, err_sz, "Cannot parse FTP PASV response");
         return -1;
     }
     char pasv_host[64];
     snprintf(pasv_host, sizeof(pasv_host), "%d.%d.%d.%d", h1, h2, h3, h4);
     int port = p1 * 256 + p2;

     /* Many local FTP servers advertise 127.0.0.1 or a WAN IP in PASV; use the
      * control peer address for the data connection when they differ. */
     const char *data_host = pasv_host;
     if (ftp->ctrl_host[0] &&
         (strcmp(pasv_host, "127.0.0.1") == 0 ||
          strcmp(pasv_host, "0.0.0.0") == 0 ||
          strcmp(pasv_host, ftp->ctrl_host) != 0)) {
         data_host = ftp->ctrl_host;
     }
     return tcp_connect_host(data_host, port, err, err_sz);
 }

 static int ftp_begin_stor(ftp_client_t *ftp, const char *remote_name,
                           char *err, size_t err_sz) {
     int data = ftp_pasv_connect(ftp, err, err_sz);
     if (data < 0) return -1;

     char safe_name[256];
     snprintf(safe_name, sizeof(safe_name), "%s", remote_name);
     ftp_clean_segment(safe_name);

     char cmd[384];
     snprintf(cmd, sizeof(cmd), "STOR %s", safe_name);
     int code = ftp_cmd(ftp, cmd, err, err_sz);
     if (code != 125 && code != 150) {
         snprintf(err, err_sz, "FTP STOR failed: %.120s", ftp->last);
         close(data);
         return -1;
     }
     return data;
 }

 static int ftp_finish_stor(ftp_client_t *ftp, int data_sock, char *err, size_t err_sz) {
     close(data_sock);
     int code = ftp_read_response(ftp);
     if (code != 226 && code != 250) {
         snprintf(err, err_sz, "FTP upload failed: %.120s", ftp->last);
         return -1;
     }
     return 0;
 }

 /* ── Save discovery ─────────────────────────────────────────────── */
 static void scan_title_dir(const char *title_path, const char *title_id, const char *uid) {
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

         /* For PS4 dirs, only pick up sdimg_ files */
         if (is_ps4 && strncmp(ent->d_name, "sdimg_", 6) != 0) continue;

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
             s->is_backup = (strncmp(ent->d_name, "sdimg_sce_bu_", 13) == 0);
             snprintf(s->user_id, sizeof(s->user_id), "%s", uid);
             s->is_usb = 0;
             /* Detect PS4 by byte 0x0 */
             s->is_ps4 = 0;
             int hfd = open(filepath, O_RDONLY);
             if (hfd >= 0) {
                 uint8_t hdr;
                 if (pread(hfd, &hdr, 1, 0) == 1 && hdr == 0x01) s->is_ps4 = 1;
                 close(hfd);
             }
             /* Old imports could leave a PS4 image in savedata_prospero
              * without its key. Prefer the complete re-import in savedata,
              * keeping the old file untouched instead of listing it twice. */
             if (!is_ps4 && s->is_ps4 && strncmp(ent->d_name, "sdimg_", 6) == 0) {
                 char correct_image[MAX_PATH_LEN], correct_key[MAX_PATH_LEN];
                 struct stat image_st, key_st;
                 snprintf(correct_image, sizeof(correct_image), "/user/home/%s/savedata/%s/%s", uid, title_id, ent->d_name);
                 snprintf(correct_key, sizeof(correct_key), "/user/home/%s/savedata/%s/%s.bin", uid, title_id, ent->d_name + 6);
                 if (stat(correct_image, &image_st) == 0 && S_ISREG(image_st.st_mode) &&
                     stat(correct_key, &key_st) == 0 && S_ISREG(key_st.st_mode) && key_st.st_size >= 96) {
                     uint8_t header = 0;
                     int correct_fd = open(correct_image, O_RDONLY);
                     int valid = correct_fd >= 0 && pread(correct_fd, &header, 1, 0) == 1 && header == 0x01;
                     if (correct_fd >= 0) close(correct_fd);
                     if (valid) {
                         logprintf("[GarlicMgr] Ignoring misplaced PS4 duplicate: %s (complete copy in savedata)\n", filepath);
                         g_save_count--;
                     }
                 }
             }
         }
     }
     closedir(d);
 }

 static void scan_savedata_prospero(const char *prospero_path, const char *uid) {
     DIR *d = opendir(prospero_path);
     if (!d) return;

     struct dirent *ent;
     while ((ent = readdir(d))) {
         if (ent->d_name[0] == '.') continue;

         char title_path[MAX_PATH_LEN];
         snprintf(title_path, sizeof(title_path), "%s/%s", prospero_path, ent->d_name);

         struct stat st;
         if (stat(title_path, &st) == 0 && S_ISDIR(st.st_mode))
             scan_title_dir(title_path, ent->d_name, uid);
     }
     closedir(d);
 }

 /* ── SFO types (parser defined later) ──────────────────────────── */
 typedef struct sfo_info {
     char title_id[16];
     char dir_name[64];
     char main_title[128];
     char sub_title[128];
     char detail[256];
     char game_title_id[16];
     uint32_t user_param;
     uint32_t list_param;
     int has_list_param;
     uint64_t blocks, system_blocks;
     uint64_t account_id;
     uint32_t user_id;
     uint32_t aid_offset;
     uint32_t uid_offset;
     char format[4];
 } sfo_info_t;
 /* Community SFOs may omit FORMAT or use "ob" (Apollo CUSA10812).
  * Keep the title's platform instead of treating every non-"obs" value as PS5. */
 static int sfo_is_ps4(const sfo_info_t *sfo, int fallback) {
     if (strncmp(sfo->title_id, "CUSA", 4) == 0) return 1;
     if (strncmp(sfo->title_id, "PPSA", 4) == 0) return 0;
     if (strcmp(sfo->format, "obs") == 0 || strcmp(sfo->format, "ob") == 0) return 1;
     if (strcmp(sfo->format, "ppr") == 0) return 0;
     return fallback;
 }
 static int parse_sfo(const char *path, sfo_info_t *info);

 static void scan_usb_saves(const char *garlic_path) {
     DIR *d = opendir(garlic_path);
     if (!d) return;
     struct dirent *ent;
     while ((ent = readdir(d))) {
         if (ent->d_name[0] == '.') continue;
         char title_path[MAX_PATH_LEN];
         snprintf(title_path, sizeof(title_path), "%s/%s", garlic_path, ent->d_name);
         struct stat st;
         if (stat(title_path, &st) < 0 || !S_ISDIR(st.st_mode)) continue;

         DIR *td = opendir(title_path);
         if (!td) continue;
         struct dirent *se;
         while ((se = readdir(td))) {
             if (se->d_name[0] == '.') continue;
             int len = strlen(se->d_name);
             if (len > 4 && strcmp(se->d_name + len - 4, ".bin") == 0) continue;

             char filepath[MAX_PATH_LEN];
             snprintf(filepath, sizeof(filepath), "%s/%s", title_path, se->d_name);
             struct stat fst;
             if (stat(filepath, &fst) < 0) continue;
             if (!S_ISREG(fst.st_mode) && !S_ISDIR(fst.st_mode)) continue;

             save_entry_t *s = save_alloc();
             if (!s) break;
             snprintf(s->path, sizeof(s->path), "%s", filepath);
             snprintf(s->title_id, sizeof(s->title_id), "%s", ent->d_name);
             snprintf(s->save_name, sizeof(s->save_name), "%s", se->d_name);
             snprintf(s->dir_name, sizeof(s->dir_name), "%s_%s", ent->d_name, se->d_name);
             s->is_backup = (strncmp(se->d_name, "sdimg_sce_bu_", 13) == 0);
             s->user_id[0] = 0;
             s->is_usb = 1;
             s->is_ps4 = 0;
             if (S_ISREG(fst.st_mode)) {
                 /* Encrypted image: PS4 if byte 0x0 == 0x01 */
                 int hfd = open(filepath, O_RDONLY);
                 if (hfd >= 0) {
                     uint8_t hdr;
                     if (pread(hfd, &hdr, 1, 0) == 1 && hdr == 0x01) s->is_ps4 = 1;
                     close(hfd);
                 }
             } else if (S_ISDIR(fst.st_mode)) {
                 /* Decrypted folder: check FORMAT in param.sfo — "obs"=PS4, "ppr"=PS5 */
                 char sfo[MAX_PATH_LEN];
                 snprintf(sfo, sizeof(sfo), "%s/sce_sys/param.sfo", filepath);
                 sfo_info_t sfo_info;
                 if (parse_sfo(sfo, &sfo_info) == 0 && sfo_is_ps4(&sfo_info, 0))
                     s->is_ps4 = 1;
             }
         }
         closedir(td);
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
             scan_savedata_prospero(prospero, ue->d_name);
             char ps4[MAX_PATH_LEN];
             snprintf(ps4, sizeof(ps4), "/user/home/%s/savedata", ue->d_name);
             scan_savedata_prospero(ps4, ue->d_name);
         }
         closedir(home);
     }

     /* /mnt/usb0-7/PS5/SAVEDATA/GARLIC/<TitleId>/<savefile> */
     for (int u = 0; u < 8; u++) {
         char usb_path[MAX_PATH_LEN];
         snprintf(usb_path, sizeof(usb_path), "/mnt/usb%d/PS5/SAVEDATA/GARLIC", u);
         scan_usb_saves(usb_path);
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
 /* dst lands at 0777 so files copied into a mounted PFS pass the game's
  * 0777 verification at save load. 0755 (or 0775 with default umask 022)
  * mounts + PPR-authenticates cleanly but the game flags the save as
  * corrupted — see garlic-worker v1.1.6. fchmod after open is defensive
  * against a future umask that would clear world-write bits. */
 static int copy_file(const char *src, const char *dst) {
     int sfd = open(src, O_RDONLY);
     if (sfd < 0) return -1;
     int dfd = open(dst, O_CREAT | O_WRONLY | O_TRUNC, 0777);
     if (dfd < 0) { int saved_errno = errno; close(sfd); errno = saved_errno; return -2; }
     fchmod(dfd, 0777);
     char *buf = malloc(BUF_SIZE);
     if (!buf) { close(sfd); close(dfd); errno = ENOMEM; return -3; }
     int result = 0, saved_errno = 0;
     for (;;) {
         ssize_t n = read(sfd, buf, BUF_SIZE);
         if (n < 0 && errno == EINTR) continue;
         if (n < 0) { result = -4; saved_errno = errno; break; }
         if (n == 0) break;
         ssize_t offset = 0;
         while (offset < n) {
             ssize_t written = write(dfd, buf + offset, (size_t)(n - offset));
             if (written < 0 && errno == EINTR) continue;
             if (written <= 0) {
                 result = -5; saved_errno = written < 0 ? errno : EIO;
                 break;
             }
             offset += written;
         }
         if (result < 0) break;
     }
     free(buf);
     close(sfd);
     if (close(dfd) < 0 && result == 0) { result = -5; saved_errno = errno; }
     if (result < 0) errno = saved_errno;
     return result;
 }

 /* ── Recursive directory copy ───────────────────────────────────── */
 static int copy_dir_recursive_impl(const char *src, const char *dst, int skip_sidecar) {
     if (mkdir(dst,0777) < 0 && errno != EEXIST) return -1;
     DIR *d=opendir(src);
     if (!d) return -1;
     int result=0;
     struct dirent *ent;
     while ((ent=readdir(d))) {
         if (ent->d_name[0] == '.' || (skip_sidecar && chives_is_sidecar(ent->d_name))) continue;
         char sp[MAX_PATH_LEN],dp[MAX_PATH_LEN];
         if (snprintf(sp,sizeof(sp),"%s/%s",src,ent->d_name) >= (int)sizeof(sp) ||
             snprintf(dp,sizeof(dp),"%s/%s",dst,ent->d_name) >= (int)sizeof(dp)) { result=-1; break; }
         struct stat st;
         if (stat(sp,&st) < 0 ||
             (S_ISDIR(st.st_mode) ? copy_dir_recursive_impl(sp,dp,0) : copy_file(sp,dp)) < 0) {
             result=-1; break;
         }
     }
     closedir(d);
     return result;
 }
 static int copy_dir_recursive(const char *src, const char *dst) {
     return copy_dir_recursive_impl(src,dst,0);
 }

 /* ── Base64 encode/decode ───────────────────────────────────────── */
 static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

 static int b64_encode(const uint8_t *in, size_t len, char *out, size_t out_sz) {
     size_t needed = 4 * ((len + 2) / 3) + 1;
     if (out_sz < needed) return -1;
     char *p = out;
     for (size_t i = 0; i < len; i += 3) {
         uint32_t v = (uint32_t)in[i] << 16;
         if (i + 1 < len) v |= (uint32_t)in[i+1] << 8;
         if (i + 2 < len) v |= (uint32_t)in[i+2];
         *p++ = b64_table[(v >> 18) & 0x3F];
         *p++ = b64_table[(v >> 12) & 0x3F];
         *p++ = (i + 1 < len) ? b64_table[(v >> 6) & 0x3F] : '=';
         *p++ = (i + 2 < len) ? b64_table[v & 0x3F] : '=';
     }
     *p = 0;
     return (int)(p - out);
 }

 static int b64_decode_char(char c) {
     if (c >= 'A' && c <= 'Z') return c - 'A';
     if (c >= 'a' && c <= 'z') return c - 'a' + 26;
     if (c >= '0' && c <= '9') return c - '0' + 52;
     if (c == '+') return 62;
     if (c == '/') return 63;
     return -1;
 }

 static int b64_decode(const char *in, size_t in_len, uint8_t *out, size_t out_sz) {
     size_t j = 0;
     for (size_t i = 0; i + 3 < in_len; i += 4) {
         if (in[i] == '=' || in[i] == 0) break;
         int a = b64_decode_char(in[i]);
         int b = b64_decode_char(in[i+1]);
         int c = (in[i+2] != '=') ? b64_decode_char(in[i+2]) : 0;
         int d = (in[i+3] != '=') ? b64_decode_char(in[i+3]) : 0;
         if (a < 0 || b < 0) break;
         if (j < out_sz) out[j++] = (a << 2) | (b >> 4);
         if (in[i+2] != '=' && j < out_sz) out[j++] = ((b & 0xF) << 4) | (c >> 2);
         if (in[i+3] != '=' && j < out_sz) out[j++] = ((c & 3) << 6) | d;
     }
     return (int)j;
 }

 /* ── Mount / unmount ────────────────────────────────────────────── */
 /* Protected metadata I/O lives in CMP/ps5param.c. */

 static int mount_save(int idx) {
     g_mount_error[0] = 0;
     if (g_mounted) return -1;
     ps5param_clear_cache(); g_image_fresh = 0;
     if (idx < 0 || idx >= g_save_count) return -2;

     save_entry_t *s = &g_saves[idx];
     const char *bname = strrchr(s->path, '/');
     bname = bname ? bname + 1 : s->path;

     /* Detect PS4 vs PS5 by reading byte 0 of image (0x01=PS4, 0x02=PS5) */
     int is_ps4 = 0;
     {
         int hfd = open(s->path, O_RDONLY);
         if (hfd >= 0) {
             uint8_t hdr;
             if (pread(hfd, &hdr, 1, 0) == 1 && hdr == 0x01) is_ps4 = 1;
             close(hfd);
         }
     }
     logprintf("[GarlicMgr] mount: %s detected as %s\n", bname, is_ps4 ? "PS4" : "PS5");

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
         if (is_ps4 && strncmp(bname, "sdimg_", 6) == 0) {
             const char *savename = bname + 6;
             char src_dir[MAX_PATH_LEN], src_bin[MAX_PATH_LEN], dst_bin[MAX_PATH_LEN];
             strncpy(src_dir, s->path, sizeof(src_dir) - 1);
             src_dir[sizeof(src_dir) - 1] = 0;
             char *sl = strrchr(src_dir, '/');
             if (sl) *(sl + 1) = 0;
             snprintf(src_bin, sizeof(src_bin), "%s%s.bin", src_dir, savename);
             snprintf(dst_bin, sizeof(dst_bin), "/data/save_files/%s.bin", savename);
             if (copy_file(src_bin, dst_bin) < 0) {
                 int copy_errno = errno;
                 snprintf(g_mount_error, sizeof(g_mount_error),
                          "Cannot copy PS4 key for %.80s/%.80s (errno=%d). Check the installed .bin companion.",
                          s->title_id, savename, copy_errno);
                 logprintf("[GarlicMgr] %s Source: %s Destination: %s\n", g_mount_error, src_bin, dst_bin);
                 /* Never try a leftover key belonging to another title/slot. */
                 unlink(dst_bin);
                 unlink(g_local_copy);
                 g_local_copy[0] = 0;
                 return -4;
             }
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
             snprintf(g_mount_error, sizeof(g_mount_error),
                      "Cannot open PS4 .bin key (errno=%d). Re-import the save with its companion key.", errno);
             logprintf("[GarlicMgr] mount: cannot open sealed key %s (errno=%d)\n", bin_path, errno);
             free(data);
             return -4;
         }
         int r = read(fd, data, 0x60);
         close(fd);
         if (r != 0x60) {
             snprintf(g_mount_error, sizeof(g_mount_error), "PS4 .bin key is incomplete: read %d of 96 bytes", r);
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
         if (fd < 0) {
             logprintf("[GarlicMgr] mount: cannot open %s (errno=%d)\n", mount_src, errno);
             free(data); return -4;
         }
         int ret = pread(fd, data, 0x60, 0x800);
         close(fd);
         if (ret != 0x60) {
             logprintf("[GarlicMgr] mount: short read key from %s (%d)\n", mount_src, ret);
             free(data); return -5;
         }
         logprintf("[GarlicMgr] mount: PS5 key from %s (keyset=%d)\n",
                mount_src, (data[9] << 8) | data[8]);

         int pfsmgr = open("/dev/pfsmgr", O_RDWR);
         if (pfsmgr < 0) {
             logprintf("[GarlicMgr] mount: cannot open /dev/pfsmgr (errno=%d)\n", errno);
             free(data); return -6;
         }
         ret = ioctl(pfsmgr, 0xc0845302, data);
         close(pfsmgr);
         if (ret >= 0) {
             memcpy(decrypted_key, data + 0x60, 0x20);
             key_ok = 1;
             logprintf("[GarlicMgr] mount: PS5 key decrypted OK\n");
         } else {
             logprintf("[GarlicMgr] mount: PS5 key decrypt failed (ret=%d, errno=%d)\n", ret, errno);
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

     /* PS5: recover the real param.sfo from the header blob before mounting */
     if (!is_ps4) {
         ps5param_capture_for_image(mount_src);
         save_key_cache_image(mount_src);
     }

     signal(SIGPIPE, SIG_DFL);
     int ret = sceFsMountSaveData(&mopt, mount_src, g_mount_point, decrypted_key);
     signal(SIGPIPE, SIG_IGN);

     if (ret >= 0) {
         logprintf("[GarlicMgr] Mounted OK (handle=%d, key_ok=%d)\n", ret, key_ok);
         snprintf(g_mounted_path, sizeof(g_mounted_path), "%s", s->path);
         g_mounted = 1;
         g_mounted_idx = idx;
         return 0;
     }
     snprintf(g_mount_error, sizeof(g_mount_error),
              "sceFsMountSaveData failed: %d (0x%x), %s, key_decrypted=%s, errno=%d",
              ret, ret, is_ps4 ? "PS4" : "PS5", key_ok ? "yes" : "no", errno);
     ps5param_clear_cache();
     logprintf("[GarlicMgr] Mount failed (0x%x, key_ok=%d, errno=%d: %s)\n", ret, key_ok, errno, strerror(errno));
     return ret;
 }

 int unmount_save(void) {
     if (!g_mounted) return -1;

     UmountOpt uopt;
     memset(&uopt, 0, sizeof(uopt));
     sceFsInitUmountSaveDataOpt(&uopt);
     int ret = sceFsUmountSaveData(&uopt, g_mount_point, 0, 0);
     if (ret < 0) {
         logprintf("[GarlicMgr] Native save unmount failed: 0x%x\n",ret);
         return ret;
     }
     sync();

     /* Copy modified save back to original location */
     if (g_local_copy[0] && g_mounted_path[0]) {
         printf("[GarlicMgr] Copying back %s -> %s\n", g_local_copy, g_mounted_path);
         copy_file(g_local_copy, g_mounted_path);
         unlink(g_local_copy);
     }

     g_mounted = 0;
     g_mounted_idx = -1;
     g_mounted_path[0] = 0;
     g_mount_point[0] = 0;
     g_local_copy[0] = 0;
     ps5param_clear_cache(); g_image_fresh = 0;
     return 0;
 }

 /* ── Mount by path (for uploaded files already on /data/) ──────── */
 int mount_by_path_at_checked(const char *path, const char *mount_point,
                                     int track, int require_key) {
     if (require_key) g_mount_error[0] = 0;
     if (track && g_mounted && unmount_save() < 0) return -12;
     if (track) { ps5param_clear_cache(); g_image_fresh = 0; }

     const char *bname = strrchr(path, '/');
     bname = bname ? bname + 1 : path;

     /* Detect PS4 vs PS5 by reading byte 0 (0x01=PS4, 0x02=PS5) */
     int is_ps4 = 0;
     {
         int hfd = open(path, O_RDONLY);
         if (hfd >= 0) {
             uint8_t hdr;
             if (pread(hfd, &hdr, 1, 0) == 1 && hdr == 0x01) is_ps4 = 1;
             close(hfd);
         }
     }
     if (track) g_enc_ps4 = is_ps4;
     logprintf("[GarlicMgr] mount_by_path: %s detected as %s\n", bname, is_ps4 ? "PS4" : "PS5");

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
         if (fd < 0) {
             if (require_key) snprintf(g_mount_error,sizeof(g_mount_error),"Cannot open new PS5 image for sealed-key recovery (errno=%d)",errno);
             free(data); return -1;
         }
         int ret = pread(fd, data, 0x60, 0x800);
         close(fd);
         if (ret != 0x60) {
             if (require_key) snprintf(g_mount_error,sizeof(g_mount_error),"Cannot read the generated PS5 sealed key at image offset 0x800");
             free(data); return -2;
         }

         int pfsmgr = open("/dev/pfsmgr", 2);
         if (pfsmgr < 0) {
             if (require_key) snprintf(g_mount_error,sizeof(g_mount_error),"Cannot open pfsmgr for new PS5 key recovery (errno=%d)",errno);
             free(data); return -3;
         }
         ret = ioctl(pfsmgr, 0xc0845302, data);
         int key_errno = errno;
         close(pfsmgr);
         if (ret >= 0) {
             memcpy(decrypted_key, data + 0x60, 0x20);
             key_ok = 1;
             if (require_key) logprintf("[GarlicMgr] Generated PS5 sealed key recovered; using recovered image key\n");
         } else if (require_key) {
             snprintf(g_mount_error,sizeof(g_mount_error),"New PS5 image key recovery failed: pfsmgr ret=%d errno=%d",ret,key_errno);
         }
     }

     free(data);

     if (!key_ok) {
         logprintf("[GarlicMgr] mount: key decryption failed for %s\n", path);
         if (require_key) {
             if (!g_mount_error[0]) snprintf(g_mount_error,sizeof(g_mount_error),"Generated PS5 image key recovery failed; zero-key fallback blocked");
             return -11;
         }
         /* Try mounting with zeroed key anyway */
     }

     mkdir(mount_point, 0777);

     MountOpt mopt;
     memset(&mopt, 0, sizeof(mopt));
     sceFsInitMountSaveDataOpt(&mopt);
     mopt.budgetid = "system";

     /* PS5: recover the real param.sfo from the header blob before mounting */
     if (track && !is_ps4) {
         ps5param_capture_for_image(path);
         save_key_cache_image(path);
     }

     signal(SIGPIPE, SIG_DFL);
     int ret = sceFsMountSaveData(&mopt, path, mount_point, decrypted_key);
     signal(SIGPIPE, SIG_IGN);

     if (ret >= 0) {
         logprintf("[GarlicMgr] mount: mounted %s (handle=%d, key_ok=%d)\n", path, ret, key_ok);
         if (track) {
             snprintf(g_mount_point, sizeof(g_mount_point), "%s", mount_point);
             snprintf(g_mounted_path, sizeof(g_mounted_path), "%s", path);
             g_local_copy[0] = 0;
             g_mounted_idx = -1;
             g_mounted = 1;
             g_image_fresh = require_key != 0;
         }
         return 0;
     }
     if (track) ps5param_clear_cache();
     logprintf("[GarlicMgr] mount: failed 0x%x (key_ok=%d)\n", ret, key_ok);
     return ret;
 }

 static int mount_by_path_at(const char *path, const char *mount_point, int track) {
     return mount_by_path_at_checked(path,mount_point,track,0);
 }

 static int mount_by_path(const char *path) {
     return mount_by_path_at(path, "/data/mount_sd", 1);
 }

 /* ── SFO parser ────────────────────────────────────────────────── */
 /* Parse an SFO already in memory (e.g. recovered from the PS5PARAM blob). */
 static int parse_sfo_mem(const uint8_t *buf, size_t size, sfo_info_t *info) {
     memset(info, 0, sizeof(*info));
     if (!buf || size < 20) return -1;

     /* Check if all zeros (corrupted) */
     int all_zero = 1;
     size_t check_len = size < 256 ? size : 256;
     for (size_t i = 0; i < check_len; i++) {
         if (buf[i] != 0) { all_zero = 0; break; }
     }
     if (all_zero) return -2;

     /* Check magic PSF\0 */
     if (buf[0] != 0x00 || buf[1] != 0x50 || buf[2] != 0x53 || buf[3] != 0x46)
         return -1;

     uint32_t key_off, data_off, n_entries;
     memcpy(&key_off, buf + 8, 4);
     memcpy(&data_off, buf + 12, 4);
     memcpy(&n_entries, buf + 16, 4);
     if (n_entries > (size - 20) / 16 || key_off >= size || data_off > size)
         return -1;

     for (uint32_t i = 0; i < n_entries; i++) {
         const uint8_t *idx = buf + 20 + i * 16;
         uint16_t koff;
         uint32_t param_len, doff;
         memcpy(&koff, idx, 2);
         memcpy(&param_len, idx + 4, 4);
         memcpy(&doff, idx + 12, 4);

         uint64_t key_pos = (uint64_t)key_off + koff;
         uint64_t val_pos = (uint64_t)data_off + doff;
         if (key_pos >= size || val_pos >= size) continue;

         size_t key_avail = size - (size_t)key_pos;
         const char *key = (const char *)(buf + key_pos);
         if (strnlen(key, key_avail) == key_avail) continue;

         size_t val_avail = size - (size_t)val_pos;
         uint32_t n = param_len <= val_avail ? param_len : (uint32_t)val_avail;
         const uint8_t *val = buf + val_pos;

         if (strcmp(key, "TITLE_ID") == 0)
             snprintf(info->title_id, sizeof(info->title_id), "%.*s", (int)n, (char*)val);
         else if (strcmp(key, "SAVEDATA_DIRECTORY") == 0)
             snprintf(info->dir_name, sizeof(info->dir_name), "%.*s", (int)n, (char*)val);
         else if (strcmp(key, "MAINTITLE") == 0 || strcmp(key, "TITLE") == 0)
             snprintf(info->main_title, sizeof(info->main_title), "%.*s", (int)n, (char*)val);
         else if (strcmp(key, "SUBTITLE") == 0)
             snprintf(info->sub_title, sizeof(info->sub_title), "%.*s", (int)n, (char*)val);
         else if (strcmp(key, "DETAIL") == 0)
             snprintf(info->detail, sizeof(info->detail), "%.*s", (int)n, (char*)val);
         else if (strcmp(key, "SAVEDATA_BLOCKS") == 0 && n >= 4)
             memcpy(&info->blocks, val, n >= 8 ? 8 : 4);
         else if (strcmp(key, "SYSTEM_BLOCKS") == 0 && n >= 4)
             memcpy(&info->system_blocks, val, n >= 8 ? 8 : 4);
         else if (strcmp(key, "PARAMS") == 0 || strcmp(key, "USER_PARAM") == 0) {
             if (n >= 4) memcpy(&info->user_param, val, 4);
         }
         else if (strcmp(key, "ACCOUNT_ID") == 0 && n >= 8)
             memcpy(&info->account_id, val, 8);
         else if (strcmp(key, "USER_ID") == 0 && n >= 4)
             memcpy(&info->user_id, val, 4);
         else if (strcmp(key, "FORMAT") == 0)
             snprintf(info->format, sizeof(info->format), "%.*s", (int)n, (char*)val);
         else if (strcmp(key, "SAVEDATA_LIST_PARAM") == 0 && n >= 4) {
             memcpy(&info->list_param, val, 4);
             info->has_list_param = 1;
         }
         else if (strcmp(key, "CATEGORY") == 0) {
             /* game_title_id from CATEGORY not needed, use title_id */
         }
     }
     /* Fall back to the legacy PARAMS field only when the SFO has no
      * SAVEDATA_LIST_PARAM entry. Slot 0 is a valid value, so presence must
      * be tracked separately. */
     if (!info->has_list_param)
         info->list_param = info->user_param;

     /* Default game_title_id to title_id */
     if (!info->game_title_id[0])
         strncpy(info->game_title_id, info->title_id, sizeof(info->game_title_id) - 1);

     return 0;
 }

 static int parse_sfo(const char *path, sfo_info_t *info) {
     memset(info, 0, sizeof(*info));
     int fd = open(path, O_RDONLY);
     if (fd < 0) return -1;

     struct stat st;
     if (fstat(fd, &st) < 0 || st.st_size < 20) { close(fd); return -1; }

     uint8_t *buf = malloc(st.st_size);
     if (!buf) { close(fd); return -1; }
     if (read(fd, buf, st.st_size) != st.st_size) { free(buf); close(fd); return -1; }
     close(fd);

     int ret = parse_sfo_mem(buf, st.st_size, info);
     free(buf);
     return ret;
 }


 /* CMP normal native image-key handling lives in CMP/native_key.c. */

 /* chives.json is host-side round-trip metadata, never a game-save file. */
 int chives_read_image(const char *image, chives_geometry_t *g) {
     uint8_t header[0x370];
     struct stat st;
     int fd = open(image, O_RDONLY);
     if (fd < 0) return -1;
     int ok = fstat(fd, &st) == 0 && st.st_size >= (off_t)sizeof(header) &&
         pread(fd, header, sizeof(header), 0) == (ssize_t)sizeof(header) &&
         chives_from_header(header, sizeof(header), (uint64_t)st.st_size, g) == 0;
     close(fd);
     return ok ? 0 : -1;
 }
 void chives_escape(const char *in, char *out, size_t cap) {
     size_t n = 0;
     while (*in && n + 2 < cap) {
         unsigned char c = (unsigned char)*in++;
         if (c == '"' || c == '\\') out[n++] = '\\';
         if (c >= 32) out[n++] = (char)c;
     }
     out[n] = 0;
 }
 static uint64_t chives_sfo_blocks_mem(const uint8_t *buf, size_t size, const char *field) {
     if (!sfo_bytes_valid(buf, size)) return 0;
     uint32_t keys, data, count;
     memcpy(&keys, buf + 8, 4); memcpy(&data, buf + 12, 4); memcpy(&count, buf + 16, 4);
     for (uint32_t i = 0; i < count; i++) {
         const uint8_t *e = buf + 20 + 16 * i;
         uint16_t k; uint32_t n, d;
         memcpy(&k, e, 2); memcpy(&n, e + 4, 4); memcpy(&d, e + 12, 4);
         if (!strcmp((const char *)buf + keys + k, field)) {
             if (n >= 8) return chives_le64(buf + data + d);
             if (n >= 4) return chives_le32(buf + data + d);
         }
     }
     return 0;
 }
 static uint64_t chives_sfo_blocks(const char *path, const char *field) {
     int fd = open(path, O_RDONLY);
     off_t pos;
     uint8_t b[8];
     uint64_t v = 0;
     if (fd < 0) return 0;
     if (sfo_field_offset(fd, field, 0, 8, &pos) == 0 && pread(fd,b,8,pos) == 8)
         v = chives_le64(b);
     else if (sfo_field_offset(fd, field, 0, 4, &pos) == 0 && pread(fd,b,4,pos) == 4)
         v = chives_le32(b);
     close(fd);
     return v;
 }
 static int chives_export_json(const char *image, const char *mount,
                                char *json, size_t cap) {
     /* PS4 round-tripping stays on the original path: its allocation layout
      * has not been validated with this PS5 fix's real-image fixtures. */
     uint8_t version[8];
     int vfd=open(image,O_RDONLY);
     if (vfd < 0) return -1;
     ssize_t vn=pread(vfd,version,sizeof(version),0);
     close(vfd);
     if (vn != (ssize_t)sizeof(version)) return -1;
     if (chives_le64(version) == 1) return 0;
     chives_geometry_t g;
     if (chives_read_image(image, &g) < 0) return -1;
     char path[MAX_PATH_LEN], title[96], directory[768], format[96];
     sfo_info_t sfo = {0};
     snprintf(path,sizeof(path),"%s/sce_sys/param.sfo",mount);
     int real_sfo = ps5param_cached_for_mount(mount) && !strcmp(image, ps5param_cache_image());
     if (real_sfo) parse_sfo_mem(ps5param_cache_data(), ps5param_cache_size(), &sfo);
     else parse_sfo(path,&sfo);
     uint64_t saved_blocks = real_sfo ? chives_sfo_blocks_mem(ps5param_cache_data(),
         ps5param_cache_size(),"SAVEDATA_BLOCKS") : chives_sfo_blocks(path,"SAVEDATA_BLOCKS");
     uint64_t system_blocks = real_sfo ? chives_sfo_blocks_mem(ps5param_cache_data(),
         ps5param_cache_size(),"SYSTEM_BLOCKS") : chives_sfo_blocks(path,"SYSTEM_BLOCKS");
     chives_escape(sfo.title_id,title,sizeof(title));
     chives_escape(sfo.dir_name,directory,sizeof(directory));
     chives_escape(sfo.format,format,sizeof(format));
     garlic_key_capture_t candidate;
     char crypto[GARLIC_KEY_JSON_BYTES] = {0};
     int key_available = 0;
     if (g_mounted) {
         key_available = save_key_cached_image(image,&candidate,&g.original_image_size_bytes);
     } else key_available = save_key_capture_image(image, &candidate, NULL) == 0;
     if (key_available && garlic_key_crypto_json(&candidate, crypto, sizeof(crypto)) < 0) {
         garlic_key_wipe(&candidate, sizeof(candidate)); return -1;
     }
     garlic_key_wipe(&candidate, sizeof(candidate));
     int n = snprintf(json,cap,
         "{\n  \"schema_version\": 1,\n  \"platform\": \"%s\",\n"
         "  \"title_id\": \"%s\",\n  \"save_directory\": \"%s\",\n"
         "  \"save_format\": \"%s\",\n  \"original_image_size_bytes\": %llu,\n"
         "  \"pfs\": {\n    \"version\": %llu,\n    \"block_size_bytes\": %u,\n"
         "    \"block_count\": %llu,\n    \"mode_raw\": %u,\n    \"backup_header_count\": %u, \"fs_ext\": %u\n  },\n"
         "  \"sfo\": {\"savedata_blocks\": %llu, \"system_blocks\": %llu}%s%s\n}\n",
         g.is_ps4 ? "PS4" : "PS5",title,directory,format,
         (unsigned long long)g.original_image_size_bytes,(unsigned long long)g.version,
         g.block_size_bytes,(unsigned long long)g.block_count,(unsigned)g.mode_raw,
         g.backup_header_count,g.fs_ext,(unsigned long long)saved_blocks,
         (unsigned long long)system_blocks, crypto[0] ? ",\n  \"crypto\": " : "", crypto);
     garlic_key_wipe(crypto, sizeof(crypto));
     return n > 0 && (size_t)n < cap ? n : -1;
 }
 static int chives_write_export(const char *image,const char *mount,const char *dest) {
     char json[2048],path[MAX_PATH_LEN];
     int n = chives_export_json(image,mount,json,sizeof(json));
     if (n < 0) return -1;
     if (!n) return 0;
     snprintf(path,sizeof(path),"%s/chives.json",dest);
     int fd = open(path,O_WRONLY|O_CREAT|O_TRUNC,0600);
     if (fd < 0) return -1;
     int ok = write(fd,json,(size_t)n) == n;
     if (close(fd) < 0) ok = 0;
     return ok ? 0 : -1;
 }
 static int chives_read_file(const char *base,chives_geometry_t *g) {
     char path[MAX_PATH_LEN],json[CHIVES_MAX_JSON+1];
     snprintf(path,sizeof(path),"%s/chives.json",base);
     int fd = open(path,O_RDONLY);
     if (fd < 0) return errno == ENOENT ? 0 : -1;
     struct stat st;
     int ok = fstat(fd,&st) == 0 && st.st_size > 0 && st.st_size <= CHIVES_MAX_JSON;
     ssize_t n = ok ? read(fd,json,(size_t)st.st_size) : -1;
     close(fd);
     return ok && n == st.st_size && chives_parse(json,(size_t)n,g) == 0 ? 1 : -1;
 }
 int chives_verify_created(const char *image,const chives_geometry_t *expected) {
     chives_geometry_t actual;
     if (chives_read_image(image,&actual) < 0) return -1;
     logprintf("[GarlicMgr] Created PFS: version=%llu block=%u blocks=%llu mode=0x%x backup=%u\n",
               (unsigned long long)actual.version,actual.block_size_bytes,
               (unsigned long long)actual.block_count,(unsigned)actual.mode_raw,
               actual.backup_header_count);
     if (actual.version != expected->version ||
         actual.block_size_bytes != expected->block_size_bytes ||
         actual.block_count != expected->block_count ||
         (expected->has_fs_ext && (!actual.has_fs_ext || actual.fs_ext != expected->fs_ext))) {
         logprintf("[GarlicMgr] Formatter did not preserve requested PFS geometry\n");
         return -1;
     }
     return 0;
 }
 static void chives_apply_opt(CreateOpt *opt,const chives_geometry_t *g) {
     /* mode_raw and backup_header_count are diagnostic data; they are not
      * interchangeable with formatter option flags. */
     opt->blockSize = (int)g->block_size_bytes;
 }

 /* CMP native creation/conversion and source provenance: CMP/pfs_rebuild.c. */

 /* Prefer an exact PS4 template, then try the user's other local saves.
  * Read a disposable image copy on a separate mount; never write the donor. */
 static int patch_local_sfo_owner(const char *path, const uint8_t account[8],
                                  uint32_t uid, int is_ps4) {
     if (!is_ps4) return patch_sfo_account(path, account, &uid);
     if (g_owner_mount_active) return -1;
     sfo_info_t incoming;
     if (parse_sfo(path, &incoming) < 0) return -1;
     uint8_t params[1024];
     const char *image = "/data/save_files/sdimg__owner_template";
     const char *key = "/data/save_files/_owner_template.bin";
     const char *point = "/data/mount_owner";
     for (int pass = 0; pass < 3; pass++) {
     for (int i = 0; i < g_save_count; i++) {
         const save_entry_t *save = &g_saves[i];
         const char *dir = save->save_name;
         if (strncmp(dir, "sdimg_", 6) == 0) dir += 6;
         int same_title = strcmp(save->title_id, incoming.title_id) == 0;
         int rank = same_title ? (strcmp(dir, incoming.dir_name) == 0 ? 0 : 1) : 2;
         if (!save->is_ps4 || save->is_usb || save->is_backup || rank != pass ||
             (uint32_t)strtoul(save->user_id, NULL, 16) != uid) continue;
         char key_src[MAX_PATH_LEN];
         snprintf(key_src, sizeof(key_src), "%s", save->path);
         char *base = strrchr(key_src, '/');
         if (!base) continue;
         snprintf(base + 1, sizeof(key_src) - (size_t)(base + 1 - key_src), "%s.bin", dir);
         mkdir("/data/save_files", 0777);
         if (copy_file(save->path, image) < 0 || copy_file(key_src, key) < 0) {
             unlink(image); unlink(key); continue;
         }
         if (mount_by_path_at(image, point, 0) < 0) {
             unlink(image); unlink(key); continue;
         }
         g_owner_mount_active = 1;
         char template_sfo[MAX_PATH_LEN];
         snprintf(template_sfo, sizeof(template_sfo), "%s/sce_sys/param.sfo", point);
         sfo_info_t donor;
         int valid = parse_sfo(template_sfo, &donor) == 0 &&
             strcmp(donor.title_id, save->title_id) == 0 &&
             strcmp(donor.dir_name, dir) == 0 &&
             sfo_read_owner_params(template_sfo, account, uid, params) == 0;
         UmountOpt opt;
         memset(&opt, 0, sizeof(opt));
         sceFsInitUmountSaveDataOpt(&opt);
         if (sceFsUmountSaveData(&opt, point, 0, 0) < 0) return -1;
         g_owner_mount_active = 0;
         unlink(image); unlink(key);
         if (!valid) continue;
         int patched = pass == 0 ? patch_sfo_owner_params(path, account, uid, params) :
                                   patch_sfo_owner_identity(path, account, uid, params);
         if (patched < 0) return -1;
         logprintf("[GarlicMgr] PS4 ownership %s from local %s/%s for user %x\n",
                   pass == 0 ? "restored" : "partially recovered (unverified)",
                   donor.title_id, donor.dir_name, uid);
         return pass == 0 ? 0 : 1;
     }
     }
     logprintf("[GarlicMgr] No local PS4 ownership template for %s/%s and user %x\n",
               incoming.title_id, incoming.dir_name, uid);
     return -2;
 }

 /* Import is best effort: unavailable ownership metadata is a warning, not
  * a reason to cancel copying the save. Normal mount/copy errors still fail. */
 static int patch_import_sfo_owner(const char *path, uint64_t original_aid,
                                   const char *uid_hex, uint32_t uid, int is_ps4,
                                   uint64_t *local_aid) {
     if (get_account_id_for_user(uid_hex, local_aid) < 0) {
         *local_aid = original_aid;
         return 4;
     }
     int result = patch_local_sfo_owner(path, (const uint8_t *)local_aid, uid, is_ps4);
     if (result >= 0) return result;
     if (patch_sfo_account(path, (const uint8_t *)local_aid, &uid) == 0) return 2;
     /* Try the account alone if a user field is absent. */
     if (patch_sfo_account(path, (const uint8_t *)local_aid, NULL) == 0) return 2;
     *local_aid = original_aid;
     sfo_info_t actual;
     if (parse_sfo(path, &actual) == 0) *local_aid = actual.account_id;
     return 3;
 }

 static const char *import_owner_warning(int result) {
     switch (result) {
         case 1: return "Owner identity recovered from another local save. Full ownership could not be verified; the game may report corrupt data.";
         case 2: return "Full ownership metadata unavailable. Imported with basic account/user changes only; the game may report corrupt data.";
         case 3: return "Ownership changes could not be verified. Imported anyway; the game may report corrupt data.";
         case 4: return "Selected user Account ID could not be read. Imported with original ownership; the game may report corrupt data.";
         default: return "";
     }
 }

 /* Per-user PARAMS HMAC cache.
  * The HMAC at PARAMS offset 0x08 (32 bytes) is identical across all saves
  * for the same user — we cache it from any valid param.sfo we encounter. */
 static uint8_t g_params_hmac[32] = {0};
 static int g_params_hmac_valid = 0;

 /* Try to extract and cache the PARAMS HMAC from a mounted save's param.sfo */
 static void cache_params_hmac(const char *sfo_path) {
     if (g_params_hmac_valid) return;
     int fd = open(sfo_path, O_RDONLY);
     if (fd < 0) return;
     uint8_t hdr[20];
     if (read(fd, hdr, 20) != 20) { close(fd); return; }
     if (hdr[0] != 0 || hdr[1] != 'P' || hdr[2] != 'S' || hdr[3] != 'F') { close(fd); return; }
     uint32_t koff, doff, nent;
     memcpy(&koff, hdr + 8, 4);
     memcpy(&doff, hdr + 12, 4);
     memcpy(&nent, hdr + 16, 4);
     for (uint32_t i = 0; i < nent; i++) {
         uint8_t idx[16];
         pread(fd, idx, 16, 20 + i * 16);
         uint16_t ko; memcpy(&ko, idx, 2);
         char kname[32] = {0};
         pread(fd, kname, 31, koff + ko);
         if (strcmp(kname, "PARAMS") == 0) {
             uint32_t d_off;
             memcpy(&d_off, idx + 12, 4);
             uint8_t candidate[32];
             pread(fd, candidate, 32, doff + d_off + 0x08);
             int valid = 0;
             for (int b = 0; b < 32; b++)
                 if (candidate[b]) { valid = 1; break; }
             if (valid) {
                 memcpy(g_params_hmac, candidate, 32);
                 g_params_hmac_valid = 1;
                 logprintf("[GarlicMgr] Cached PARAMS HMAC: %02x%02x%02x%02x...\n",
                           candidate[0], candidate[1], candidate[2], candidate[3]);
             }
             break;
         }
     }
     close(fd);
 }

 /* In-memory variant: PS5PARAM blobs are parsed without touching the PFS. */
 static void cache_params_hmac_mem(const uint8_t *buf, size_t size) {
     if (g_params_hmac_valid || !buf || size < 20) return;
     if (buf[0] != 0 || buf[1] != 'P' || buf[2] != 'S' || buf[3] != 'F') return;
     uint32_t koff, doff, nent;
     memcpy(&koff, buf + 8, 4);
     memcpy(&doff, buf + 12, 4);
     memcpy(&nent, buf + 16, 4);
     if (nent > (size - 20) / 16 || koff >= size || doff >= size) return;
     for (uint32_t i = 0; i < nent; i++) {
         const uint8_t *idx = buf + 20 + i * 16;
         uint16_t ko;
         uint32_t d_off, plen;
         memcpy(&ko, idx, 2);
         memcpy(&plen, idx + 4, 4);
         memcpy(&d_off, idx + 12, 4);
         uint64_t kpos = (uint64_t)koff + ko;
         if (kpos >= size) continue;
         if (strnlen((const char *)(buf + kpos), size - (size_t)kpos) == size - (size_t)kpos)
             continue;
         if (strcmp((const char *)(buf + kpos), "PARAMS") != 0) continue;
         uint64_t vpos = (uint64_t)doff + d_off + 0x08;
         if (plen < 0x28 || vpos + 32 > size) break;
         const uint8_t *candidate = buf + vpos;
         int valid = 0;
         for (int b = 0; b < 32; b++)
             if (candidate[b]) { valid = 1; break; }
         if (valid) {
             memcpy(g_params_hmac, candidate, 32);
             g_params_hmac_valid = 1;
             logprintf("[GarlicMgr] Cached PARAMS HMAC from blob: %02x%02x%02x%02x...\n",
                       candidate[0], candidate[1], candidate[2], candidate[3]);
         }
         break;
     }
 }

 /* Write an SFO buffer to a path (used to restore the real metadata into a
  * freshly mounted PFS so the rest of the pipeline sees the correct values). */
 static int install_sfo_file(const char *path, const uint8_t *buf, uint32_t len) {
     if (!path || !sfo_bytes_valid(buf, len)) return -1;
     int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0777);
     if (fd < 0) return -1;
     garlic_upload_t u = {.expected=len, .received=len, .crc=UINT32_C(0xffffffff)};
     uint8_t check[4096];
     garlic_upload_write(fd, buf, len, &u);
     if (garlic_upload_finish(fd, path, &u, check, sizeof(check)) < 0) return -1;
     logprintf("[GarlicMgr] Installed real param.sfo (%u B) -> %s\n", len, path);
     return 0;
 }

 /* Read the entire physical SFO, never a truncated prefix or cached pre-edit
  * metadata. Finalization uses this after ownership edits and before unmount. */
 int read_sfo_file(const char *path, uint8_t *buf, uint32_t cap) {
     int fd = open(path, O_RDONLY);
     if (fd < 0) return -1;
     struct stat st;
     int ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
         st.st_size >= 20 && (uint64_t)st.st_size <= cap;
     size_t total = 0, size = ok ? (size_t)st.st_size : 0;
     while (ok && total < size) {
         ssize_t n = read(fd, buf + total, size - total);
         if (n < 0 && errno == EINTR) continue;
         if (n <= 0) { ok = 0; break; }
         total += (size_t)n;
     }
     if (close(fd) < 0) ok = 0;
     int valid = ok && sfo_bytes_valid(buf, total);
     if (!valid)
         logprintf("[GarlicMgr] read_sfo_file failed: path=%s ok=%d bytes=%zu sfo_valid=%d\n",
                   path, ok, total, total ? sfo_bytes_valid(buf, total) : 0);
     return valid ? (int)total : -1;
 }

 /* A cached SFO belongs only to the currently tracked image and its canonical
  * metadata path. Other saves, PS4 donor mounts and small buffers cannot reuse it. */
 static int read_effective_param_sfo(const char *sfo_path, uint8_t *buf,
                                     uint32_t bufsize, int *from_blob) {
     if (from_blob) *from_blob = 0;
     if (!sfo_path || !buf) return -1;
     char expected[MAX_PATH_LEN];
     snprintf(expected, sizeof(expected), "%s/sce_sys/param.sfo", g_mount_point);
     if (!strcmp(sfo_path, expected) && ps5param_cached_for_mount(g_mount_point)) {
         if (ps5param_cache_size() > bufsize) return -1;
         memcpy(buf, ps5param_cache_data(), ps5param_cache_size());
         if (from_blob) *from_blob = 1;
         return (int)ps5param_cache_size();
     }
     return read_sfo_file(sfo_path, buf, bufsize);
 }

 /* CMP layout-aware PS5 metadata finalization: CMP/pfs_rebuild.c. */

 /* Measure the selected mount before unmounting; parent /data or another
  * filesystem's free space must never be used as this save's allocation. */
 static int save_payload_bytes(const char *base, uint64_t *total, unsigned depth) {
     if (depth > 64) return -1;
     DIR *dir = opendir(base); if (!dir) return -1;
     struct dirent *ent; int result = 0;
     while ((ent = readdir(dir))) {
         if (!strcmp(ent->d_name,".") || !strcmp(ent->d_name,"..")) continue;
         if (!depth && chives_is_sidecar(ent->d_name)) continue;
         char path[MAX_PATH_LEN]; struct stat st;
         int n = snprintf(path,sizeof(path),"%s/%s",base,ent->d_name);
         if (n < 0 || (size_t)n >= sizeof(path) || lstat(path,&st) < 0) { result=-1; break; }
         if (S_ISDIR(st.st_mode)) {
             if (save_payload_bytes(path,total,depth+1) < 0) { result=-1; break; }
         } else if (S_ISREG(st.st_mode)) {
             if (st.st_size < 0 || (uint64_t)st.st_size > UINT64_MAX - *total) { result=-1; break; }
             *total += (uint64_t)st.st_size;
         }
     }
     closedir(dir); return result;
 }
 static int capture_save_usage(const sfo_info_t *sfo, garlic_save_usage_t *usage) {
     if (!g_mounted || !g_mount_point[0]) return -1;
     uint64_t payload = 0, capacity = 0, unit = 0, blocks = 0, free_blocks = 0;
     if (save_payload_bytes(g_mount_point,&payload,0) < 0) return -1;
     struct statfs fs;
     if (statfs(g_mount_point,&fs) == 0 && !strcmp(fs.f_mntonname,g_mount_point) &&
         fs.f_bsize && fs.f_blocks && fs.f_bfree <= fs.f_blocks &&
         fs.f_blocks <= UINT64_MAX / fs.f_bsize) {
         unit=fs.f_bsize; blocks=fs.f_blocks; free_blocks=fs.f_bfree;
     }
     const char *image = g_local_copy[0] ? g_local_copy : g_mounted_path;
     chives_geometry_t geometry;
     if (image[0] && chives_read_image(image,&geometry) == 0)
         capacity=geometry.block_count*geometry.block_size_bytes;
     if (garlic_save_usage(sfo->blocks,sfo->system_blocks,unit,blocks,free_blocks,payload,capacity,usage) < 0) return -1;
     logprintf("[GarlicMgr] Save usage: blocks=%llu free=%llu occupied_KiB=%llu system_blocks=%llu (%s)\n",
         (unsigned long long)usage->blocks,(unsigned long long)usage->free_blocks,
         (unsigned long long)usage->size_kib,(unsigned long long)usage->system_blocks,
         usage->estimated ? "payload estimate" : "mounted filesystem");
     return 0;
 }

 /* Locate a real param.sfo anywhere under an extracted upload (the zip may be
  * rooted at <title_id>/<save_name>/).  Root-level sce_sys is checked first. */
 static int find_real_sfo(const char *base, char *out, size_t outsz, int depth) {
     if (!base || depth > 4) return -1;
     char p[MAX_PATH_LEN];
     snprintf(p, sizeof(p), "%s/sce_sys/param.sfo", base);
     int fd = open(p, O_RDONLY);
     if (fd >= 0) {
         struct stat st;
         if (fstat(fd, &st) == 0 && st.st_size >= 20 && st.st_size <= 0x8000) {
             uint8_t *b = malloc((size_t)st.st_size);
             if (b) {
                 ssize_t rn = read(fd, b, (size_t)st.st_size);
                 int ok = (rn == st.st_size && sfo_bytes_valid(b, (size_t)rn));
                 free(b);
                 if (ok) {
                     close(fd);
                     snprintf(out, outsz, "%s", p);
                     return 0;
                 }
             }
         }
         close(fd);
     }
     DIR *d = opendir(base);
     if (!d) return -1;
     struct dirent *e;
     int found = -1;
     while ((e = readdir(d))) {
         if (e->d_name[0] == '.') continue;
         char sub[MAX_PATH_LEN];
         snprintf(sub, sizeof(sub), "%s/%s", base, e->d_name);
         struct stat st;
         if (stat(sub, &st) == 0 && S_ISDIR(st.st_mode)) {
             if (find_real_sfo(sub, out, outsz, depth + 1) == 0) { found = 0; break; }
         }
     }
     closedir(d);
     return found;
 }

 static int mount_nested_save_image(const char *tmp,const char *mount) {
     char nested[MAX_PATH_LEN];
     snprintf(nested,sizeof(nested),"%s/save",mount);
     int fd=open(nested,O_RDONLY);
     if (fd < 0) return -1;
     uint8_t header[0x370];
     struct stat st;
     ssize_t got=fstat(fd,&st) == 0 && st.st_size >= (off_t)sizeof(header) ?
         read(fd,header,sizeof(header)) : -1;
     close(fd);
     chives_geometry_t geometry;
     if (got != (ssize_t)sizeof(header) ||
         chives_from_header(header,sizeof(header),(uint64_t)st.st_size,&geometry) < 0 ||
         geometry.is_ps4 || geometry.block_count*geometry.block_size_bytes != (uint64_t)st.st_size)
         return -1;
     const char *copy="/data/save_files/_tmp_nested";
     unlink(copy);
     if (copy_file(nested,copy) < 0) { unlink(copy); return -1; }
     sync();
     if (unmount_save() < 0 || rename(copy,tmp) < 0) { unlink(copy); return -1; }
     int ret=mount_by_path(tmp);
     if (ret >= 0)
         logprintf("[GarlicMgr] Imported nested PS5 save image from outer container\n");
     return ret;
 }

 /* ── Generate minimal param.sfo ────────────────────────────────── */
 static int generate_sfo(const char *path, const char *title_id, const char *dir_name,
                         const char *main_title, const char *sub_title,
                         uint64_t account_id, uint64_t blocks, uint64_t system_blocks,
                         uint32_t user_id, const char *game_title_id, int is_ps4,
                         const uint8_t *params_hmac) {
     /*
      * SFO format: header + index entries + key table + data table
      * All 15 standard PS5 save entries, matching real console output.
      * fmt: 0x0004 = raw binary, 0x0204 = utf8 string, 0x0404 = uint32
      */
     #define SFO_MAX 4096
     uint8_t buf[SFO_MAX];
     memset(buf, 0, sizeof(buf));

     const char *keys[] = {
         "ACCOUNT_ID", "ATTRIBUTE", "CATEGORY", "DETAIL", "FORMAT",
         "LINEAGE_ID", "MAINTITLE", "PARAMS", "SAVEDATA_BLOCKS",
         "SAVEDATA_DIRECTORY", "SAVEDATA_LIST_PARAM", "SAVEDATA_REVISION",
         "SUBTITLE", "SYSTEM_BLOCKS", "TITLE_ID"
     };
     int nkeys = 15;

     /* Calculate offsets */
     uint32_t key_off = 20 + nkeys * 16;
     uint32_t key_total = 0;
     for (int i = 0; i < nkeys; i++)
         key_total += strlen(keys[i]) + 1;
     uint32_t data_off = key_off + key_total;
     if (data_off % 4) data_off += 4 - (data_off % 4);

     /* Header */
     buf[0] = 0x00; buf[1] = 0x50; buf[2] = 0x53; buf[3] = 0x46;
     buf[4] = 0x01; buf[5] = 0x01;
     memcpy(buf + 8, &key_off, 4);
     memcpy(buf + 12, &data_off, 4);
     uint32_t ne = nkeys;
     memcpy(buf + 16, &ne, 4);

     /* Build key table */
     uint32_t kpos = 0;
     for (int i = 0; i < nkeys; i++) {
         size_t kl = strlen(keys[i]) + 1;
         memcpy(buf + key_off + kpos, keys[i], kl);
         kpos += kl;
     }

     const char *fmt_str = is_ps4 ? "obs" : "ppr";

     /* Build index + data */
     uint32_t dpos = 0;
     kpos = 0;
     for (int i = 0; i < nkeys; i++) {
         uint8_t *idx = buf + 20 + i * 16;
         uint16_t ko = kpos;
         memcpy(idx, &ko, 2);

         uint32_t param_len = 0, param_max = 0;
         uint16_t param_fmt = 0x0204;

         if (strcmp(keys[i], "ACCOUNT_ID") == 0) {
             param_fmt = 0x0004; param_len = 8; param_max = 8;
             memcpy(buf + data_off + dpos, &account_id, 8);
         } else if (strcmp(keys[i], "ATTRIBUTE") == 0) {
             param_fmt = 0x0404; param_len = 4; param_max = 4;
         } else if (strcmp(keys[i], "CATEGORY") == 0) {
             param_len = 3; param_max = 4;
             memcpy(buf + data_off + dpos, "sd", 3);
         } else if (strcmp(keys[i], "DETAIL") == 0) {
             param_len = 1; param_max = 1024;
         } else if (strcmp(keys[i], "FORMAT") == 0) {
             param_len = 3; param_max = 4;
             memcpy(buf + data_off + dpos, fmt_str, 3);
         } else if (strcmp(keys[i], "LINEAGE_ID") == 0) {
             param_fmt = 0x0004; param_len = 16; param_max = 16;
         } else if (strcmp(keys[i], "MAINTITLE") == 0) {
             const char *t = main_title && main_title[0] ? main_title : title_id;
             param_len = strlen(t) + 1; param_max = 128;
             if (param_len > param_max) param_len = param_max;
             memcpy(buf + data_off + dpos, t, param_len);
         } else if (strcmp(keys[i], "PARAMS") == 0) {
             param_fmt = 0x0004; param_len = 1024; param_max = 1024;
             /* PARAMS internal structure (psdevwiki + RE):
              * 0x00: reserved (0), 0x04: user_id, 0x08: HMAC (32B, needs key),
              * 0x28: flags (1), 0x2C: title_id (12B), 0x38: game_title_id (12B),
              * 0x54: unknown (2) */
             uint8_t *p = buf + data_off + dpos;
             uint32_t uid = user_id;
             memcpy(p + 0x04, &uid, 4);
             if (params_hmac) memcpy(p + 0x08, params_hmac, 32);
             uint32_t flags = 1;
             memcpy(p + 0x28, &flags, 4);
             strncpy((char *)(p + 0x2C), title_id, 12);
             const char *gtid = game_title_id && game_title_id[0] ? game_title_id : title_id;
             strncpy((char *)(p + 0x38), gtid, 12);
             uint32_t unk2 = 2;
             memcpy(p + 0x54, &unk2, 4);
         } else if (strcmp(keys[i], "SAVEDATA_BLOCKS") == 0) {
             param_fmt = 0x0004; param_len = 8; param_max = 8;
             memcpy(buf + data_off + dpos, &blocks, 8);
         } else if (strcmp(keys[i], "SAVEDATA_DIRECTORY") == 0) {
             const char *d = dir_name && dir_name[0] ? dir_name : "savedata0";
             param_len = strlen(d) + 1; param_max = 32;
             if (param_len > param_max) param_len = param_max;
             memcpy(buf + data_off + dpos, d, param_len);
         } else if (strcmp(keys[i], "SAVEDATA_LIST_PARAM") == 0) {
             param_fmt = 0x0404; param_len = 4; param_max = 4;
         } else if (strcmp(keys[i], "SAVEDATA_REVISION") == 0) {
             param_fmt = 0x0004; param_len = 16; param_max = 16;
         } else if (strcmp(keys[i], "SUBTITLE") == 0) {
             const char *st = sub_title && sub_title[0] ? sub_title : "";
             param_len = strlen(st) + 1; param_max = 128;
             if (param_len > param_max) param_len = param_max;
             memcpy(buf + data_off + dpos, st, param_len);
         } else if (strcmp(keys[i], "SYSTEM_BLOCKS") == 0) {
             param_fmt = 0x0004; param_len = 8; param_max = 8;
             memcpy(buf + data_off + dpos, &system_blocks, 8);
         } else if (strcmp(keys[i], "TITLE_ID") == 0) {
             param_len = strlen(title_id) + 1; param_max = 12;
             if (param_len > param_max) param_len = param_max;
             memcpy(buf + data_off + dpos, title_id, param_len);
         }

         memcpy(idx + 2, &param_fmt, 2);
         memcpy(idx + 4, &param_len, 4);
         memcpy(idx + 8, &param_max, 4);
         memcpy(idx + 12, &dpos, 4);
         dpos += param_max;
         kpos += strlen(keys[i]) + 1;
     }

     uint32_t total = data_off + dpos;
     int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0777);
     if (fd < 0) return -1;
     write(fd, buf, total);
     close(fd);
     logprintf("[GarlicMgr] Generated param.sfo: %s (title=%s dir=%s fmt=%s)\n",
               path, title_id, dir_name, fmt_str);
     return 0;
 }

 /* ── Recursive mkdir helper ────────────────────────────────────── */
 static void recursive_mkdir(const char *path) {
     char tmp[MAX_PATH_LEN];
     snprintf(tmp, sizeof(tmp), "%s", path);
     for (char *p = tmp + 1; *p; p++) {
         if (*p == '/') {
             *p = 0;
             mkdir(tmp, 0777);
             *p = '/';
         }
     }
     mkdir(tmp, 0777);
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

 /* A closed/aborted browser socket must stop output promptly; retry partial
  * sends rather than silently dropping the rest of a large buffer. */
 static int save_socket_send(int sock,const void *data,size_t size) {
     const unsigned char *p=data;
     while(size){
         ssize_t n=send(sock,p,size,0);
         if(n<0&&errno==EINTR)continue;
         if(n<=0)return -1;
         p+=(size_t)n;size-=(size_t)n;
     }
     return 0;
 }

 static void zip_send(int sock, const char *base, const char *metadata) {
     zip_entry_t *entries = malloc((MAX_ZIP_ENTRIES + 2) * sizeof(zip_entry_t));
     if (!entries) return;
     int count = 0;
     collect_files(base, "", entries, &count);
     int real_sfo = ps5param_cached_for_mount(base);
     if (real_sfo) {
         int found = 0;
         for (int i = 0; i < count; i++) if (ps5param_is_sfo_name(entries[i].name)) found = 1;
         if (!found) {
             memset(&entries[count], 0, sizeof(entries[count]));
             snprintf(entries[count].name, sizeof(entries[count].name), "sce_sys/param.sfo");
             entries[count++].size = ps5param_cache_size();
         }
     }
     if (metadata) {
         /* Replace a legacy on-disk sidecar with the current virtual record. */
         for (int i = 0; i < count; i++)
             if (chives_is_sidecar(entries[i].name)) entries[i--] = entries[--count];
         memset(&entries[count],0,sizeof(entries[count]));
         snprintf(entries[count].name,sizeof(entries[count].name),"chives.json");
         entries[count++].size = (uint32_t)strlen(metadata);
     }

     uint32_t offset = 0;
     for (int i = 0; i < count; i++) {
         zip_entry_t *e = &entries[i];
         e->offset = offset;
         uint16_t nlen = strlen(e->name);

         char fullpath[MAX_PATH_LEN];
         snprintf(fullpath, sizeof(fullpath), "%s/%s", base, e->name);
         int virtual_metadata = metadata && chives_is_sidecar(e->name);
         int virtual_sfo = real_sfo && ps5param_is_sfo_name(e->name);
         int fd = -1;
         uint8_t *fdata = NULL;
         if(virtual_metadata){
             fdata=malloc(e->size);if(fdata)memcpy(fdata,metadata,e->size);
         }else if(virtual_sfo){
             e->size=ps5param_cache_size();
             fdata=malloc(e->size);if(fdata)memcpy(fdata,ps5param_cache_data(),e->size);
         }else{
             fd=open(fullpath,O_RDONLY);
             if(fd>=0&&e->size>0){fdata=malloc(e->size);if(fdata){ssize_t nread=read(fd,fdata,e->size);(void)nread;}close(fd);}
             else if(fd>=0)close(fd);
         }
         if (e->size && !fdata) goto zip_done;
         e->crc = fdata ? calc_crc(fdata, e->size) : 0;

         uint8_t lh[30]; memset(lh, 0, 30);
         lh[0]=0x50; lh[1]=0x4b; lh[2]=0x03; lh[3]=0x04;
         lh[4]=20;
         memcpy(lh+14, &e->crc, 4);
         memcpy(lh+18, &e->size, 4);
         memcpy(lh+22, &e->size, 4);
         memcpy(lh+26, &nlen, 2);
         if(save_socket_send(sock,lh,30)<0||save_socket_send(sock,e->name,nlen)<0||
            (fdata&&save_socket_send(sock,fdata,e->size)<0)) {free(fdata);goto zip_done;}
         free(fdata);
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
         if(save_socket_send(sock,cd,46)<0||save_socket_send(sock,e->name,nlen)<0)goto zip_done;
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
     save_socket_send(sock,ecd,22);
 zip_done:
     free(entries);
 }

 /* ── Zip streaming for specific files by path ──────────────────── */
 typedef struct { const char *path; const char *name; } zip_file_t;

 typedef int (*zip_write_fn)(void *ctx, const void *buf, size_t len);
 typedef struct {
     zip_write_fn write;
     void *ctx;
     uint64_t bytes;
 } zip_sink_t;

 static int socket_zip_write(void *ctx, const void *buf, size_t len) {
     int sock = *(int *)ctx;
     return send_all_fd(sock, buf, len);
 }

 typedef struct {
     uint8_t *data;
     size_t len;
     size_t cap;
 } mem_buf_t;

 static int mem_zip_write(void *ctx, const void *buf, size_t len) {
     mem_buf_t *m = (mem_buf_t *)ctx;
     if (m->len + len > m->cap) {
         size_t newcap = m->cap ? m->cap * 2 : 1024 * 1024;
         while (newcap < m->len + len) newcap *= 2;
         uint8_t *p = realloc(m->data, newcap);
         if (!p) return -1;
         m->data = p;
         m->cap = newcap;
     }
     memcpy(m->data + m->len, buf, len);
     m->len += len;
     return 0;
 }

 static int zip_sink_write(zip_sink_t *sink, const void *buf, size_t len) {
     if (!sink || !sink->write) return -1;
     if (len == 0) return 0;
     if (sink->write(sink->ctx, buf, len) < 0) return -1;
     sink->bytes += len;
     return 0;
 }

 static int zip_write_files(zip_sink_t *sink, const zip_file_t *files, int nfiles, char *iobuf) {
     zip_entry_t *entries = malloc(nfiles * sizeof(zip_entry_t));
     if (!entries) return -1;

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
         lh[6]=0x08; /* flag: data descriptor follows — CRC+sizes must be 0 */
         memcpy(lh+26, &nlen, 2);
         if (zip_sink_write(sink, lh, 30) < 0 ||
             zip_sink_write(sink, e->name, nlen) < 0) {
             close(fd);
             free(entries);
             return -1;
         }

         uint32_t crc = 0xFFFFFFFF;
         char *buf = iobuf;
         ssize_t nr;
         while ((nr = read(fd, buf, BUF_SIZE)) > 0) {
             for (ssize_t j = 0; j < nr; j++) {
                 crc ^= (uint8_t)buf[j];
                 for (int k = 0; k < 8; k++)
                     crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
             }
             if (zip_sink_write(sink, buf, (size_t)nr) < 0) {
                 close(fd);
                 free(entries);
                 return -1;
             }
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
         if (zip_sink_write(sink, dd, 16) < 0) {
             free(entries);
             return -1;
         }

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
         if (zip_sink_write(sink, cd, 46) < 0 ||
             zip_sink_write(sink, e->name, nlen) < 0) {
             free(entries);
             return -1;
         }
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
     if (zip_sink_write(sink, ecd, 22) < 0) {
         free(entries);
         return -1;
     }
     free(entries);
     return 0;
 }

 static void zip_send_files(int sock, const zip_file_t *files, int nfiles, char *iobuf) {
     zip_sink_t sink;
     sink.write = socket_zip_write;
     sink.ctx = &sock;
     sink.bytes = 0;
     zip_write_files(&sink, files, nfiles, iobuf);
 }

 typedef struct {
     int is_title;
     int auto_job;
     save_entry_t save;
     char title_id[32];
 } cloud_job_args_t;

 static int cloud_start_job(cloud_job_args_t *job, char *err, size_t err_sz);

 static int file_zip_write(void *ctx, const void *buf, size_t len) {
     int fd = *(int *)ctx;
     const char *p = (const char *)buf;
     size_t off = 0;
     while (off < len) {
         ssize_t wr = write(fd, p + off, len - off);
         if (wr <= 0) return -1;
         off += (size_t)wr;
     }
     return 0;
 }

 static void cloud_timestamp(char *out, size_t out_sz) {
     time_t now = time(NULL);
     struct tm tmv;
     memset(&tmv, 0, sizeof(tmv));
     localtime_r(&now, &tmv);
     snprintf(out, out_sz, "%04d%02d%02d-%02d%02d%02d",
              tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
              tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
 }

 static void cloud_remote_dir(const cloud_config_t *cfg, const char *title_id,
                              const char *user_id, char *out, size_t out_sz) {
     const char *uid = (user_id && user_id[0]) ? user_id : "system";
     char base[512];
     snprintf(base, sizeof(base), "%s", cfg->ftp.remote_path[0] ? cfg->ftp.remote_path : "/");
     size_t len = strlen(base);
     while (len > 1 && base[len - 1] == '/') base[--len] = 0;
     snprintf(out, out_sz, "%s/%s/%s", base, title_id, uid);
 }

 static void cloud_backup_file_dir(const char *base_path, const char *title_id,
                                   const char *user_id, char *out, size_t out_sz) {
     const char *uid = (user_id && user_id[0]) ? user_id : "all";
     char base[MAX_PATH_LEN];
    snprintf(base, sizeof(base), "%s", base_path && base_path[0] ? base_path : BACKUP_DEFAULT_LOCAL_DIR);
     size_t len = strlen(base);
     while (len > 1 && base[len - 1] == '/') base[--len] = 0;
     snprintf(out, out_sz, "%s/%s/%s", base, title_id, uid);
 }

static int cloud_stage_zip_file(const char *filename, const zip_file_t *files, int nfiles,
                                char *iobuf, char *out_path, size_t out_path_sz,
                                char *err, size_t err_sz) {
    mkdir("/data", 0777);
    mkdir("/data/garlic", 0777);
    mkdir(BACKUP_TMP_DIR, 0777);
    char final_path[MAX_PATH_LEN], tmp_path[MAX_PATH_LEN];
    snprintf(final_path, sizeof(final_path), "%s/%s", BACKUP_TMP_DIR, filename);
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", final_path);

    int fd = open(tmp_path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0) {
        snprintf(err, err_sz, "Cannot create staging ZIP: %s", tmp_path);
        return -1;
    }

    zip_sink_t sink;
    sink.write = file_zip_write;
    sink.ctx = &fd;
    sink.bytes = 0;
    int zr = zip_write_files(&sink, files, nfiles, iobuf);
    if (zr < 0) {
        close(fd);
        unlink(tmp_path);
        snprintf(err, err_sz, "Failed while writing staging ZIP");
        return -1;
    }
    fsync(fd);
    close(fd);
    if (rename(tmp_path, final_path) < 0) {
        unlink(tmp_path);
        snprintf(err, err_sz, "Failed to finalize staging ZIP");
        return -1;
    }
    snprintf(out_path, out_path_sz, "%s", final_path);
    return 0;
}

static int cloud_copy_file_atomic(const char *src, const char *dst, char *err, size_t err_sz) {
    char tmp[MAX_PATH_LEN];
    snprintf(tmp, sizeof(tmp), "%s.tmp", dst);
    if (copy_file(src, tmp) < 0) {
        unlink(tmp);
        snprintf(err, err_sz, "Failed to copy backup file");
        return -1;
    }
    if (rename(tmp, dst) < 0) {
        unlink(tmp);
        snprintf(err, err_sz, "Failed to finalize backup file");
        return -1;
    }
    return 0;
}

static int cloud_copy_staged_zip_target(const char *stage_path, const char *base_path,
                                        const char *title_id, const char *user_id,
                                        const char *filename, char *out_path, size_t out_path_sz,
                                        char *err, size_t err_sz) {
    if (!base_path || !base_path[0]) {
        snprintf(err, err_sz, "Backup folder is not configured");
        return -1;
    }
    char dir[MAX_PATH_LEN];
    cloud_backup_file_dir(base_path, title_id, user_id, dir, sizeof(dir));
    recursive_mkdir(dir);
    char final_path[MAX_PATH_LEN];
    snprintf(final_path, sizeof(final_path), "%s/%s", dir, filename);
    if (cloud_copy_file_atomic(stage_path, final_path, err, err_sz) < 0) return -1;
    if (out_path && out_path_sz)
        snprintf(out_path, out_path_sz, "%s", final_path);
    return 0;
}

static int cloud_queue_staged_zip(const char *stage_path, const char *filename,
                                  char *err, size_t err_sz) {
    mkdir("/data", 0777);
    mkdir("/data/garlic", 0777);
    mkdir(CLOUD_QUEUE_DIR, 0777);
    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "%s/%s", CLOUD_QUEUE_DIR, filename);
    return cloud_copy_file_atomic(stage_path, path, err, err_sz);
}

static int cloud_upload_zip_file(const cloud_config_t *cfg, const char *remote_dir,
                                 const char *remote_name, const char *stage_path,
                                 char *iobuf, char *err, size_t err_sz) {
    ftp_client_t ftp;
    if (ftp_connect_login(&ftp, &cfg->ftp, err, err_sz) < 0) return -1;
    if (ftp_cwd_mkdirs(&ftp, remote_dir, err, err_sz) < 0) {
        ftp_close(&ftp);
        return -1;
    }
    int data_sock = ftp_begin_stor(&ftp, remote_name, err, err_sz);
    if (data_sock < 0) {
        ftp_close(&ftp);
        return -1;
    }
    int fd = open(stage_path, O_RDONLY);
    if (fd < 0) {
        close(data_sock);
        ftp_close(&ftp);
        snprintf(err, err_sz, "Cannot read staging ZIP");
        return -1;
    }
    ssize_t nr;
    while ((nr = read(fd, iobuf, BUF_SIZE)) > 0) {
        if (send_all_fd(data_sock, iobuf, (size_t)nr) < 0) {
            close(fd);
            close(data_sock);
            ftp_close(&ftp);
            snprintf(err, err_sz, "Failed while streaming staged ZIP to FTP");
            return -1;
        }
    }
    close(fd);
    if (nr < 0) {
        close(data_sock);
        ftp_close(&ftp);
        snprintf(err, err_sz, "Failed to read staging ZIP");
        return -1;
    }
    if (ftp_finish_stor(&ftp, data_sock, err, err_sz) < 0) {
        ftp_close(&ftp);
        return -1;
    }
    ftp_close(&ftp);
    return 0;
}

 static int cloud_build_single_files(const save_entry_t *s, zip_file_t *files,
                                     char names[][512], char *bin_path,
                                     int *nfiles) {
     *nfiles = 0;
     struct stat st;
     if (stat(s->path, &st) < 0 || !S_ISREG(st.st_mode)) return -1;

     snprintf(names[*nfiles], 512, "%s/%s", s->title_id, s->save_name);
     files[*nfiles].path = s->path;
     files[*nfiles].name = names[*nfiles];
     (*nfiles)++;

     if (s->is_ps4 && strncmp(s->save_name, "sdimg_", 6) == 0) {
         const char *savename = s->save_name + 6;
         char dir[MAX_PATH_LEN];
         strncpy(dir, s->path, sizeof(dir) - 1);
         dir[sizeof(dir) - 1] = 0;
         char *sl = strrchr(dir, '/');
         if (sl) *(sl + 1) = 0;
         snprintf(bin_path, MAX_PATH_LEN, "%s%s.bin", dir, savename);
         if (stat(bin_path, &st) == 0 && S_ISREG(st.st_mode)) {
             snprintf(names[*nfiles], 512, "%s/%s.bin", s->title_id, savename);
             files[*nfiles].path = bin_path;
             files[*nfiles].name = names[*nfiles];
             (*nfiles)++;
         }
     }
     return 0;
 }

 static int cloud_collect_title_files(const char *title_id, zip_file_t **out_files,
                                      char ***out_names, char ***out_allocs,
                                      int *out_nfiles, int *out_nallocs,
                                      char *err, size_t err_sz) {
     *out_files = NULL;
     *out_names = NULL;
     *out_allocs = NULL;
     *out_nfiles = 0;
     *out_nallocs = 0;

     zip_file_t *zfiles = malloc(g_save_count * 2 * sizeof(zip_file_t));
     char **names = malloc(g_save_count * 2 * sizeof(char *));
     char **allocs = malloc(g_save_count * sizeof(char *));
     if (!zfiles || !names || !allocs) {
         free(zfiles); free(names); free(allocs);
         snprintf(err, err_sz, "Out of memory");
         return -1;
     }

     int nfiles = 0, nallocs = 0;
     for (int i = 0; i < g_save_count; i++) {
         if (strcmp(g_saves[i].title_id, title_id) != 0 || g_saves[i].is_usb) continue;
         struct stat fst;
         if (stat(g_saves[i].path, &fst) < 0 || !S_ISREG(fst.st_mode)) continue;

         names[nfiles] = malloc(512);
         if (!names[nfiles]) continue;
         snprintf(names[nfiles], 512, "%s/%s", title_id, g_saves[i].save_name);
         zfiles[nfiles].path = g_saves[i].path;
         zfiles[nfiles].name = names[nfiles];
         nfiles++;

         if (g_saves[i].is_ps4 && strncmp(g_saves[i].save_name, "sdimg_", 6) == 0) {
             const char *savename = g_saves[i].save_name + 6;
             char dir[MAX_PATH_LEN];
             strncpy(dir, g_saves[i].path, sizeof(dir) - 1);
             dir[sizeof(dir) - 1] = 0;
             char *sl = strrchr(dir, '/');
             if (sl) *(sl + 1) = 0;
             char *bin_path = malloc(MAX_PATH_LEN);
             if (!bin_path) continue;
             snprintf(bin_path, MAX_PATH_LEN, "%s%s.bin", dir, savename);
             if (stat(bin_path, &fst) == 0 && S_ISREG(fst.st_mode)) {
                 names[nfiles] = malloc(512);
                 if (!names[nfiles]) { free(bin_path); continue; }
                 snprintf(names[nfiles], 512, "%s/%s.bin", title_id, savename);
                 zfiles[nfiles].path = bin_path;
                 zfiles[nfiles].name = names[nfiles];
                 allocs[nallocs++] = bin_path;
                 nfiles++;
             } else {
                 free(bin_path);
             }
         }
     }

     if (nfiles == 0) {
         free(zfiles); free(names); free(allocs);
         snprintf(err, err_sz, "No system saves found for this title");
         return -1;
     }

     *out_files = zfiles;
     *out_names = names;
     *out_allocs = allocs;
     *out_nfiles = nfiles;
     *out_nallocs = nallocs;
     return 0;
 }

 static void cloud_free_title_files(char **names, char **allocs, int nfiles, int nallocs,
                                    zip_file_t *zfiles) {
     if (names) for (int i = 0; i < nfiles; i++) free(names[i]);
     if (allocs) for (int i = 0; i < nallocs; i++) free(allocs[i]);
     free(names);
     free(allocs);
     free(zfiles);
 }

 static int cloud_zip_files_to_memory(const zip_file_t *files, int nfiles, char *iobuf,
                                      mem_buf_t *out, char *err, size_t err_sz) {
     memset(out, 0, sizeof(*out));
     zip_sink_t sink;
     sink.write = mem_zip_write;
     sink.ctx = out;
     sink.bytes = 0;
     if (zip_write_files(&sink, files, nfiles, iobuf) < 0) {
         free(out->data);
         memset(out, 0, sizeof(*out));
         snprintf(err, err_sz, "Failed to package backup ZIP");
         return -1;
     }
     return 0;
 }

 static int cloud_package_single(int idx, char *iobuf, mem_buf_t *out,
                                 char *filename, size_t filename_sz,
                                 char *err, size_t err_sz) {
     scan_saves();
     if (idx < 0 || idx >= g_save_count || g_saves[idx].is_usb) {
         snprintf(err, err_sz, "Invalid system save index");
         return -1;
     }
     save_entry_t *s = &g_saves[idx];
     zip_file_t files[2];
     char names[2][512];
     char bin_path[MAX_PATH_LEN] = {0};
     int nfiles = 0;
     if (cloud_build_single_files(s, files, names, bin_path, &nfiles) < 0) {
         snprintf(err, err_sz, "Cannot read save file");
         return -1;
     }
     char stamp[32], safe_save[128];
     cloud_timestamp(stamp, sizeof(stamp));
     snprintf(safe_save, sizeof(safe_save), "%s", s->save_name);
     sanitize_filename(safe_save);
     snprintf(filename, filename_sz, "%s_%s_%s_enc.zip", stamp, s->title_id, safe_save);
     sanitize_filename(filename);
     return cloud_zip_files_to_memory(files, nfiles, iobuf, out, err, err_sz);
 }

 static int cloud_package_title(const char *title_id, char *iobuf, mem_buf_t *out,
                                char *filename, size_t filename_sz,
                                char *err, size_t err_sz) {
     scan_saves();
     zip_file_t *zfiles = NULL;
     char **names = NULL, **allocs = NULL;
     int nfiles = 0, nallocs = 0;
     if (cloud_collect_title_files(title_id, &zfiles, &names, &allocs,
                                   &nfiles, &nallocs, err, err_sz) < 0) {
         return -1;
     }
     char stamp[32];
     cloud_timestamp(stamp, sizeof(stamp));
     snprintf(filename, filename_sz, "%s_%s_all_enc.zip", stamp, title_id);
     sanitize_filename(filename);
     int ret = cloud_zip_files_to_memory(zfiles, nfiles, iobuf, out, err, err_sz);
     cloud_free_title_files(names, allocs, nfiles, nallocs, zfiles);
     return ret;
 }

 typedef struct {
     char title_id[32];
     uint64_t sig;
 } auto_snapshot_t;

 typedef struct {
     int watcher_running;
     int lnc_available;
     int lnc_saw_title;
     int fallback_mode;
     char current_title[32];
     char last_closed[32];
     char last_result[256];
     time_t last_event;
 } auto_state_t;

 static pthread_mutex_t g_auto_mtx = PTHREAD_MUTEX_INITIALIZER;
 static auto_state_t g_auto_state = {0};
 static auto_snapshot_t g_auto_snaps[CLOUD_MAX_TITLES];
 static int g_auto_snap_count = 0;

 static int g_lnc_saw_title = 0;

 static void auto_set_result(const char *title_id, const char *fmt, ...) {
     pthread_mutex_lock(&g_auto_mtx);
     if (title_id) snprintf(g_auto_state.last_closed, sizeof(g_auto_state.last_closed), "%s", title_id);
     g_auto_state.last_event = time(NULL);
     va_list ap;
     va_start(ap, fmt);
     vsnprintf(g_auto_state.last_result, sizeof(g_auto_state.last_result), fmt, ap);
     va_end(ap);
     pthread_mutex_unlock(&g_auto_mtx);
 }

 static int auto_get_running_title(char *title_id, size_t title_sz, int *out_app_id) {
     title_id[0] = 0;
     if (out_app_id) *out_app_id = 0;
     int app_id = sceSystemServiceGetAppIdOfRunningBigApp();
     if (app_id <= 0) return 0;
     char tid[16] = {0};
     sceLncUtilGetAppTitleId((unsigned int)app_id, tid);
     if (!tid[0]) return 0;
     snprintf(title_id, title_sz, "%s", tid);
     if (out_app_id) *out_app_id = app_id;
     return 1;
 }

 static auto_snapshot_t *auto_snapshot_for(const char *title_id) {
     for (int i = 0; i < g_auto_snap_count; i++)
         if (strcmp(g_auto_snaps[i].title_id, title_id) == 0) return &g_auto_snaps[i];
     if (g_auto_snap_count >= CLOUD_MAX_TITLES) return NULL;
     auto_snapshot_t *s = &g_auto_snaps[g_auto_snap_count++];
     memset(s, 0, sizeof(*s));
     snprintf(s->title_id, sizeof(s->title_id), "%s", title_id);
     return s;
 }

 static uint64_t auto_title_signature(const char *title_id) {
     uint64_t sig = 1469598103934665603ULL;
     for (int i = 0; i < g_save_count; i++) {
         save_entry_t *s = &g_saves[i];
         if (s->is_usb || strcmp(s->title_id, title_id) != 0) continue;
         struct stat st;
         if (stat(s->path, &st) < 0) continue;
         const unsigned char *p = (const unsigned char *)s->save_name;
         while (*p) { sig ^= *p++; sig *= 1099511628211ULL; }
         p = (const unsigned char *)s->user_id;
         while (*p) { sig ^= *p++; sig *= 1099511628211ULL; }
         sig ^= (uint64_t)st.st_size; sig *= 1099511628211ULL;
         sig ^= (uint64_t)st.st_mtime; sig *= 1099511628211ULL;
     }
     return sig;
 }

 static int cloud_queue_count(void) {
     int count = 0;
     DIR *d = opendir(CLOUD_QUEUE_DIR);
     if (!d) return 0;
     struct dirent *ent;
     while ((ent = readdir(d))) {
         size_t len = strlen(ent->d_name);
         if (len > 4 && strcmp(ent->d_name + len - 4, ".zip") == 0) count++;
     }
     closedir(d);
     return count;
 }

 static int auto_trigger_title(const char *title_id, const cloud_config_t *cfg) {
     if(garlic_lifecycle_stopping())return -1;
     char err[256] = {0};
     if (!cloud_title_is_watched(cfg, title_id)) return 0;
     if (cfg->targets.local.enabled || cfg->targets.usb.enabled || cfg->targets.ftp_enabled ||
         (cfg->targets.drive_enabled && cfg->auto_backup.queue_for_browser_drive &&
          strcmp(cfg->drive.mode, "browser") == 0)) {
         cloud_job_args_t *job = calloc(1, sizeof(*job));
         if (!job) { auto_set_result(title_id, "Auto backup failed: out of memory"); return -1; }
         job->is_title = 1;
         job->auto_job = 1;
         snprintf(job->title_id, sizeof(job->title_id), "%s", title_id);
         if (cloud_start_job(job, err, sizeof(err)) < 0) {
             free(job);
             auto_set_result(title_id, "Auto backup failed: %s", err);
             return -1;
         }
         auto_set_result(title_id, "Auto backup started");
         return 0;
     }
     auto_set_result(title_id, "Auto backup skipped: no enabled backup targets");
     return 0;
 }

 static void auto_snapshot_title_locked(const char *title_id) {
     auto_snapshot_t *snap = auto_snapshot_for(title_id);
     if (!snap) return;
     snap->sig = auto_title_signature(title_id);
 }

 static void auto_on_title_closed(const char *closed, const cloud_config_t *cfg) {
     auto_set_result(closed, "Detected title close; waiting %ds for save settle",
                     cfg->auto_backup.settle_seconds);
     logprintf("[GarlicMgr] Auto: title closed %s, settling %ds\n",
               closed, cfg->auto_backup.settle_seconds);
     if(garlic_lifecycle_pause((unsigned)cfg->auto_backup.settle_seconds))return;
     pthread_mutex_lock(&g_mtx);
     if(garlic_lifecycle_stopping()){pthread_mutex_unlock(&g_mtx);return;}
     scan_saves();
     auto_snapshot_t *snap = auto_snapshot_for(closed);
     uint64_t sig = auto_title_signature(closed);
     int changed = (!snap || sig != snap->sig);
     if (snap) snap->sig = sig;
     pthread_mutex_unlock(&g_mtx);
     if (changed) {
         logprintf("[GarlicMgr] Auto: saves changed for %s, uploading\n", closed);
         auto_trigger_title(closed, cfg);
     } else {
         auto_set_result(closed, "No save changes detected after close");
         logprintf("[GarlicMgr] Auto: no save changes for %s\n", closed);
     }
 }

 static void *auto_watcher_thread(void *arg) {
     (void)arg;
     char last_running[32] = {0};
     int last_app_id = 0;
     pthread_mutex_lock(&g_auto_mtx);
     g_auto_state.watcher_running = 1;
     g_auto_state.lnc_available = 1;
     g_auto_state.fallback_mode = 0;
     pthread_mutex_unlock(&g_auto_mtx);

     while (!garlic_lifecycle_stopping()) {
         if (g_resume_pending) {
             g_resume_pending = 0;
             pthread_mutex_lock(&g_mtx);
             if(garlic_lifecycle_stopping()){pthread_mutex_unlock(&g_mtx);break;}
             scan_saves();
             pthread_mutex_unlock(&g_mtx);
             auto_set_result(NULL, "Console resumed; rescanned saves");
             logprintf("[GarlicMgr] Auto: console resumed, rescanned saves\n");
         }

         cloud_config_t cfg;
         char err[256] = {0};
         if (cloud_load_config(&cfg, err, sizeof(err)) == 0 && cfg.enabled && cfg.auto_backup.enabled) {
             char running[32] = {0};
             int app_id = 0;
             int has_running = auto_get_running_title(running, sizeof(running), &app_id);
             int watched = has_running && cloud_title_is_watched(&cfg, running);

             pthread_mutex_lock(&g_auto_mtx);
             snprintf(g_auto_state.current_title, sizeof(g_auto_state.current_title),
                      "%s", has_running ? running : "");
             if (watched) {
                 g_lnc_saw_title = 1;
                 g_auto_state.lnc_saw_title = 1;
             }
             pthread_mutex_unlock(&g_auto_mtx);

             if (watched) {
                 if (strcmp(last_running, running) != 0 || last_app_id != app_id) {
                     pthread_mutex_lock(&g_mtx);
                     if(garlic_lifecycle_stopping()){pthread_mutex_unlock(&g_mtx);break;}
                     scan_saves();
                     auto_snapshot_title_locked(running);
                     pthread_mutex_unlock(&g_mtx);
                     snprintf(last_running, sizeof(last_running), "%s", running);
                     last_app_id = app_id;
                     auto_set_result(running, "Watching running title %s", running);
                     logprintf("[GarlicMgr] Auto: watching %s (app 0x%x)\n", running, app_id);
                 }
             } else if (last_running[0] && (!has_running || app_id != last_app_id)) {
                 char closed[32];
                 snprintf(closed, sizeof(closed), "%s", last_running);
                 last_running[0] = 0;
                 last_app_id = 0;
                 auto_on_title_closed(closed, &cfg);
             }
             if(garlic_lifecycle_pause((unsigned)cfg.auto_backup.poll_seconds))break;
         } else {
             pthread_mutex_lock(&g_auto_mtx);
             g_auto_state.current_title[0] = 0;
             if (err[0]) snprintf(g_auto_state.last_result, sizeof(g_auto_state.last_result), "%s", err);
             pthread_mutex_unlock(&g_auto_mtx);
             if(garlic_lifecycle_pause(5))break;
         }
     }
     return NULL;
 }

 static void *garlic_lifecycle_watcher(void *arg) {
     void *result=auto_watcher_thread(arg);garlic_lifecycle_set_watcher_active(0);return result;
 }
 static void start_auto_watcher(void) {
     pthread_t tid;
     pthread_attr_t attr;
     pthread_attr_init(&attr);
     pthread_attr_setstacksize(&attr, 2 * 1024 * 1024);
     garlic_lifecycle_set_watcher_active(1);
     if (pthread_create(&tid, &attr, garlic_lifecycle_watcher, NULL) == 0) pthread_detach(tid);
     else garlic_lifecycle_set_watcher_active(0);
     pthread_attr_destroy(&attr);
 }

 static void *cloud_upload_thread(void *arg) {
     cloud_job_args_t *job = (cloud_job_args_t *)arg;
     char err[256] = {0};
     char remote_dir[768] = {0};
     char remote_name[256] = {0};
     char remote_full[1024] = {0};
     cloud_config_t cfg;

     if (cloud_load_config(&cfg, err, sizeof(err)) < 0) {
         cloud_set_done(0, err, NULL);
         free(job);
         return NULL;
     }
     if (!cfg.enabled) {
         cloud_set_done(0, "Cloud backup is disabled in config", NULL);
         free(job);
         return NULL;
     }
     char *iobuf = malloc(BUF_SIZE);
     if (!iobuf) {
         cloud_set_done(0, "Out of memory", NULL);
         free(job);
         return NULL;
     }

     pthread_mutex_lock(&g_mtx);
     if (g_mounted) unmount_save();
     scan_saves();
     cloud_set_progress(10, NULL);

     int ret = -1;
     int mtx_locked = 1;
     zip_file_t *upload_files = NULL;
     int upload_nfiles = 0;
     zip_file_t *zfiles = NULL;
     char **names = NULL, **allocs = NULL;
     int nfiles = 0, nallocs = 0;
     char **path_copies = NULL;
     int path_copy_count = 0;
     zip_file_t files[2];
     char file_names[2][512];
     char bin_path[MAX_PATH_LEN] = {0};

     if (job->is_title) {
         if (!cloud_title_is_watched(&cfg, job->title_id)) {
             snprintf(err, sizeof(err), "Title %s is not in watch_titles", job->title_id);
         } else if (cloud_collect_title_files(job->title_id, &zfiles, &names, &allocs,
                                               &nfiles, &nallocs, err, sizeof(err)) == 0) {
             char stamp[32];
             cloud_timestamp(stamp, sizeof(stamp));
             cloud_remote_dir(&cfg, job->title_id, "all", remote_dir, sizeof(remote_dir));
             snprintf(remote_name, sizeof(remote_name), "%s_%s_all_enc.zip", stamp, job->title_id);
             sanitize_filename(remote_name);
             snprintf(remote_full, sizeof(remote_full), "%s/%s", remote_dir, remote_name);
             cloud_set_progress(25, remote_full);
             path_copies = calloc((size_t)nfiles, sizeof(char *));
             if (!path_copies) {
                 snprintf(err, sizeof(err), "Out of memory");
             } else {
                 for (int i = 0; i < nfiles; i++) {
                     path_copies[i] = strdup(zfiles[i].path);
                     if (!path_copies[i]) {
                         snprintf(err, sizeof(err), "Out of memory");
                         break;
                     }
                     zfiles[i].path = path_copies[i];
                 }
                 if (!err[0]) {
                     upload_files = zfiles;
                     upload_nfiles = nfiles;
                     path_copy_count = nfiles;
                 }
             }
         }
     } else {
         save_entry_t *s = NULL;
         for (int i = 0; i < g_save_count; i++) {
             if (!g_saves[i].is_usb &&
                 strcmp(g_saves[i].path, job->save.path) == 0 &&
                 strcmp(g_saves[i].title_id, job->save.title_id) == 0) {
                 s = &g_saves[i];
                 break;
             }
         }
         if (!s) {
             snprintf(err, sizeof(err), "Save no longer exists");
         } else if (!cloud_title_is_watched(&cfg, s->title_id)) {
             snprintf(err, sizeof(err), "Title %s is not in watch_titles", s->title_id);
         } else if (cloud_build_single_files(&job->save, files, file_names, bin_path, &nfiles) == 0) {
             char stamp[32], safe_save[128];
             cloud_timestamp(stamp, sizeof(stamp));
             snprintf(safe_save, sizeof(safe_save), "%s", s->save_name);
             sanitize_filename(safe_save);
             cloud_remote_dir(&cfg, s->title_id, s->user_id, remote_dir, sizeof(remote_dir));
             snprintf(remote_name, sizeof(remote_name), "%s_%s_%s_enc.zip",
                      stamp, s->title_id, safe_save);
             sanitize_filename(remote_name);
             snprintf(remote_full, sizeof(remote_full), "%s/%s", remote_dir, remote_name);
             cloud_set_progress(25, remote_full);
             upload_files = files;
             upload_nfiles = nfiles;
         } else {
             snprintf(err, sizeof(err), "Cannot read save file");
         }
     }

     if (mtx_locked) {
         pthread_mutex_unlock(&g_mtx);
         mtx_locked = 0;
     }

    int final_success_count = 0, final_target_count = 0;
    if (upload_files && upload_nfiles > 0 && !err[0]) {
        int success_count = 0, fail_count = 0, target_done = 0;
        int target_total = 0;
        char target_path[MAX_PATH_LEN] = {0};
        char stage_path[MAX_PATH_LEN] = {0};
        char all_paths[1024] = {0};
        char target_err[256] = {0};
        char step_msg[128] = {0};
        const char *target_title = job->is_title ? job->title_id : job->save.title_id;
        const char *target_user = job->is_title ? "all" : job->save.user_id;
        int drive_queue_enabled = job->auto_job && cfg.targets.drive_enabled &&
                                  cfg.auto_backup.queue_for_browser_drive &&
                                  job->is_title && strcmp(cfg.drive.mode, "browser") == 0;

        if (cfg.targets.local.enabled) target_total++;
        if (cfg.targets.usb.enabled) target_total++;
        if (cfg.targets.ftp_enabled) target_total++;
        if (drive_queue_enabled) target_total++;
        final_target_count = target_total;

        if (target_total <= 0) {
            snprintf(err, sizeof(err), "No backup targets are enabled");
            ret = -1;
        } else {
            cloud_set_step(30, "Packaging backup ZIP", remote_full);
            if (cloud_stage_zip_file(remote_name, upload_files, upload_nfiles, iobuf,
                                     stage_path, sizeof(stage_path), err, sizeof(err)) < 0) {
                ret = -1;
            }
        }

        if (stage_path[0] && cfg.targets.local.enabled) {
            target_err[0] = 0;
            target_done++;
            int ok = cloud_copy_staged_zip_target(stage_path, cfg.targets.local.path,
                                                  target_title, target_user, remote_name,
                                                  target_path, sizeof(target_path),
                                                  target_err, sizeof(target_err)) == 0;
            if (ok) {
                success_count++;
                snprintf(all_paths + strlen(all_paths), sizeof(all_paths) - strlen(all_paths),
                         "%slocal:%s", all_paths[0] ? "; " : "", target_path);
            } else {
                fail_count++;
                snprintf(err + strlen(err), sizeof(err) - strlen(err), "%slocal: %s",
                         err[0] ? "; " : "", target_err);
            }
            snprintf(step_msg, sizeof(step_msg), "Local backup %s (%d/%d)",
                     ok ? "done" : "failed", target_done, target_total);
            cloud_set_step(35 + (target_done * 60 / target_total), step_msg,
                           ok ? target_path : remote_full);
            notify("Garlic SaveMgr: %s", step_msg);
        }

        if (stage_path[0] && cfg.targets.usb.enabled) {
            target_err[0] = 0;
            target_done++;
            int ok = cloud_copy_staged_zip_target(stage_path, cfg.targets.usb.path,
                                                  target_title, target_user, remote_name,
                                                  target_path, sizeof(target_path),
                                                  target_err, sizeof(target_err)) == 0;
            if (ok) {
                success_count++;
                snprintf(all_paths + strlen(all_paths), sizeof(all_paths) - strlen(all_paths),
                         "%susb:%s", all_paths[0] ? "; " : "", target_path);
            } else {
                fail_count++;
                snprintf(err + strlen(err), sizeof(err) - strlen(err), "%susb: %s",
                         err[0] ? "; " : "", target_err);
            }
            snprintf(step_msg, sizeof(step_msg), "USB backup %s (%d/%d)",
                     ok ? "done" : "failed", target_done, target_total);
            cloud_set_step(35 + (target_done * 60 / target_total), step_msg,
                           ok ? target_path : remote_full);
            notify("Garlic SaveMgr: %s", step_msg);
        }

        if (stage_path[0] && cfg.targets.ftp_enabled) {
            target_err[0] = 0;
            target_done++;
            int ok = cloud_upload_zip_file(&cfg, remote_dir, remote_name, stage_path,
                                           iobuf, target_err, sizeof(target_err)) == 0;
            if (ok) {
                success_count++;
                snprintf(all_paths + strlen(all_paths), sizeof(all_paths) - strlen(all_paths),
                         "%sftp:%s", all_paths[0] ? "; " : "", remote_full);
            } else {
                fail_count++;
                snprintf(err + strlen(err), sizeof(err) - strlen(err), "%sftp: %s",
                         err[0] ? "; " : "", target_err);
            }
            snprintf(step_msg, sizeof(step_msg), "FTP backup %s (%d/%d)",
                     ok ? "done" : "failed", target_done, target_total);
            cloud_set_step(35 + (target_done * 60 / target_total), step_msg, remote_full);
            notify("Garlic SaveMgr: %s", step_msg);
        }

        if (stage_path[0] && drive_queue_enabled) {
            target_err[0] = 0;
            target_done++;
            int ok = cloud_queue_staged_zip(stage_path, remote_name, target_err, sizeof(target_err)) == 0;
            if (ok) {
                success_count++;
                snprintf(all_paths + strlen(all_paths), sizeof(all_paths) - strlen(all_paths),
                         "%sdrive_queue:%s", all_paths[0] ? "; " : "", remote_name);
            } else {
                fail_count++;
                snprintf(err + strlen(err), sizeof(err) - strlen(err), "%sdrive_queue: %s",
                         err[0] ? "; " : "", target_err);
            }
            snprintf(step_msg, sizeof(step_msg), "Drive queue %s (%d/%d)",
                     ok ? "done" : "failed", target_done, target_total);
            cloud_set_step(35 + (target_done * 60 / target_total), step_msg, remote_name);
            notify("Garlic SaveMgr: %s", step_msg);
        }

        final_success_count = success_count;
        if (success_count > 0) {
            ret = 0;
            snprintf(remote_full, sizeof(remote_full), "%d/%d targets complete: %s",
                     success_count, target_total, all_paths);
            if (fail_count > 0)
                logprintf("[GarlicMgr] Cloud backup partial failures: %s\n", err);
        } else if (target_total > 0) {
            ret = -1;
            if (!err[0]) snprintf(err, sizeof(err), "All backup targets failed");
        }
        if (stage_path[0]) unlink(stage_path);
    }

     if (path_copies) {
         for (int i = 0; i < path_copy_count; i++) free(path_copies[i]);
         free(path_copies);
     }
     if (zfiles)
         cloud_free_title_files(names, allocs, nfiles, nallocs, zfiles);
     free(iobuf);

     if (ret == 0) {
         logprintf("[GarlicMgr] Cloud upload complete: %s\n", remote_full);
        if (final_target_count > 0)
            notify("Garlic SaveMgr: backup %d/%d done", final_success_count, final_target_count);
        else
            notify("Garlic SaveMgr: cloud backup complete");
         cloud_set_done(1, NULL, remote_full);
     } else {
         logprintf("[GarlicMgr] Cloud upload failed: %s\n", err);
        if (final_target_count > 0)
            notify("Garlic SaveMgr: backup %d/%d done", final_success_count, final_target_count);
        else
            notify("Garlic SaveMgr: cloud backup failed");
         cloud_set_done(0, err[0] ? err : "Cloud upload failed", remote_full);
     }
     free(job);
     return NULL;
 }

 static int cloud_start_job(cloud_job_args_t *job, char *err, size_t err_sz) {
     char active[128];
     if (job->is_title)
         snprintf(active, sizeof(active), "Uploading title %s", job->title_id);
     else
         snprintf(active, sizeof(active), "Uploading %s/%s", job->save.title_id, job->save.save_name);
     if(cloud_reserve_job(active,err,err_sz)<0)return -1;

     pthread_t tid;
     pthread_attr_t attr;
     pthread_attr_init(&attr);
     pthread_attr_setstacksize(&attr, 2 * 1024 * 1024);
     if (pthread_create(&tid, &attr, cloud_upload_thread, job) != 0) {
         pthread_attr_destroy(&attr);
         cloud_set_done(0, "Failed to start cloud upload thread", NULL);
         snprintf(err, err_sz, "Failed to start cloud upload thread");
         return -1;
     }
     pthread_detach(tid);
     pthread_attr_destroy(&attr);
     return 0;
 }

 /* ── Zip extraction (upload) ────────────────────────────────────── */
 static int chives_info_geometry(const sfo_info_t *info,chives_geometry_t *g) {
     if (!info->blocks || info->system_blocks > UINT64_MAX-info->blocks) return -1;
     memset(g,0,sizeof(*g));
     g->version=2;
     g->block_size_bytes=65536;
     g->block_count=info->blocks+info->system_blocks;
     g->original_image_size_bytes=g->block_count*(uint64_t)g->block_size_bytes;
     g->backup_header_count=1;
     g->mode_raw=0x000d;
     g->has_fs_ext=1;
     g->fs_ext=info->system_blocks;
     return chives_geometry_valid(g) ? 0 : -1;
 }
 static int chives_sfo_geometry(const uint8_t *payload,size_t size,chives_geometry_t *g,
                                sfo_info_t *info) {
     return parse_sfo_mem(payload,size,info) < 0 ? -1 : chives_info_geometry(info,g);
 }
 static int chives_zip_geometry(const uint8_t *data,size_t len,chives_geometry_t *g) {
     size_t off=0,sz;
     int found=0,image_found=0,entries=0,ret;
     const uint8_t *payload;
     char name[MAX_PATH_LEN];
     chives_geometry_t image={0};
     while ((ret=chives_zip_next(data,len,&off,name,sizeof(name),&payload,&sz)) > 0) {
         entries++;
         const char *base = strrchr(name,'/');
         base = base ? base + 1 : name;
         /* Validate each entry, including files after the sidecar. */
         if (chives_is_sidecar(name)) {
             if (found || chives_parse((const char *)payload,sz,g) < 0) return -1;
             found=1;
         } else if (!strcmp(base,"PS5IMAGE")) {
             chives_geometry_t candidate;
             if (chives_from_header(payload,sz,sz,&candidate) < 0) return -1;
             if (image_found && memcmp(&image,&candidate,sizeof(image))) return -1;
             image=candidate;
             image_found=1;
         }
     }
     if (ret < 0 || !entries) return -1;
     if (found && image_found && memcmp(g,&image,sizeof(image))) return -1;
     if (!found && image_found) *g=image;
     if (!found && !image_found) {
         off=0;
         while ((ret=chives_zip_next(data,len,&off,name,sizeof(name),&payload,&sz)) > 0) {
             const char *base=strrchr(name,'/');
             base=base ? base+1 : name;
             if (strcmp(base,"param.sfo")) continue;
             sfo_info_t info;
             return chives_sfo_geometry(payload,sz,g,&info) == 0 ? 1 : -1;
         }
     }
     return found || image_found;
 }
 static int chives_zip_physical_sfo(const uint8_t *data, size_t len, const chives_geometry_t *geometry) {
     size_t off = 0, size;
     const uint8_t *payload;
     char name[MAX_PATH_LEN];
     int ret;
     while ((ret = chives_zip_next(data, len, &off, name, sizeof(name), &payload, &size)) > 0) {
         const char *base = strrchr(name, '/');
         base = base ? base + 1 : name;
         if (!strcmp(base, "param.sfo") && garlic_legacy_sfo_matches(geometry, payload, size))
             return 1;
     }
     return 0;
 }

 static int chives_file_physical_sfo(const char *base, const chives_geometry_t *geometry) {
     char path[MAX_PATH_LEN];
     static uint8_t sfo[0x8000];
     snprintf(path, sizeof(path), "%s/sce_sys/param.sfo", base);
     int size = read_sfo_file(path, sfo, sizeof(sfo) - 20);
     return size > 0 && garlic_legacy_sfo_matches(geometry, sfo, size);
 }

 static int restore_legacy_sfo_from_zip(const uint8_t *data, size_t len, const char *mount) {
     char root_sfo[MAX_PATH_LEN];
     snprintf(root_sfo,sizeof(root_sfo),"%s/sce_sys/param.sfo",mount);
     int fd=open(root_sfo,O_RDONLY);
     if (fd < 0) return 0;
     int zero=1;
     uint8_t check[4096];
     ssize_t n;
     while ((n=read(fd,check,sizeof(check))) > 0)
         for (ssize_t i=0;i<n;i++) if (check[i]) { zero=0; break; }
     close(fd);
     if (!zero) return 0;

     size_t off=0,size;
     int ret;
     const uint8_t *payload;
     char name[MAX_PATH_LEN];
     const char *temp="/data/save_files/_ps5image_legacy";
     while ((ret=chives_zip_next(data,len,&off,name,sizeof(name),&payload,&size)) > 0) {
         const char *base=strrchr(name,'/');
         base=base ? base+1 : name;
         if (strcmp(base,"PS5IMAGE")) continue;
         int out=open(temp,O_CREAT|O_WRONLY|O_TRUNC,0755);
         if (out < 0) return -1;
         size_t done=0;
         while (done<size) {
             ssize_t written=write(out,payload+done,size-done);
             if (written <= 0) { close(out); unlink(temp); return -1; }
             done+=(size_t)written;
         }
         if (close(out) < 0) { unlink(temp); return -1; }
         static uint8_t sfo[0x8000];
         int sfo_size=ps5param_read_sfo(temp,sfo,sizeof(sfo));
         unlink(temp);
         return sfo_size > 0 ? install_sfo_file(root_sfo,sfo,(uint32_t)sfo_size) : -1;
     }
     return 0;
 }
 static int extract_zip(const char *dest, const uint8_t *data, size_t len) {
     static const char sfo_suffix[] = "sce_sys/param.sfo";
     size_t off=0,size,prefix_len=0;
     const uint8_t *payload;
     char name[MAX_PATH_LEN],prefix[MAX_PATH_LEN];
     int count=0,ret,sfo_entries=0;
     while ((ret=chives_zip_next(data,len,&off,name,sizeof(name),&payload,&size)) > 0) {
         size_t name_len=strlen(name),suffix_len=sizeof(sfo_suffix)-1;
         if (name_len >= suffix_len && !strcmp(name+name_len-suffix_len,sfo_suffix) &&
             (name_len == suffix_len || name[name_len-suffix_len-1] == '/')) {
             if (sfo_entries++) return -1;
             prefix_len=name_len-suffix_len;
             memcpy(prefix,name,prefix_len);
             prefix[prefix_len]=0;
         }
     }
     if (ret < 0) return -1;
     if (prefix_len)
         logprintf("[GarlicMgr] Flattening uploaded save directory: %s\n",prefix);

     off=0;
     while ((ret=chives_zip_next(data,len,&off,name,sizeof(name),&payload,&size)) > 0) {
         const char *base = strrchr(name,'/');
         base = base ? base + 1 : name;
         if (chives_is_sidecar(name) || !strcmp(base,"PS5PARAM") ||
             !strcmp(base,"PS5PARAM_SIZE") || !strcmp(base,"PS5KEY") ||
             !strcmp(base,"PS5IMAGE")) continue;
         if (!size) continue;
        if (prefix_len) {
             if (strncmp(name,prefix,prefix_len)) return -1;
             memmove(name,name+prefix_len,strlen(name+prefix_len)+1);
             if (!name[0]) continue;
         }
         char path[MAX_PATH_LEN];
         if (snprintf(path,sizeof(path),"%s/%s",dest,name) >= (int)sizeof(path)) return -1;
         if (name[strlen(name)-1] == '/') {
             recursive_mkdir(path);
             continue;
         }
         char *slash=strrchr(path,'/');
         if (slash) { *slash=0; recursive_mkdir(path); *slash='/'; }
         int fd=open(path,O_CREAT|O_WRONLY|O_TRUNC,0777);
         if (fd < 0) return -1;
         size_t done=0;
         while (done < size) {
             ssize_t wr=write(fd,payload+done,size-done);
             if (wr <= 0) { close(fd); return -1; }
             done+=(size_t)wr;
         }
         if (close(fd) < 0) return -1;
         count++;
     }
     return ret < 0 ? -1 : count;
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

 static ssize_t upload_socket_receive(void *context, void *buffer, size_t size) {
     return recv_all(*(int *)context,buffer,size);
 }

 typedef struct { char *bytes; size_t size; int error; } pfs_log_snapshot_t;
 /* Read-only, non-draining snapshot. Existing payload credentials already
  * carry the capability required by kern.msgbuf on firmware 13.60. */
 static pfs_log_snapshot_t pfs_log_snapshot(void) {
     pfs_log_snapshot_t out = {0};
     size_t size = 0;
     if (sysctlbyname("kern.msgbuf",NULL,&size,NULL,0) < 0) {
         out.error = errno; return out;
     }
     if (size > 256 * 1024) { out.error = EOVERFLOW; return out; }
     size_t capacity = size ? size : 1;
     out.bytes = malloc(capacity);
     if (!out.bytes) { out.error = ENOMEM; return out; }
     out.size = capacity;
     if (sysctlbyname("kern.msgbuf",out.bytes,&out.size,NULL,0) < 0) {
         out.error = errno; free(out.bytes); out.bytes = NULL; out.size = 0;
     } else if (out.size > capacity) {
         out.error = EOVERFLOW; free(out.bytes); out.bytes = NULL; out.size = 0;
     }
     return out;
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
         "Access-Control-Allow-Headers: Content-Type, X-Garlic-Transfer\r\n"
         "Connection: close\r\n"
         "\r\n",
         status_line, content_type, body_len);
     send(sock, hdr, hlen, 0);
     if (body && body_len > 0) {
         int off = 0;
         while (off < body_len) {
             int chunk = body_len - off;
             if (chunk > 262144) chunk = 262144;
             ssize_t s = send(sock, body + off, chunk, 0);
             if (s <= 0) break;
             off += s;
         }
     }
 }

 void http_json(int sock, const char *json) {
     http_send(sock, "200 OK", "application/json", json, strlen(json));
 }
 static void http_ps5param_failure(int sock) {
     char message[768], escaped[1536], json[1664];
     snprintf(message,sizeof(message),"%s; output was not published or installed",
              ps5param_error()[0] ? ps5param_error() : "PS5PARAM finalization failed");
     json_escape(message,escaped,sizeof(escaped));
     snprintf(json,sizeof(json),"{\"error\":\"%s\"}",escaped);
     http_json(sock,json);
 }


 static int read_request_body(int sock, char *req, int n, char *iobuf,
                              char **out, size_t *out_len, char *err, size_t err_sz) {
     *out = NULL;
     *out_len = 0;
     size_t clen = 0;
     char *cl = strcasestr(req, "Content-Length:");
     if (cl) clen = strtoul(cl + 15, NULL, 10);
     if (clen == 0 || clen > 64 * 1024) {
         snprintf(err, err_sz, "Invalid settings body size");
         return -1;
     }
     char *body_start = strstr(req, "\r\n\r\n");
     if (!body_start) {
         snprintf(err, err_sz, "Bad request");
         return -1;
     }
     body_start += 4;
     size_t body_in_buf = n - (body_start - req);
     if (body_in_buf > clen) body_in_buf = clen;
     char *body = malloc(clen + 1);
     if (!body) {
         snprintf(err, err_sz, "Out of memory");
         return -1;
     }
     memcpy(body, body_start, body_in_buf);
     size_t got = body_in_buf;
     while (got < clen) {
         size_t want = BUF_SIZE < (clen - got) ? BUF_SIZE : (clen - got);
         ssize_t r = recv_all(sock, iobuf, want);
         if (r <= 0) break;
         memcpy(body + got, iobuf, r);
         got += r;
     }
     body[got] = 0;
     *out = body;
     *out_len = got;
     if (got != clen) {
         snprintf(err, err_sz, "Request body was incomplete");
         return -1;
     }
     return 0;
 }

 static void cloud_send_settings(int sock) {
     cloud_config_t cfg;
     char err[256] = {0};
     int ok = (cloud_load_config(&cfg, err, sizeof(err)) == 0);
     if (!ok) {
         memset(&cfg, 0, sizeof(cfg));
         snprintf(cfg.provider, sizeof(cfg.provider), "ftp");
         snprintf(cfg.drive.mode, sizeof(cfg.drive.mode), "browser");
         cfg.ftp.port = 21;
         snprintf(cfg.ftp.remote_path, sizeof(cfg.ftp.remote_path), "/");
         char *raw = NULL;
         if (read_file_limited(CLOUD_CONFIG_PATH, &raw, 64 * 1024) == 0) {
             char parse_err[128] = {0};
             cloud_parse_config_text(raw, &cfg, parse_err, sizeof(parse_err));
             free(raw);
         }
     }
     char cfg_json[32768], err_esc[512], json[34000];
     cloud_config_to_json(&cfg, cfg_json, sizeof(cfg_json), 1);
     json_escape(err, err_esc, sizeof(err_esc));
     snprintf(json, sizeof(json),
         "{\"ok\":true,\"exists\":%s,\"config_error\":\"%s\","
         "\"direct_drive_supported\":false,\"config\":%s}",
         ok ? "true" : "false", err_esc, cfg_json);
     http_json(sock, json);
 }

 static void cloud_send_oauth_settings(int sock) {
     cloud_config_t cfg;
     char err[256] = {0};
     if (cloud_load_config(&cfg, err, sizeof(err)) < 0) {
         char eesc[512], json[768];
         json_escape(err, eesc, sizeof(eesc));
         snprintf(json, sizeof(json), "{\"error\":\"%s\"}", eesc);
         http_json(sock, json);
         return;
     }
     char client_id[1024], client_secret[1024], refresh_token[2048], access_token[4096];
     json_escape(cfg.drive.client_id, client_id, sizeof(client_id));
     json_escape(cfg.drive.client_secret, client_secret, sizeof(client_secret));
     json_escape(cfg.drive.refresh_token, refresh_token, sizeof(refresh_token));
     json_escape(cfg.drive.access_token, access_token, sizeof(access_token));
     char json[16384];
     snprintf(json, sizeof(json),
         "{\"client_id\":\"%s\",\"client_secret\":\"%s\",\"refresh_token\":\"%s\",\"access_token\":\"%s\"}",
         client_id, client_secret, refresh_token, access_token);
     http_json(sock, json);
 }

 static void cloud_handle_settings_post(int sock, char *iobuf, char *req, int n) {
     char err[256] = {0};
     char *body = NULL;
     size_t body_len = 0;
     if (read_request_body(sock, req, n, iobuf, &body, &body_len, err, sizeof(err)) < 0) {
         char eesc[512], json[768];
         json_escape(err, eesc, sizeof(eesc));
         snprintf(json, sizeof(json), "{\"error\":\"%s\"}", eesc);
         http_json(sock, json);
         free(body);
         return;
     }

     cloud_config_t cfg, old_cfg;
     char old_err[128];
     cloud_config_t *oldp = NULL;
     if (cloud_load_config(&old_cfg, old_err, sizeof(old_err)) == 0) oldp = &old_cfg;
     if (cloud_parse_config_text(body, &cfg, err, sizeof(err)) < 0) {
         char eesc[512], json[768];
         json_escape(err, eesc, sizeof(eesc));
         snprintf(json, sizeof(json), "{\"error\":\"%s\"}", eesc);
         http_json(sock, json);
         free(body);
         return;
     }
     cloud_merge_secrets(&cfg, oldp);
     if (cloud_save_config(&cfg, err, sizeof(err)) < 0) {
         char eesc[512], json[768];
         json_escape(err, eesc, sizeof(eesc));
         snprintf(json, sizeof(json), "{\"error\":\"%s\"}", eesc);
         http_json(sock, json);
         free(body);
         return;
     }
     free(body);
     http_json(sock, "{\"ok\":true}");
 }

 static void cloud_send_package_response(int sock, const char *filename, const mem_buf_t *pkg) {
     char hdr[1024];
     int hlen = snprintf(hdr, sizeof(hdr),
         "HTTP/1.1 200 OK\r\n"
         "Content-Type: application/zip\r\n"
         "Content-Disposition: attachment; filename=\"%s\"\r\n"
         "Content-Length: %zu\r\n"
         "Access-Control-Allow-Origin: *\r\n"
         "Access-Control-Expose-Headers: Content-Disposition\r\n"
         "Connection: close\r\n\r\n",
         filename, pkg->len);
     send(sock, hdr, hlen, 0);
     send_all_fd(sock, pkg->data, pkg->len);
 }

 static void cloud_send_status(int sock) {
     cloud_config_t cfg;
     char cfg_err[256] = {0};
     int cfg_ok = (cloud_load_config(&cfg, cfg_err, sizeof(cfg_err)) == 0);

     cloud_state_t st;
     pthread_mutex_lock(&g_cloud_mtx);
     st = g_cloud_state;
     pthread_mutex_unlock(&g_cloud_mtx);

     char provider[64], mode[64], host[512], remote[1024], active[256], last_err[512], last_path[1024], cfg_err_esc[512];
     json_escape(cfg_ok ? cfg.provider : "", provider, sizeof(provider));
     json_escape(cfg_ok ? cfg.drive.mode : "", mode, sizeof(mode));
     json_escape(cfg_ok ? cfg.ftp.host : "", host, sizeof(host));
     json_escape(cfg_ok ? cfg.ftp.remote_path : "", remote, sizeof(remote));
     json_escape(st.active, active, sizeof(active));
     json_escape(st.last_error, last_err, sizeof(last_err));
     json_escape(st.last_remote, last_path, sizeof(last_path));
     json_escape(cfg_err, cfg_err_esc, sizeof(cfg_err_esc));

     char json[3072];
     snprintf(json, sizeof(json),
         "{\"config_ok\":%s,\"enabled\":%s,\"provider\":\"%s\",\"drive_mode\":\"%s\","
         "\"host\":\"%s\",\"port\":%d,"
         "\"remote_path\":\"%s\",\"use_tls\":%s,\"watch_count\":%d,"
         "\"direct_drive_supported\":false,"
         "\"running\":%s,\"progress\":%d,\"active\":\"%s\","
         "\"last_ok\":%s,\"last_error\":\"%s\",\"last_remote\":\"%s\","
         "\"config_error\":\"%s\"}",
         cfg_ok ? "true" : "false",
         (cfg_ok && cfg.enabled) ? "true" : "false",
         provider,
         mode,
         host,
         cfg_ok ? cfg.ftp.port : 0,
         remote,
         (cfg_ok && cfg.ftp.use_tls) ? "true" : "false",
         cfg_ok ? cfg.watch_title_count : 0,
         st.running ? "true" : "false",
         st.progress,
         active,
         st.last_ok ? "true" : "false",
         last_err,
         last_path,
         cfg_err_esc);
     http_json(sock, json);
 }

 static void cloud_send_test_ftp(int sock) {
     cloud_config_t cfg;
     char err[512] = {0};
     if (net_init_once() < 0) {
         http_json(sock, "{\"ok\":false,\"stage\":\"net\",\"error\":\"PS5 network init (sceNetInit) failed\"}");
         return;
     }
     if (cloud_load_config(&cfg, err, sizeof(err)) < 0) {
         char eesc[512], json[768];
         json_escape(err, eesc, sizeof(eesc));
         snprintf(json, sizeof(json), "{\"ok\":false,\"stage\":\"config\",\"error\":\"%s\"}", eesc);
         http_json(sock, json);
         return;
     }
     if (!cfg.enabled) {
         http_json(sock, "{\"ok\":false,\"stage\":\"config\",\"error\":\"Cloud backup is disabled\"}");
         return;
     }
     if (!cfg.targets.ftp_enabled) {
         http_json(sock, "{\"ok\":false,\"stage\":\"config\",\"error\":\"FTP backup target is not enabled\"}");
         return;
     }

     ftp_client_t ftp;
     if (ftp_connect_login(&ftp, &cfg.ftp, err, sizeof(err)) < 0) {
         char eesc[512], json[768];
         json_escape(err, eesc, sizeof(eesc));
         snprintf(json, sizeof(json),
             "{\"ok\":false,\"stage\":\"control\",\"host\":\"%s\",\"port\":%d,\"error\":\"%s\"}",
             cfg.ftp.host, cfg.ftp.port, eesc);
         http_json(sock, json);
         return;
     }

     int data = ftp_pasv_connect(&ftp, err, sizeof(err));
     if (data < 0) {
         ftp_close(&ftp);
         char eesc[512], json[768];
         json_escape(err, eesc, sizeof(eesc));
         snprintf(json, sizeof(json),
             "{\"ok\":false,\"stage\":\"passive\",\"host\":\"%s\",\"port\":%d,\"error\":\"%s\"}",
             cfg.ftp.host, cfg.ftp.port, eesc);
         http_json(sock, json);
         return;
     }
     close(data);
     ftp_close(&ftp);

     char json[512];
     snprintf(json, sizeof(json),
         "{\"ok\":true,\"host\":\"%s\",\"port\":%d,\"message\":\"FTP control login and passive data port OK\"}",
         cfg.ftp.host, cfg.ftp.port);
     http_json(sock, json);
 }

 static void cloud_send_auto_status(int sock) {
     auto_state_t st;
     pthread_mutex_lock(&g_auto_mtx);
     st = g_auto_state;
     pthread_mutex_unlock(&g_auto_mtx);

     cloud_config_t cfg;
     char cfg_err[256] = {0};
     int cfg_ok = (cloud_load_config(&cfg, cfg_err, sizeof(cfg_err)) == 0);

     char cur[80], closed[80], result[512], cfg_err_esc[256];
     json_escape(st.current_title, cur, sizeof(cur));
     json_escape(st.last_closed, closed, sizeof(closed));
     json_escape(st.last_result, result, sizeof(result));
     json_escape(cfg_err, cfg_err_esc, sizeof(cfg_err_esc));
     char json[1536];
     snprintf(json, sizeof(json),
         "{\"watcher_running\":%s,\"lnc_available\":%s,\"lnc_saw_title\":%s,\"fallback_mode\":%s,"
         "\"cloud_enabled\":%s,\"auto_enabled\":%s,\"config_error\":\"%s\","
         "\"current_title\":\"%s\",\"last_closed\":\"%s\",\"last_result\":\"%s\","
         "\"last_event\":%lld,\"pending_count\":%d}",
         st.watcher_running ? "true" : "false",
         st.lnc_available ? "true" : "false",
         st.lnc_saw_title ? "true" : "false",
         st.fallback_mode ? "true" : "false",
         (cfg_ok && cfg.enabled) ? "true" : "false",
         (cfg_ok && cfg.auto_backup.enabled) ? "true" : "false",
         cfg_err_esc,
         cur, closed, result, (long long)st.last_event, cloud_queue_count());
     http_json(sock, json);
 }

 static int safe_queue_id(const char *id) {
     if (!id || !id[0]) return 0;
     for (const char *p = id; *p; p++) {
         if (*p == '/' || *p == '\\' || *p == '.' || *p == ':' || *p == '\r' || *p == '\n')
             return 0;
     }
     return 1;
 }

 static void cloud_send_queue(int sock) {
     DIR *d = opendir(CLOUD_QUEUE_DIR);
     char *json = malloc(64 * 1024);
     if (!json) { http_json(sock, "{\"error\":\"Out of memory\"}"); return; }
     int pos = snprintf(json, 64 * 1024, "{\"queue\":[");
     int first = 1;
     if (d) {
         struct dirent *ent;
         while ((ent = readdir(d)) && pos < 63000) {
             size_t len = strlen(ent->d_name);
             if (len <= 4 || strcmp(ent->d_name + len - 4, ".zip") != 0) continue;
             char path[MAX_PATH_LEN];
             snprintf(path, sizeof(path), "%s/%s", CLOUD_QUEUE_DIR, ent->d_name);
             struct stat st;
             if (stat(path, &st) < 0) continue;
             char id[256], escid[512];
             snprintf(id, sizeof(id), "%.*s", (int)(len - 4), ent->d_name);
             json_escape(id, escid, sizeof(escid));
             pos += snprintf(json + pos, 64 * 1024 - pos,
                 "%s{\"id\":\"%s\",\"filename\":\"%s\",\"size\":%lld,\"mtime\":%lld}",
                 first ? "" : ",", escid, escid, (long long)st.st_size, (long long)st.st_mtime);
             first = 0;
         }
         closedir(d);
     }
     snprintf(json + pos, 64 * 1024 - pos, "]}");
     http_json(sock, json);
     free(json);
 }

 static void cloud_queue_download(int sock, const char *id) {
     if (!safe_queue_id(id)) { http_json(sock, "{\"error\":\"Invalid id\"}"); return; }
     char path[MAX_PATH_LEN], filename[300];
     snprintf(filename, sizeof(filename), "%s.zip", id);
     snprintf(path, sizeof(path), "%s/%s", CLOUD_QUEUE_DIR, filename);
     struct stat st;
     if (stat(path, &st) < 0 || !S_ISREG(st.st_mode)) { http_json(sock, "{\"error\":\"Queue item not found\"}"); return; }
     int fd = open(path, O_RDONLY);
     if (fd < 0) { http_json(sock, "{\"error\":\"Cannot read queue item\"}"); return; }
     char hdr[1024];
     int hlen = snprintf(hdr, sizeof(hdr),
         "HTTP/1.1 200 OK\r\n"
         "Content-Type: application/zip\r\n"
         "Content-Disposition: attachment; filename=\"%s\"\r\n"
         "Content-Length: %lld\r\n"
         "Access-Control-Allow-Origin: *\r\n"
         "Access-Control-Expose-Headers: Content-Disposition\r\n"
         "Connection: close\r\n\r\n",
         filename, (long long)st.st_size);
     send(sock, hdr, hlen, 0);
     char *buf = malloc(BUF_SIZE);
     if (buf) {
         ssize_t nr;
         while ((nr = read(fd, buf, BUF_SIZE)) > 0) {
             if (send_all_fd(sock, buf, nr) < 0) break;
         }
         free(buf);
     }
     close(fd);
 }

 static void cloud_queue_done(int sock, const char *id) {
     if (!safe_queue_id(id)) { http_json(sock, "{\"error\":\"Invalid id\"}"); return; }
     char path[MAX_PATH_LEN];
     snprintf(path, sizeof(path), "%s/%s.zip", CLOUD_QUEUE_DIR, id);
     if (unlink(path) < 0) { http_json(sock, "{\"error\":\"Queue delete failed\"}"); return; }
     http_json(sock, "{\"ok\":true}");
 }

 /* ── Embedded Web UI (generated from src/ui.html via xxd -i) ──── */
 #include "ui.h"

 /* ── Request handler ────────────────────────────────────────────── */
 static void handle_request_inner(int sock, char *iobuf, char *req, int n);

 static void cloud_begin_upload_title(int sock, const char *url) {
     char tid[64] = {0};
     char mode[16] = "enc";
     char *tp = strstr(url, "id=");
     if (tp) url_param_decode(tp + 3, tid, sizeof(tid));
     char *mp = strstr(url, "mode=");
     if (mp) url_param_decode(mp + 5, mode, sizeof(mode));
     if (!tid[0]) { http_json(sock, "{\"error\":\"Missing id\"}"); return; }
     if (strcmp(mode, "enc") != 0) {
         http_json(sock, "{\"error\":\"Only encrypted cloud backups are supported in Phase 1\"}");
         return;
     }

     cloud_job_args_t *job = calloc(1, sizeof(*job));
     if (!job) { http_json(sock, "{\"error\":\"Out of memory\"}"); return; }
     job->is_title = 1;
     snprintf(job->title_id, sizeof(job->title_id), "%s", tid);

     char err[256] = {0};
     if (cloud_start_job(job, err, sizeof(err)) < 0) {
         free(job);
         char eesc[512], json[768];
         json_escape(err, eesc, sizeof(eesc));
         snprintf(json, sizeof(json), "{\"error\":\"%s\"}", eesc);
         http_json(sock, json);
         return;
     }
     http_json(sock, "{\"ok\":true}");
 }

 static void cloud_begin_upload_save(int sock, const char *url) {
     int idx = -1;
     char mode[16] = "enc";
     char *p = strstr(url, "idx=");
     if (p) idx = atoi(p + 4);
     char *mp = strstr(url, "mode=");
     if (mp) url_param_decode(mp + 5, mode, sizeof(mode));
     if (strcmp(mode, "enc") != 0) {
         http_json(sock, "{\"error\":\"Only encrypted cloud backups are supported in Phase 1\"}");
         return;
     }

     save_entry_t save;
     memset(&save, 0, sizeof(save));
     pthread_mutex_lock(&g_mtx);
     scan_saves();
     if (idx < 0 || idx >= g_save_count || g_saves[idx].is_usb) {
         pthread_mutex_unlock(&g_mtx);
         http_json(sock, "{\"error\":\"Invalid system save index\"}");
         return;
     }
     save = g_saves[idx];
     pthread_mutex_unlock(&g_mtx);

     cloud_job_args_t *job = calloc(1, sizeof(*job));
     if (!job) { http_json(sock, "{\"error\":\"Out of memory\"}"); return; }
     job->is_title = 0;
     job->save = save;

     char err[256] = {0};
     if (cloud_start_job(job, err, sizeof(err)) < 0) {
         free(job);
         char eesc[512], json[768];
         json_escape(err, eesc, sizeof(eesc));
         snprintf(json, sizeof(json), "{\"error\":\"%s\"}", eesc);
         http_json(sock, json);
         return;
     }
     http_json(sock, "{\"ok\":true}");
 }

 /* Thread entry — receives socket fd via malloc'd int */
 /* Discard only browser Encrypt/Decrypt scratch files. Called with g_mtx.
  * Native unmount failure keeps the image and job blocked for an explicit retry. */

 /* CMP shutdown HTTP hooks: CMP/lifecycle.c. */
 static int discard_web_transfer(const char *base, char *error, size_t cap) {
     static const char *names[]={"_tmp_key.bin","_tmp_dec.bin","sdimg__tmp_dec",
                                "_tmp_dec","_tmp_enc.bin","_tmp_enc"};
     int owned=0;char path[MAX_PATH_LEN];
     for(size_t i=0;i<sizeof(names)/sizeof(*names);i++){
         if(snprintf(path,sizeof(path),"%s/%s",base,names[i])>=(int)sizeof(path))return -1;
         if(g_mounted&&!strcmp(g_mounted_path,path))owned=1;
     }
     if(owned&&(g_local_copy[0]||unmount_save()<0)){
         snprintf(error,cap,"Temporary save could not be unmounted; it was retained. Retry Cancel cleanup.");return -1;
     }
     for(size_t i=0;i<sizeof(names)/sizeof(*names);i++){
         snprintf(path,sizeof(path),"%s/%s",base,names[i]);
         if(unlink(path)<0&&errno!=ENOENT){snprintf(error,cap,"Temporary file cleanup failed: errno=%d. Retry Cancel cleanup.",errno);return -1;}
     }
     return 0;
 }

 /* Called under g_mtx after socket shutdown, once this job owns cleanup. */
 int cleanup_web_transfer_job(garlic_transfer_control_t *control, uint64_t id,
                                      const char *base, char *error, size_t cap) {
     if (!garlic_transfer_cleanup_allowed(control,id)) {
         snprintf(error,cap,"Cancelled transfer was already replaced; current output was left intact");
         return -1;
     }
     return discard_web_transfer(base,error,cap);
 }

 /* Receive a complete uploaded image/key before any mount. Incomplete socket
  * input and partial writes cannot be promoted to a valid decrypted image. */
 static int receive_web_image(int sock,int fd,const char *path,const void *initial,
                              size_t initial_size,size_t expected,void *iobuf) {
     garlic_upload_t progress={.expected=expected,.crc=UINT32_C(0xffffffff),.actual_size=-1};
     garlic_upload_receive(fd,initial,initial_size,&progress,iobuf,BUF_SIZE,upload_socket_receive,&sock);
     if(garlic_upload_finish(fd,path,&progress,iobuf,BUF_SIZE)<0){
         char message[512],escaped[1024],json[1280];
         snprintf(message,sizeof(message),"Upload %s failed: errno=%d; received=%zu/%zu written=%zu/%zu",
                  progress.stage,progress.error,progress.received,progress.expected,progress.written,progress.expected);
         logprintf("[GarlicMgr] %s\n",message);chives_escape(message,escaped,sizeof(escaped));
         snprintf(json,sizeof(json),"{\"error\":\"%s\"}",escaped);unlink(path);http_json(sock,json);return -1;
     }
     return 0;
 }

 void *request_thread(void *arg) {
     int sock = *(int *)arg;
     free(arg);

     int rcvbuf = 1024 * 1024;
     setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
     setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &rcvbuf, sizeof(rcvbuf));
     setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &(int){1}, sizeof(int));

     struct timeval idle_timeout={15,0};
     setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,&idle_timeout,sizeof(idle_timeout));
     setsockopt(sock,SOL_SOCKET,SO_SNDTIMEO,&idle_timeout,sizeof(idle_timeout));
     char req[MAX_REQ];
     int n=0;
     /* A transfer header can cross TCP packets; do not mistake it for an
      * untagged request or start a partial-header upload. */
     while(n<(int)sizeof(req)-1){
         ssize_t got=recv(sock,req+n,sizeof(req)-1-(size_t)n,0);
         if(got<0&&errno==EINTR)continue;
         if(got<=0){close(sock);return NULL;}
         n+=(int)got;req[n]=0;if(strstr(req,"\r\n\r\n"))break;
     }
     if(!strstr(req,"\r\n\r\n")){close(sock);return NULL;}

     /* Serve static HTML without lock */
     char method[8] = {0}, url[2048] = {0};
     sscanf(req, "%7s %2047s", method, url);
     if(garlic_lifecycle_http(sock,method,url,req,(size_t)n))return NULL;

     if (strcmp(method, "OPTIONS") == 0) {
         http_send(sock, "204 No Content", "text/plain", NULL, 0);
         close(sock);
         return NULL;
     }
     if (strcmp(method, "GET") == 0 && (strcmp(url, "/") == 0 || strcmp(url, "/index.html") == 0)) {
         http_send(sock, "200 OK", "text/html", (const char *)src_ui_html, src_ui_html_len);
         close(sock);
         return NULL;
     }
     /* Favicon — return 404 immediately without lock */
     if (strcmp(method, "GET") == 0 && strcmp(url, "/favicon.ico") == 0) {
         http_send(sock, "404 Not Found", "text/plain", "", 0);
         close(sock);
         return NULL;
     }
     /* Only /api/ requests should proceed — reject anything else without lock */
     if (strncmp(url, "/api/", 5) != 0) {
         http_send(sock, "404 Not Found", "text/plain", "Not found", 9);
         close(sock);
         return NULL;
     }

     /* Tagged jobs, including stale or malformed IDs, must be checked before
      * any native or read-only fast path can bypass their job restrictions. */
     uint64_t early_job_id = 0;
     if (garlic_transfer_header(req,(size_t)n,&early_job_id) != 0) goto mounted_file_request;

     /* Read-only file download — no lock needed */
     if (strcmp(method, "GET") == 0 && strncmp(url, "/api/download_file", 18) == 0) {
         if (!g_mounted) { http_json(sock, "{\"error\":\"No save mounted\"}"); close(sock); return NULL; }
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
         if (!fname[0]) { http_json(sock, "{\"error\":\"Missing name\"}"); close(sock); return NULL; }
         if (ps5param_is_sfo_name(fname)) goto mounted_file_request;
         char filepath[MAX_PATH_LEN];
         snprintf(filepath, sizeof(filepath), "%s/%s", g_mount_point, fname);
         struct stat st;
         if (stat(filepath, &st) < 0 || !S_ISREG(st.st_mode)) {
             http_json(sock, "{\"error\":\"File not found\"}"); close(sock); return NULL;
         }
         int fd = open(filepath, O_RDONLY);
         if (fd < 0) { http_json(sock, "{\"error\":\"Cannot read file\"}"); close(sock); return NULL; }
         const char *bname = strrchr(fname, '/');
         bname = bname ? bname + 1 : fname;
         long long send_len = (long long)st.st_size;
         char hdr[1024];
         int hlen = snprintf(hdr, sizeof(hdr),
             "HTTP/1.1 200 OK\r\n"
             "Content-Type: application/octet-stream\r\n"
             "Content-Disposition: attachment; filename=\"%s\"\r\n"
             "Content-Length: %lld\r\n"
             "Access-Control-Allow-Origin: *\r\n"
             "Connection: close\r\n\r\n", bname, send_len);
         send(sock, hdr, hlen, 0);
         /* Stream read→send */
         char *buf = malloc(BUF_SIZE);
         if (buf) {
             ssize_t nr;
             while ((nr = read(fd, buf, BUF_SIZE)) > 0) {
                 ssize_t off = 0;
                 while (off < nr) {
                     ssize_t s = send(sock, buf + off, nr - off, 0);
                     if (s <= 0) goto dl_done;
                     off += s;
                 }
             }
             dl_done:
             free(buf);
         }
         close(fd);
         close(sock);
         return NULL;
     }

     /* Read-only editor read — no lock needed (reads from server buffer) */
     if (strcmp(method, "GET") == 0 && strncmp(url, "/api/editor/read", 16) == 0) {
         if (!g_ed_buf) { http_json(sock, "{\"error\":\"No file open\"}"); close(sock); return NULL; }
         size_t off = 0, len = 4096;
         char *op = strstr(url, "offset=");
         char *lp = strstr(url, "length=");
         if (op) off = strtoul(op + 7, NULL, 10);
         if (lp) len = strtoul(lp + 7, NULL, 10);
         if (off >= g_ed_size) { http_send(sock, "200 OK", "application/octet-stream", "", 0); close(sock); return NULL; }
         if (off + len > g_ed_size) len = g_ed_size - off;
         http_send(sock, "200 OK", "application/octet-stream", g_ed_buf + off, len);
         close(sock);
         return NULL;
     }

     /* Editor status — no lock needed */
     if (strcmp(method, "GET") == 0 && strncmp(url, "/api/editor/status", 18) == 0) {
         char json[512];
         snprintf(json, sizeof(json), "{\"open\":%s,\"name\":\"%s\",\"size\":%zu,\"dirty\":%s}",
             g_ed_buf ? "true" : "false", g_ed_name, g_ed_size, g_ed_dirty ? "true" : "false");
         http_json(sock, json);
         close(sock);
         return NULL;
     }

     /* Cloud endpoints stay responsive while a background upload runs */
     if (strcmp(method, "GET") == 0 && strcmp(url, "/api/cloud/status") == 0) {
         cloud_send_status(sock);
         close(sock);
         return NULL;
     }

     if (strcmp(method, "GET") == 0 && strcmp(url, "/api/cloud/test_ftp") == 0) {
         cloud_send_test_ftp(sock);
         close(sock);
         return NULL;
     }

     if (strcmp(method, "GET") == 0 && strcmp(url, "/api/settings/cloud") == 0) {
         cloud_send_settings(sock);
         close(sock);
         return NULL;
     }

     if (strcmp(method, "GET") == 0 && strcmp(url, "/api/settings/cloud/oauth") == 0) {
         cloud_send_oauth_settings(sock);
         close(sock);
         return NULL;
     }

     if (strcmp(method, "POST") == 0 && strcmp(url, "/api/settings/cloud") == 0) {
         char *iobuf = malloc(BUF_SIZE);
         if (iobuf) {
             cloud_handle_settings_post(sock, iobuf, req, n);
             free(iobuf);
         }
         close(sock);
         return NULL;
     }

     if (strcmp(method, "GET") == 0 && strncmp(url, "/api/cloud/upload_title", 23) == 0) {
         cloud_begin_upload_title(sock, url);
         close(sock);
         return NULL;
     }

     if (strcmp(method, "GET") == 0 && strncmp(url, "/api/cloud/upload", 17) == 0) {
         cloud_begin_upload_save(sock, url);
         close(sock);
         return NULL;
     }

     if (strcmp(method, "GET") == 0 && strcmp(url, "/api/cloud/auto_status") == 0) {
         cloud_send_auto_status(sock);
         close(sock);
         return NULL;
     }

     if (strcmp(method, "POST") == 0 && strcmp(url, "/api/cloud/auto_scan") == 0) {
         http_json(sock, "{\"ok\":true,\"message\":\"Auto backup uses game-close detection only\"}");
         close(sock);
         return NULL;
     }

     if (strcmp(method, "GET") == 0 && strcmp(url, "/api/cloud/queue") == 0) {
         cloud_send_queue(sock);
         close(sock);
         return NULL;
     }

     if (strcmp(method, "GET") == 0 && strncmp(url, "/api/cloud/queue_download", 25) == 0) {
         char id[256] = {0};
         char *ip = strstr(url, "id=");
         if (ip) url_param_decode(ip + 3, id, sizeof(id));
         cloud_queue_download(sock, id);
         close(sock);
         return NULL;
     }

     if (strcmp(method, "POST") == 0 && strncmp(url, "/api/cloud/queue_done", 21) == 0) {
         char id[256] = {0};
         char *ip = strstr(url, "id=");
         if (ip) url_param_decode(ip + 3, id, sizeof(id));
         cloud_queue_done(sock, id);
         close(sock);
         return NULL;
     }

 mounted_file_request:;
     /* Old browser tabs must not start a job for the removed key-only action. */
     if (!strcmp(url,"/api/transfer_begin?kind=key") ||
         !strncmp(url,"/api/export_save_key",20)) {
         http_json(sock,"{\"error\":\"Standalone key recovery is not available in this build\"}");
         close(sock);return NULL;
     }
     uint64_t job_id=0;
     int tagged=garlic_transfer_header(req,(size_t)n,&job_id);
     if(tagged<0){http_json(sock,"{\"error\":\"Invalid transfer ID\"}");close(sock);return NULL;}
     if(!strcmp(method,"POST")&&!strcmp(url,"/api/transfer_begin")){
         uint64_t id=0;char json[128];
         int opened = garlic_transfer_begin(&g_transfer,&id);
         if(opened){
             snprintf(json,sizeof(json),"{\"ok\":true,\"id\":\"%016llx\"}",(unsigned long long)id);http_json(sock,json);
         }else http_json(sock,"{\"error\":\"Another Encrypt/Decrypt job is active or awaiting Cancel cleanup\"}");
         close(sock);return NULL;
     }
     if(!strcmp(method,"POST")&&!strcmp(url,"/api/transfer_cancel")){
         char error[256]={0},escaped[512],json[640];
         if(tagged!=1||!garlic_transfer_cancel(&g_transfer,job_id)){
             http_json(sock,"{\"error\":\"No matching transfer to cancel\"}");close(sock);return NULL;
         }
         /* Set cancellation and shutdown data sockets BEFORE waiting for the
          * mount lock. This wakes the worker that may be holding that lock. */
         pthread_mutex_lock(&g_mtx);
         int result=-1;
         result=cleanup_web_transfer_job(&g_transfer,job_id,"/data/save_files",error,sizeof(error));
         if(!result)garlic_transfer_end(&g_transfer,job_id,1);
         pthread_mutex_unlock(&g_mtx);
         if(result){chives_escape(error,escaped,sizeof(escaped));snprintf(json,sizeof(json),"{\"error\":\"%s\"}",escaped);}
         else snprintf(json,sizeof(json),"{\"ok\":true,\"cancelled\":true}");
         http_json(sock,json);close(sock);return NULL;
     }
     if(!strcmp(method,"POST")&&!strcmp(url,"/api/transfer_end")){
         pthread_mutex_lock(&g_mtx);
         int result=tagged==1&&garlic_transfer_allowed(&g_transfer,job_id)&&garlic_transfer_end(&g_transfer,job_id,0);
         pthread_mutex_unlock(&g_mtx);
         http_json(sock,result?"{\"ok\":true}":"{\"error\":\"Transfer was cancelled or replaced\"}");close(sock);return NULL;
     }
     int job_slot=-1;
     if(tagged==1&&(job_slot=garlic_transfer_attach(&g_transfer,job_id,sock))<0){
         http_json(sock,"{\"error\":\"Transfer was cancelled or replaced\"}");close(sock);return NULL;
     }
     /* All other requests go through the handler with mutex */
     char *iobuf = malloc(BUF_SIZE);
     if(!iobuf){garlic_transfer_detach(&g_transfer,job_slot,job_id,sock);close(sock);return NULL;}
     pthread_mutex_lock(&g_mtx);
     if(garlic_lifecycle_stopping())
         http_json(sock,"{\"error\":\"Garlic SaveMgr is shutting down\"}");
     else if(tagged==1&&!garlic_transfer_allowed(&g_transfer,job_id))
         http_json(sock,"{\"error\":\"Transfer was cancelled or replaced\"}");
     else if(!tagged&&garlic_transfer_busy(&g_transfer)&&strcmp(url,"/api/log"))
         http_json(sock,"{\"error\":\"Encrypt/Decrypt is active; use its Cancel button first\"}");
     else handle_request_inner(sock,iobuf,req,n);
     pthread_mutex_unlock(&g_mtx);
     free(iobuf);
     garlic_transfer_detach(&g_transfer,job_slot,job_id,sock);
     close(sock);
     return NULL;
 }

 static void handle_request_inner(int sock, char *iobuf, char *req, int n) {

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
         int serve_blob = ps5param_cached_for_mount(g_mount_point) && ps5param_is_sfo_name(fname);
         struct stat st; memset(&st, 0, sizeof(st));
         int fd = -1;
         if (!serve_blob) {
             if (stat(filepath, &st) < 0 || !S_ISREG(st.st_mode)) {
                 http_json(sock, "{\"error\":\"File not found\"}"); return;
             }
             fd = open(filepath, O_RDONLY);
             if (fd < 0) { http_json(sock, "{\"error\":\"Cannot read file\"}"); return; }
         }
         const char *basename = strrchr(fname, '/');
         basename = basename ? basename + 1 : fname;
         long long send_len = serve_blob ? (long long)ps5param_cache_size() : (long long)st.st_size;
         char hdr[1024];
         int hlen = snprintf(hdr, sizeof(hdr),
             "HTTP/1.1 200 OK\r\n"
             "Content-Type: application/octet-stream\r\n"
             "Content-Disposition: attachment; filename=\"%s\"\r\n"
             "Content-Length: %lld\r\n"
             "Access-Control-Allow-Origin: *\r\n"
             "Connection: close\r\n\r\n", basename, send_len);
         send(sock, hdr, hlen, 0);
         if (serve_blob) {
             send_all_fd(sock, ps5param_cache_data(), ps5param_cache_size());
             if (fd >= 0) close(fd);
             return;
         }
         char *buf = iobuf;
         ssize_t nr;
         while ((nr = read(fd, buf, BUF_SIZE)) > 0) {
             ssize_t off = 0;
             while (off < nr) {
                 ssize_t s = send(sock, buf + off, nr - off, 0);
                 if (s <= 0) break;
                 off += s;
             }
             if (off < nr) break;
         }
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

     /* GET /api/read_file?name=<path>&offset=N&length=N -> read chunk as base64 JSON */
     if (strcmp(method, "GET") == 0 && strncmp(url, "/api/read_file", 14) == 0) {
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

         /* Parse optional offset and length */
         off_t req_off = 0;
         size_t req_len = 0; /* 0 = whole file */
         char *op = strstr(url, "offset=");
         if (op) req_off = (off_t)atoll(op + 7);
         char *lp = strstr(url, "length=");
         if (lp) req_len = (size_t)atoll(lp + 7);

         char filepath[MAX_PATH_LEN];
         snprintf(filepath, sizeof(filepath), "%s/%s", g_mount_point, fname);
         struct stat st;
         if (stat(filepath, &st) < 0 || !S_ISREG(st.st_mode)) {
             http_json(sock, "{\"error\":\"File not found\"}"); return;
         }

         /* Clamp offset/length */
         if (req_off >= st.st_size) req_off = st.st_size;
         if (req_len == 0 || req_len > (size_t)(st.st_size - req_off))
             req_len = (size_t)(st.st_size - req_off);
         /* Cap single read at 64KB */
         if (req_len > 262144) req_len = 262144; /* 256KB max per read */

         int fd = open(filepath, O_RDONLY);
         if (fd < 0) { http_json(sock, "{\"error\":\"Cannot read file\"}"); return; }
         uint8_t *fbuf = malloc(req_len);
         if (!fbuf) { close(fd); http_json(sock, "{\"error\":\"Out of memory\"}"); return; }
         ssize_t nr = pread(fd, fbuf, req_len, req_off);
         close(fd);
         if (nr < 0) { free(fbuf); http_json(sock, "{\"error\":\"Read error\"}"); return; }

         size_t b64_len = 4 * ((nr + 2) / 3) + 1;
         size_t json_len = b64_len + 128;
         char *json = malloc(json_len);
         if (!json) { free(fbuf); http_json(sock, "{\"error\":\"Out of memory\"}"); return; }
         int pos = snprintf(json, json_len, "{\"total\":%lld,\"offset\":%lld,\"length\":%d,\"data\":\"",
                            (long long)st.st_size, (long long)req_off, (int)nr);
         b64_encode(fbuf, nr, json + pos, json_len - pos);
         pos += strlen(json + pos);
         snprintf(json + pos, json_len - pos, "\"}");
         free(fbuf);
         http_json(sock, json);
         free(json);
         return;
     }

     /* POST /api/write_file?name=<path> -> write base64 JSON body to file */
     if (strcmp(method, "POST") == 0 && strncmp(url, "/api/write_file", 15) == 0) {
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

         /* Read POST body */
         char *cl_hdr = strcasestr(req, "Content-Length:");
         size_t body_len = 0;
         if (cl_hdr) body_len = (size_t)atol(cl_hdr + 15);
         if (body_len == 0 || body_len > 4 * 1024 * 1024) {
             http_json(sock, "{\"error\":\"Invalid body\"}"); return;
         }
         char *body = malloc(body_len + 1);
         if (!body) { http_json(sock, "{\"error\":\"Out of memory\"}"); return; }
         char *hdr_end = strstr(req, "\r\n\r\n");
         size_t hdr_len = hdr_end ? (hdr_end + 4 - req) : n;
         size_t already = (n > (int)hdr_len) ? n - hdr_len : 0;
         if (already > body_len) already = body_len;
         if (already) memcpy(body, req + hdr_len, already);
         size_t got = already;
         while (got < body_len) {
             ssize_t r2 = recv(sock, body + got, body_len - got, 0);
             if (r2 <= 0) break;
             got += r2;
         }
         body[got] = 0;

         /* Body is base64 string */
         size_t dec_sz = (got * 3) / 4 + 4;
         uint8_t *dec = malloc(dec_sz);
         if (!dec) { free(body); http_json(sock, "{\"error\":\"Out of memory\"}"); return; }
         int dec_len = b64_decode(body, got, dec, dec_sz);
         free(body);

         char filepath[MAX_PATH_LEN];
         snprintf(filepath, sizeof(filepath), "%s/%s", g_mount_point, fname);
         int fd = open(filepath, O_CREAT | O_WRONLY | O_TRUNC, 0777);
         if (fd < 0) { free(dec); http_json(sock, "{\"error\":\"Cannot write file\"}"); return; }
         write(fd, dec, dec_len);
         close(fd);
         sync();
         free(dec);
         printf("[GarlicMgr] Wrote %d bytes to %s\n", dec_len, fname);
         char json[128];
         snprintf(json, sizeof(json), "{\"ok\":true,\"size\":%d}", dec_len);
         http_json(sock, json);
         return;
     }

     /* POST /api/patch_file?name=<path>&offset=N&length=N -> patch bytes in file */
     if (strcmp(method, "POST") == 0 && strncmp(url, "/api/patch_file", 15) == 0) {
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

         off_t patch_off = 0;
         char *op = strstr(url, "offset=");
         if (op) patch_off = (off_t)atoll(op + 7);

         /* Read POST body (base64) */
         char *cl_hdr = strcasestr(req, "Content-Length:");
         size_t body_len = 0;
         if (cl_hdr) body_len = (size_t)atol(cl_hdr + 15);
         if (body_len == 0 || body_len > 1024 * 1024) {
             http_json(sock, "{\"error\":\"Invalid body\"}"); return;
         }
         char *body = malloc(body_len + 1);
         if (!body) { http_json(sock, "{\"error\":\"Out of memory\"}"); return; }
         char *hdr_end = strstr(req, "\r\n\r\n");
         size_t hdr_len = hdr_end ? (hdr_end + 4 - req) : n;
         size_t already = (n > (int)hdr_len) ? n - hdr_len : 0;
         if (already > body_len) already = body_len;
         if (already) memcpy(body, req + hdr_len, already);
         size_t got = already;
         while (got < body_len) {
             ssize_t r2 = recv(sock, body + got, body_len - got, 0);
             if (r2 <= 0) break;
             got += r2;
         }
         body[got] = 0;

         /* Decode base64 */
         size_t dec_sz = (got * 3) / 4 + 4;
         uint8_t *dec = malloc(dec_sz);
         if (!dec) { free(body); http_json(sock, "{\"error\":\"Out of memory\"}"); return; }
         int dec_len = b64_decode(body, got, dec, dec_sz);
         free(body);

         char filepath[MAX_PATH_LEN];
         snprintf(filepath, sizeof(filepath), "%s/%s", g_mount_point, fname);
         int fd = open(filepath, O_WRONLY);
         if (fd < 0) { free(dec); http_json(sock, "{\"error\":\"Cannot open file\"}"); return; }
         ssize_t written = pwrite(fd, dec, dec_len, patch_off);
         close(fd);
         sync();
         free(dec);
         printf("[GarlicMgr] Patched %d bytes at offset %lld in %s\n", (int)written, (long long)patch_off, fname);
         char json[128];
         snprintf(json, sizeof(json), "{\"ok\":true,\"written\":%d}", (int)written);
         http_json(sock, json);
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
         char *buf = iobuf;
         ssize_t nr;
         while ((nr = read(fd, buf, BUF_SIZE)) > 0)
             send(sock, buf, nr, 0);
         close(fd);
         return;
     }

     /* GET /api/usb_list -> detect connected USB drives */
     if (strcmp(method, "GET") == 0 && strcmp(url, "/api/usb_list") == 0) {
         char json[256] = "{\"usb\":[";
         int pos = strlen(json), first = 1;
         for (int u = 0; u < 8; u++) {
             char mp[32];
             snprintf(mp, sizeof(mp), "/mnt/usb%d", u);
             struct stat st;
             if (stat(mp, &st) == 0 && S_ISDIR(st.st_mode)) {
                 /* Check if it's actually mounted (has contents) */
                 DIR *d = opendir(mp);
                 if (d) {
                     struct dirent *ent;
                     int has_files = 0;
                     while ((ent = readdir(d))) {
                         if (ent->d_name[0] != '.') { has_files = 1; break; }
                     }
                     closedir(d);
                     if (has_files) {
                         if (!first) json[pos++] = ',';
                         pos += snprintf(json + pos, sizeof(json) - pos, "%d", u);
                         first = 0;
                     }
                 }
             }
         }
         snprintf(json + pos, sizeof(json) - pos, "]}");
         http_json(sock, json);
         return;
     }

     /* GET /api/account_current -> read-only foreground PS5 profile lookup. */
     if (strcmp(method,"GET") == 0 && strcmp(url,"/api/account_current") == 0) {
         char uid_hex[9], username[17], escaped_name[128], json[512];
         uint64_t account_id = 0; const char *error = NULL;
         if (current_psn_account(uid_hex,username,&account_id,&error) < 0) {
             snprintf(json,sizeof(json),"{\"error\":\"%s\"}",error);
             http_json(sock,json); return;
         }
         json_escape(username,escaped_name,sizeof(escaped_name));
         snprintf(json,sizeof(json),
             "{\"ok\":true,\"user_id\":\"%s\",\"user_name\":\"%s\",\"account_id\":\"%016llX\"}",
             uid_hex,escaped_name,(unsigned long long)account_id);
         http_json(sock,json); return;
     }

     /* GET /api/users -> list users with usernames */
     if (strcmp(method, "GET") == 0 && strcmp(url, "/api/users") == 0) {
         DIR *home = opendir("/user/home");
         char json[2048] = "{\"users\":[";
         int pos = strlen(json), first = 1;
         if (home) {
             struct dirent *ue;
             while ((ue = readdir(home))) {
                 if (ue->d_name[0] == '.') continue;
                 char upath[MAX_PATH_LEN];
                 snprintf(upath, sizeof(upath), "/user/home/%s/username.dat", ue->d_name);
                 char uname[17] = {0};
                 int fd = open(upath, O_RDONLY);
                 if (fd >= 0) {
                     read(fd, uname, 16);
                     uname[16] = 0;
                     close(fd);
                 }
                 if (!uname[0]) snprintf(uname, sizeof(uname), "User %s", ue->d_name);
                 if (!first) json[pos++] = ',';
                 pos += snprintf(json + pos, sizeof(json) - pos,
                     "{\"id\":\"%s\",\"name\":\"%s\"}", ue->d_name, uname);
                 first = 0;
             }
             closedir(home);
         }
         snprintf(json + pos, sizeof(json) - pos, "]}");
         http_json(sock, json);
         return;
     }

     /* GET /api/saves */
     if (strcmp(method, "GET") == 0 && strcmp(url, "/api/saves") == 0) {
         scan_saves();
         int need = snprintf(NULL, 0, "{\"saves\":[");
         for (int i = 0; i < g_save_count; i++) {
             if (i > 0) need++;
             const char *tname = lookup_title(g_saves[i].title_id);
             const char *stype = g_saves[i].is_ps4 ? "ps4" : "ps5";
             /* Count escaped title_name length */
             int tname_esc_len = 0;
             if (tname) {
                 for (const char *c = tname; *c; c++)
                     tname_esc_len += (*c == '"' || *c == '\\' || *c < 0x20) ? 2 : 1;
             }
             need += snprintf(NULL, 0,
                 "{\"title_id\":\"%s\",\"save_name\":\"%s\",\"path\":\"%s\",\"dir\":\"%s\",\"title_name\":\"\",\"type\":\"%s\",\"backup\":%s,\"usb\":%s,\"uid\":\"%s\"}",
                 g_saves[i].title_id, g_saves[i].save_name, g_saves[i].path, g_saves[i].dir_name,
                 stype, g_saves[i].is_backup ? "true" : "false", g_saves[i].is_usb ? "true" : "false",
                 g_saves[i].user_id);
             need += tname_esc_len;
         }
         need += snprintf(NULL, 0, "]}");
         char *json = malloc(need + 1);
         if (!json) { http_json(sock, "{\"error\":\"Out of memory\"}"); return; }
         int pos = snprintf(json, need + 1, "{\"saves\":[");
         for (int i = 0; i < g_save_count; i++) {
             if (i > 0) json[pos++] = ',';
             const char *tname = lookup_title(g_saves[i].title_id);
             const char *stype = g_saves[i].is_ps4 ? "ps4" : "ps5";
             /* Escape title_name for JSON */
             char esc_tname[512] = {0};
             if (tname) {
                 int tp = 0;
                 for (const char *c = tname; *c && tp < (int)sizeof(esc_tname) - 2; c++) {
                     if (*c == '"' || *c == '\\') { esc_tname[tp++] = '\\'; esc_tname[tp++] = *c; }
                     else if (*c >= 0x20) { esc_tname[tp++] = *c; }
                 }
                 esc_tname[tp] = 0;
             }
             pos += snprintf(json + pos, need + 1 - pos,
                 "{\"title_id\":\"%s\",\"save_name\":\"%s\",\"path\":\"%s\",\"dir\":\"%s\",\"title_name\":\"%s\",\"type\":\"%s\",\"backup\":%s,\"usb\":%s,\"uid\":\"%s\"}",
                 g_saves[i].title_id, g_saves[i].save_name, g_saves[i].path, g_saves[i].dir_name,
                 esc_tname, stype, g_saves[i].is_backup ? "true" : "false", g_saves[i].is_usb ? "true" : "false",
                 g_saves[i].user_id);
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
         if (idx < 0 || idx >= g_save_count) {
             http_json(sock, "{\"error\":\"Invalid index\"}"); return;
         }

         /* Check if this is a decrypted folder (USB) — just list contents, no mount */
         struct stat path_st;
         int is_dir = (stat(g_saves[idx].path, &path_st) == 0 && S_ISDIR(path_st.st_mode));

         const char *browse_root;
         if (is_dir) {
             browse_root = g_saves[idx].path;
             /* Set mount point so read_file/write_file work on USB folders */
             snprintf(g_mount_point, sizeof(g_mount_point), "%s", browse_root);
             g_mounted = 1;
             g_mounted_idx = idx;
             g_mounted_path[0] = 0;
             g_local_copy[0] = 0;
             ps5param_clear_cache();
         } else {
             int ret = mount_save(idx);
             if (ret < 0) {
                 char json[1200], escaped_error[1024];
                 if (g_mount_error[0]) {
                     json_escape(g_mount_error, escaped_error, sizeof(escaped_error));
                     snprintf(json, sizeof(json), "{\"error\":\"%s\"}", escaped_error);
                 } else {
                     snprintf(json, sizeof(json), "{\"error\":\"Mount failed: %d (0x%x)\"}", ret, ret);
                 }
                 http_json(sock, json);
                 return;
             }
             browse_root = g_mount_point;
         }

         /* Parse param.sfo properly using key-value parser */
         char acct_id[20] = {0};
         char save_title[64] = {0};
         char sfo_title_id[16] = {0};
         char sfo_path[MAX_PATH_LEN];
         snprintf(sfo_path, sizeof(sfo_path), "%s/sce_sys/param.sfo", browse_root);
         sfo_info_t sfo_info;
         uint8_t sfo_buf[0x8000];
         int sfo_from_blob = 0;
         int sfo_bytes = read_effective_param_sfo(sfo_path, sfo_buf, sizeof(sfo_buf), &sfo_from_blob);
         int sfo_ret = sfo_bytes > 0 ? parse_sfo_mem(sfo_buf, (size_t)sfo_bytes, &sfo_info)
                                     : (sfo_bytes == 0 ? -2 : -1);
         if (sfo_ret < 0) memset(&sfo_info, 0, sizeof(sfo_info));
         int sfo_zeroed = (sfo_ret == -2) && !sfo_from_blob;
         int sfo_db_found = 0;
         if (sfo_zeroed) {
             /* Strip sdimg_ prefix for DB dir_name lookup */
             const char *db_dir = g_saves[idx].save_name;
             if (strncmp(db_dir, "sdimg_", 6) == 0) db_dir += 6;
             const char *db_types[] = {"savedata_prospero", "savedata"};
             for (int dt = 0; dt < 2 && !sfo_db_found; dt++) {
                 char db_path[MAX_PATH_LEN];
                 snprintf(db_path, sizeof(db_path), "/system_data/%s/%s/db/user/savedata.db",
                          db_types[dt], g_saves[idx].user_id);
                 sqlite3 *db = NULL;
                 if (sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
                     char sql[512];
                     snprintf(sql, sizeof(sql),
                         "SELECT 1 FROM savedata WHERE title_id='%s' AND dir_name='%s' LIMIT 1",
                         g_saves[idx].title_id, db_dir);
                     sqlite3_stmt *st = NULL;
                     if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK &&
                         sqlite3_step(st) == SQLITE_ROW) sfo_db_found = 1;
                     if (st) sqlite3_finalize(st);
                     sqlite3_close(db);
                 }
             }
         }
         if (sfo_ret == 0) {
             if (sfo_from_blob) cache_params_hmac_mem(sfo_buf, (size_t)sfo_bytes);
             else cache_params_hmac(sfo_path);
             snprintf(acct_id, sizeof(acct_id), "0x%016llX",
                      (unsigned long long)sfo_info.account_id);
             if (sfo_info.main_title[0]) {
                 int tp = 0;
                 for (int ti = 0; sfo_info.main_title[ti] && tp < (int)sizeof(save_title) - 2; ti++) {
                     char ch = sfo_info.main_title[ti];
                     if (ch == '"' || ch == '\\') { save_title[tp++] = '\\'; }
                     if (ch >= 0x20) save_title[tp++] = ch;
                 }
                 save_title[tp] = 0;
             }
             if (sfo_info.title_id[0])
                 strncpy(sfo_title_id, sfo_info.title_id, sizeof(sfo_title_id) - 1);
         }

         const char *tid = sfo_title_id[0] ? sfo_title_id : g_saves[idx].title_id;
         int need = snprintf(NULL, 0,
             "{\"title_id\":\"%s\",\"save_name\":\"%s\",\"mount\":\"%s\","
             "\"account_id\":\"%s\",\"save_title\":\"%s\",\"sfo_zeroed\":%s,\"db_found\":%s,\"blob_found\":%s,\"files\":[",
             tid, g_saves[idx].save_name, browse_root, acct_id, save_title,
             sfo_zeroed ? "true" : "false", sfo_db_found ? "true" : "false",
             sfo_from_blob ? "true" : "false");
         need += json_list_dir(NULL, 0, browse_root, "");
         need += snprintf(NULL, 0, "]}");
         char *json = malloc(need + 1);
         if (!json) { http_json(sock, "{\"error\":\"Out of memory\"}"); return; }
         int pos = snprintf(json, need + 1,
             "{\"title_id\":\"%s\",\"save_name\":\"%s\",\"mount\":\"%s\","
             "\"account_id\":\"%s\",\"save_title\":\"%s\",\"sfo_zeroed\":%s,\"db_found\":%s,\"blob_found\":%s,\"files\":[",
             tid, g_saves[idx].save_name, browse_root, acct_id, save_title,
             sfo_zeroed ? "true" : "false", sfo_db_found ? "true" : "false",
             sfo_from_blob ? "true" : "false");
         pos += json_list_dir(json + pos, need + 1 - pos, browse_root, "");
         snprintf(json + pos, need + 1 - pos, "]}");
         http_json(sock, json);
         free(json);
         return;
     }

     /* GET /api/db_titles -> list all title_id/dir_name combos from savedata DBs */
     if (strcmp(method, "GET") == 0 && strncmp(url, "/api/db_titles", 14) == 0) {
         char uid_hex[16] = {0};
         char *uidp = strstr(url, "uid=");
         if (uidp) { strncpy(uid_hex, uidp + 4, sizeof(uid_hex) - 1);
             char *amp = strchr(uid_hex, '&'); if (amp) *amp = 0; }
         if (!uid_hex[0]) {
             int lu = 0; sceUserServiceGetForegroundUser(&lu);
             snprintf(uid_hex, sizeof(uid_hex), "%x", (uint32_t)lu);
         }

         char resp[32768];
         int pos = 0;
         pos += snprintf(resp + pos, sizeof(resp) - pos, "{\"titles\":[");

         const char *db_types[] = {"savedata_prospero", "savedata"};
         int first = 1;
         for (int dt = 0; dt < 2; dt++) {
             char db_path[MAX_PATH_LEN];
             snprintf(db_path, sizeof(db_path),
                      "/system_data/%s/%s/db/user/savedata.db", db_types[dt], uid_hex);
             sqlite3 *db = NULL;
             if (sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) continue;
             sqlite3_stmt *stmt = NULL;
             const char *sql = "SELECT title_id, dir_name, main_title FROM savedata ORDER BY title_id, dir_name";
             if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
                 while (sqlite3_step(stmt) == SQLITE_ROW) {
                     const char *tid = (const char *)sqlite3_column_text(stmt, 0);
                     const char *dir = (const char *)sqlite3_column_text(stmt, 1);
                     const char *title = (const char *)sqlite3_column_text(stmt, 2);
                     if (!tid || !dir) continue;
                     if (!first) pos += snprintf(resp + pos, sizeof(resp) - pos, ",");
                     first = 0;
                     /* Escape title for JSON */
                     char esc_title[256] = {0};
                     if (title) {
                         int j = 0;
                         for (int k = 0; title[k] && j < (int)sizeof(esc_title) - 2; k++) {
                             if (title[k] == '"' || title[k] == '\\') esc_title[j++] = '\\';
                             esc_title[j++] = title[k];
                         }
                     }
                     pos += snprintf(resp + pos, sizeof(resp) - pos,
                         "{\"tid\":\"%s\",\"dir\":\"%s\",\"title\":\"%s\",\"ps4\":%d}",
                         tid, dir, esc_title, dt == 1 ? 1 : 0);
                     if (pos >= (int)sizeof(resp) - 256) break;
                 }
             }
             if (stmt) sqlite3_finalize(stmt);
             sqlite3_close(db);
         }
         pos += snprintf(resp + pos, sizeof(resp) - pos, "]}");
         http_json(sock, resp);
         return;
     }

     /* GET /api/regen_sfo -> regenerate param.sfo from savedata DB for mounted save */
     if (strcmp(method, "GET") == 0 && strncmp(url, "/api/regen_sfo", 14) == 0) {
         if (!g_mounted) {
             http_json(sock, "{\"error\":\"No save mounted\"}"); return;
         }

         /* PS5: the real metadata was recovered from the PS5PARAM blob before
          * mounting.  Restore it into the PFS instead of rebuilding a lossy
          * SFO from the display-only savedata DB. */
         if (ps5param_cached_for_mount(g_mount_point)) {
             char real_sfo_path[MAX_PATH_LEN];
             snprintf(real_sfo_path, sizeof(real_sfo_path), "%s/sce_sys/param.sfo", g_mount_point);
             if (install_sfo_file(real_sfo_path, ps5param_cache_data(), ps5param_cache_size()) == 0) {
                 cache_params_hmac_mem(ps5param_cache_data(), ps5param_cache_size());
                 sfo_info_t si;
                 if (parse_sfo(real_sfo_path, &si) == 0) {
                     char t_esc[512], st_esc[512], resp[1280];
                     json_escape(si.main_title, t_esc, sizeof(t_esc));
                     json_escape(si.sub_title, st_esc, sizeof(st_esc));
                     snprintf(resp, sizeof(resp),
                              "{\"ok\":true,\"blob\":true,\"title\":\"%s\",\"subtitle\":\"%s\","
                              "\"blocks\":%llu,\"system_blocks\":%llu}",
                              t_esc, st_esc,(unsigned long long)si.blocks,(unsigned long long)si.system_blocks);
                     http_json(sock, resp);
                     return;
                 }
             } else {
                 http_json(sock, "{\"error\":\"Cannot restore real PS5 metadata\"}"); return;
             }
         }

         /* Accept title_id and dir_name from query params (for zeroed SFO where we can't detect) */
         char q_title_id[32] = {0}, q_dir_name[256] = {0};
         char *tp = strstr(url, "title_id=");
         if (tp) { tp += 9; int i = 0;
             while (tp[i] && tp[i] != '&' && i < (int)sizeof(q_title_id) - 1) { q_title_id[i] = tp[i]; i++; }
             q_title_id[i] = 0;
         }
         char *dp = strstr(url, "dir_name=");
         if (dp) { dp += 9; int i = 0;
             while (dp[i] && dp[i] != '&' && i < (int)sizeof(q_dir_name) - 1) { q_dir_name[i] = dp[i]; i++; }
             q_dir_name[i] = 0;
         }

         /* Use query params if provided, else fall back to save entry */
         const char *lookup_tid = q_title_id[0] ? q_title_id : (g_mounted_idx >= 0 ? g_saves[g_mounted_idx].title_id : "");
         const char *lookup_dir = q_dir_name[0] ? q_dir_name : (g_mounted_idx >= 0 ? g_saves[g_mounted_idx].save_name : "");
         /* Strip sdimg_ prefix for DB lookup */
         if (strncmp(lookup_dir, "sdimg_", 6) == 0) lookup_dir += 6;

         if (!lookup_tid[0] || !lookup_dir[0]) {
             http_json(sock, "{\"error\":\"Missing title_id or dir_name\"}"); return;
         }

         /* Get uid — from save entry or foreground user */
         char uid_hex[16] = {0};
         if (g_mounted_idx >= 0 && g_saves[g_mounted_idx].user_id[0]) {
             strncpy(uid_hex, g_saves[g_mounted_idx].user_id, sizeof(uid_hex) - 1);
         } else {
             char *uidp = strstr(url, "uid=");
             if (uidp) { strncpy(uid_hex, uidp + 4, sizeof(uid_hex) - 1);
                 char *amp = strchr(uid_hex, '&'); if (amp) *amp = 0; }
             if (!uid_hex[0]) {
                 int lu = 0; sceUserServiceGetForegroundUser(&lu);
                 snprintf(uid_hex, sizeof(uid_hex), "%x", (uint32_t)lu);
             }
         }

         int is_ps4 = (g_mounted_idx >= 0) ? g_saves[g_mounted_idx].is_ps4 : 0;

         /* Try both PS5 and PS4 DBs */
         sqlite3 *db = NULL;
         int db_opened = 0;
         const char *db_types[] = {"savedata_prospero", "savedata"};
         for (int dt = 0; dt < 2 && !db_opened; dt++) {
             char db_path[MAX_PATH_LEN];
             snprintf(db_path, sizeof(db_path),
                      "/system_data/%s/%s/db/user/savedata.db", db_types[dt], uid_hex);
             if (sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
                 /* Check if entry exists */
                 char chk[512];
                 snprintf(chk, sizeof(chk), "SELECT 1 FROM savedata WHERE title_id='%s' AND dir_name='%s' LIMIT 1",
                          lookup_tid, lookup_dir);
                 sqlite3_stmt *chk_st = NULL;
                 if (sqlite3_prepare_v2(db, chk, -1, &chk_st, NULL) == SQLITE_OK &&
                     sqlite3_step(chk_st) == SQLITE_ROW) {
                     db_opened = 1;
                     is_ps4 = (dt == 1);
                 }
                 if (chk_st) sqlite3_finalize(chk_st);
                 if (!db_opened) { sqlite3_close(db); db = NULL; }
             }
         }
         if (!db_opened) {
             char err[256];
             snprintf(err, sizeof(err), "{\"error\":\"No DB entry for %s/%s\"}", lookup_tid, lookup_dir);
             http_json(sock, err);
             return;
         }

         sqlite3_stmt *stmt = NULL;
         const char *sql = "SELECT main_title, sub_title, blocks, account_id, system_blocks, "
                           "user_id, game_title_id "
                           "FROM savedata WHERE title_id=? AND dir_name=? LIMIT 1";
         if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
             http_json(sock, "{\"error\":\"DB query failed\"}");
             sqlite3_close(db);
             return;
         }
         sqlite3_bind_text(stmt, 1, lookup_tid, -1, SQLITE_STATIC);
         sqlite3_bind_text(stmt, 2, lookup_dir, -1, SQLITE_STATIC);

         if (sqlite3_step(stmt) != SQLITE_ROW) {
             char err[256];
             snprintf(err, sizeof(err), "{\"error\":\"No DB entry for %s/%s\"}",
                      lookup_tid, lookup_dir);
             http_json(sock, err);
             sqlite3_finalize(stmt);
             sqlite3_close(db);
             return;
         }

         const char *main_title    = (const char *)sqlite3_column_text(stmt, 0);
         const char *sub_title     = (const char *)sqlite3_column_text(stmt, 1);
         int64_t blocks            = sqlite3_column_int64(stmt, 2);
         int64_t account_id_db     = sqlite3_column_int64(stmt, 3);
         int64_t system_blocks     = sqlite3_column_int64(stmt, 4);
         uint32_t db_user_id       = (uint32_t)sqlite3_column_int64(stmt, 5);
         const char *db_gtid       = (const char *)sqlite3_column_text(stmt, 6);

         char sfo_path[MAX_PATH_LEN];
         snprintf(sfo_path, sizeof(sfo_path), "%s/sce_sys/param.sfo", g_mount_point);
         logprintf("[GarlicMgr] Regenerating param.sfo from DB: %s/%s title='%s' aid=%lld uid=%u\n",
                   lookup_tid, lookup_dir,
                   main_title ? main_title : "", (long long)account_id_db, db_user_id);

         generate_sfo(sfo_path, lookup_tid, lookup_dir,
                      main_title ? main_title : lookup_tid,
                      sub_title ? sub_title : "",
                      (uint64_t)account_id_db, (uint64_t)blocks,
                      (uint64_t)system_blocks, db_user_id,
                      db_gtid, is_ps4,
                      g_params_hmac_valid ? g_params_hmac : NULL);

         /* Re-read to verify and return info */
         sfo_info_t sfo_info;
         if (parse_sfo(sfo_path, &sfo_info) == 0) {
             char resp[512];
             snprintf(resp, sizeof(resp),
                      "{\"ok\":true,\"title\":\"%s\",\"subtitle\":\"%s\","
                      "\"blocks\":%lld,\"system_blocks\":%lld}",
                      main_title ? main_title : "",
                      sub_title ? sub_title : "",
                      (long long)blocks, (long long)system_blocks);
             http_json(sock, resp);
         } else {
             http_json(sock, "{\"error\":\"Generated SFO failed verification\"}");
         }

         sqlite3_finalize(stmt);
         sqlite3_close(db);
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

         if (s->is_ps4 && strncmp(s->save_name, "sdimg_", 6) == 0) {
             /* PS4: zip the save image + .bin sealed key together */
             const char *savename = s->save_name + 6;
             char dir[MAX_PATH_LEN];
             strncpy(dir, s->path, sizeof(dir) - 1);
             dir[sizeof(dir) - 1] = 0;
             char *sl = strrchr(dir, '/');
             if (sl) *(sl + 1) = 0;
             char bin_path[MAX_PATH_LEN];
             snprintf(bin_path, sizeof(bin_path), "%s%s.bin", dir, savename);

             char zip_name[512];
             snprintf(zip_name, sizeof(zip_name), "%s_%s.zip", s->title_id, savename);
             char key_name[256];
             snprintf(key_name, sizeof(key_name), "%s.bin", savename);

             zip_file_t zfiles[2] = {
                 { s->path, s->save_name },
                 { bin_path, key_name }
             };
             /* Check if .bin exists; if not, just send 1 file */
             int nfiles = (stat(bin_path, &st) == 0) ? 2 : 1;

             char hdr[512];
             int hlen = snprintf(hdr, sizeof(hdr),
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Type: application/zip\r\n"
                 "Content-Disposition: attachment; filename=\"%s\"\r\n"
                 "Access-Control-Allow-Origin: *\r\n"
                 "Connection: close\r\n"
                 "\r\n", zip_name);
             send(sock, hdr, hlen, 0);
             zip_send_files(sock, zfiles, nfiles, iobuf);
         } else {
             /* PS5: stream raw image */
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
             char *buf = iobuf;
             ssize_t nr;
             while ((nr = read(fd, buf, BUF_SIZE)) > 0)
                 send(sock, buf, nr, 0);
             close(fd);
         }
         return;
     }

     /* GET /api/download -> tar stream */
     if (strcmp(method, "GET") == 0 && strcmp(url, "/api/download") == 0) {
         if (!g_mounted) { http_json(sock, "{\"error\":\"No save mounted\"}"); return; }
         char metadata[2048];
         const char *image = g_local_copy[0] ? g_local_copy : g_mounted_path;
         const char *export_metadata = NULL;
         /* A decrypted USB folder has no mounted image; retain its existing
          * sidecar, if present, and keep legacy folder downloads available. */
         if (image[0]) {
             int meta_len=chives_export_json(image,g_mount_point,metadata,sizeof(metadata));
             if (meta_len < 0) {
                 http_json(sock, "{\"error\":\"Cannot read original PFS geometry for export\"}"); return;
             }
             if (meta_len > 0) export_metadata = metadata;
         }
         char hdr[512];
         int hlen = snprintf(hdr, sizeof(hdr),
             "HTTP/1.1 200 OK\r\n"
             "Content-Type: application/zip\r\n"
             "Access-Control-Allow-Origin: *\r\n"
             "Connection: close\r\n"
             "\r\n");
         send(sock, hdr, hlen, 0);
         zip_send(sock, g_mount_point, export_metadata);
         return;
     }

     /* GET /api/dump_usb?idx=N&usb=U -> mount, copy decrypted files to USB, unmount */
     if (strcmp(method, "GET") == 0 && strncmp(url, "/api/dump_usb", 13) == 0) {
         scan_saves();
         int idx = -1, usb_num = 0;
         char *p = strstr(url, "idx=");
         if (p) idx = atoi(p + 4);
         p = strstr(url, "usb=");
         if (p) usb_num = atoi(p + 4);
         if (usb_num < 0 || usb_num > 7) usb_num = 0;
         if (idx < 0 || idx >= g_save_count) {
             http_json(sock, "{\"error\":\"Invalid index\"}"); return;
         }
         save_entry_t *s = &g_saves[idx];
         pid_t rpid = getpid();
         kernel_set_ucred_uid(rpid, 0);
         kernel_set_ucred_authid(rpid, 0x4800000000000010ULL);

         /* Mount the save */
         if (g_mounted) unmount_save();
         int ret = mount_save(idx);
         if (ret < 0) {
             char json[128];
             snprintf(json, sizeof(json), "{\"error\":\"Mount failed: %d\"}", ret);
             http_json(sock, json);
             return;
         }

         /* Create USB destination dirs */
         char usb_base[64];
         snprintf(usb_base, sizeof(usb_base), "/mnt/usb%d", usb_num);
         char tmp[MAX_PATH_LEN];
         snprintf(tmp, sizeof(tmp), "%s/PS5", usb_base); mkdir(tmp, 0777);
         snprintf(tmp, sizeof(tmp), "%s/PS5/SAVEDATA", usb_base); mkdir(tmp, 0777);
         snprintf(tmp, sizeof(tmp), "%s/PS5/SAVEDATA/GARLIC", usb_base); mkdir(tmp, 0777);
         char title_dir[MAX_PATH_LEN];
         snprintf(title_dir, sizeof(title_dir), "%s/PS5/SAVEDATA/GARLIC/%s", usb_base, s->title_id);
         mkdir(title_dir, 0777);
         char save_dir[MAX_PATH_LEN];
         snprintf(save_dir, sizeof(save_dir), "%s/%s", title_dir, s->save_name);

         /* Copy decrypted files from mount point to USB */
         int cpret = copy_dir_recursive(g_mount_point, save_dir);
         if (cpret == 0) cpret = chives_write_export(g_local_copy[0] ? g_local_copy : g_mounted_path,
                                                    g_mount_point,save_dir);

         /* PS5: the in-PFS param.sfo is a zero placeholder; write the real one
          * recovered from the header blob into the exported folder. */
         if (cpret == 0 && ps5param_cached_for_mount(g_mount_point)) {
             char usb_sfo[MAX_PATH_LEN];
             snprintf(usb_sfo, sizeof(usb_sfo), "%s/sce_sys/param.sfo", save_dir);
             install_sfo_file(usb_sfo, ps5param_cache_data(), ps5param_cache_size());
         }

         /* Unmount (no changes made, just reading) */
         unmount_save();

         if (cpret < 0) {
             http_json(sock, "{\"error\":\"Failed to copy files to USB\"}");
             return;
         }

         char json[512];
         snprintf(json, sizeof(json),
             "{\"ok\":true,\"path\":\"%s\"}", save_dir);
         http_json(sock, json);
         return;
     }

     /* GET /api/unmount: an already completed finalization is not a native
      * unmount failure. A real failure still keeps the tracked mount intact. */
     if (strcmp(method, "GET") == 0 && strcmp(url, "/api/unmount") == 0) {
         if (!g_mounted) { http_json(sock,"{\"ok\":true,\"already_unmounted\":true}"); return; }
         int ret = unmount_save();
         char json[192];
         if (ret < 0) snprintf(json,sizeof(json),"{\"ok\":false,\"error\":\"Native unmount failed (result=%d); mount retained\"}",ret);
         else snprintf(json,sizeof(json),"{\"ok\":true}");
         http_json(sock,json); return;
     }

     /* GET /api/log */
     if (strcmp(method, "GET") == 0 && strcmp(url, "/api/log") == 0) {
         g_logbuf[g_logpos] = 0;
         http_send(sock, "200 OK", "text/plain", g_logbuf, g_logpos);
         return;
     }

     /* ── Server-side editor APIs ─────────────────────────────────── */

     /* GET /api/editor/open?name=<path> — load file into server memory */
     if (strcmp(method, "GET") == 0 && strncmp(url, "/api/editor/open", 16) == 0) {
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

         /* Close previous editor buffer */
         if (g_ed_buf) { free(g_ed_buf); g_ed_buf = NULL; }
         g_ed_size = 0; g_ed_dirty = 0; g_ed_name[0] = 0;

         char filepath[MAX_PATH_LEN];
         snprintf(filepath, sizeof(filepath), "%s/%s", g_mount_point, fname);
         int use_blob = ps5param_cached_for_mount(g_mount_point) && ps5param_is_sfo_name(fname);
         if (use_blob) {
             g_ed_buf = malloc(ps5param_cache_size());
             if (!g_ed_buf) { http_json(sock, "{\"error\":\"Out of memory\"}"); return; }
             memcpy(g_ed_buf, ps5param_cache_data(), ps5param_cache_size());
             g_ed_size = ps5param_cache_size();
         } else {
             struct stat st;
             if (stat(filepath, &st) < 0 || !S_ISREG(st.st_mode)) {
                 http_json(sock, "{\"error\":\"File not found\"}"); return;
             }
             g_ed_buf = malloc(st.st_size ? (size_t)st.st_size : 1);
             if (!g_ed_buf) { http_json(sock, "{\"error\":\"Out of memory\"}"); return; }
             int fd = open(filepath, O_RDONLY);
             if (fd < 0) { free(g_ed_buf); g_ed_buf = NULL; http_json(sock, "{\"error\":\"Cannot read\"}"); return; }
             while (g_ed_size < (size_t)st.st_size) {
                 ssize_t nr = read(fd, g_ed_buf + g_ed_size, (size_t)st.st_size - g_ed_size);
                 if (nr < 0 && errno == EINTR) continue;
                 if (nr <= 0) break;
                 g_ed_size += (size_t)nr;
             }
             close(fd);
             if (g_ed_size != (size_t)st.st_size) {
                 free(g_ed_buf); g_ed_buf = NULL;
                 http_json(sock, "{\"error\":\"Incomplete file read\"}"); return;
             }
         }
         snprintf(g_ed_image, sizeof(g_ed_image), "%s", g_local_copy[0] ? g_local_copy : g_mounted_path);
         strncpy(g_ed_name, fname, sizeof(g_ed_name) - 1);
         logprintf("[GarlicMgr] Editor opened: %s (%zu bytes)\n", fname, g_ed_size);
         char json[256];
         snprintf(json, sizeof(json), "{\"ok\":true,\"size\":%zu}", g_ed_size);
         http_json(sock, json);
         return;
     }

     /* GET /api/editor/read?offset=N&length=N — return raw bytes from buffer */
     if (strcmp(method, "GET") == 0 && strncmp(url, "/api/editor/read", 16) == 0) {
         if (!g_ed_buf) { http_json(sock, "{\"error\":\"No file open\"}"); return; }
         size_t off = 0, len = 4096;
         char *op = strstr(url, "offset=");
         char *lp = strstr(url, "length=");
         if (op) off = strtoul(op + 7, NULL, 10);
         if (lp) len = strtoul(lp + 7, NULL, 10);
         if (off >= g_ed_size) { http_send(sock, "200 OK", "application/octet-stream", "", 0); return; }
         if (off + len > g_ed_size) len = g_ed_size - off;
         http_send(sock, "200 OK", "application/octet-stream", g_ed_buf + off, len);
         return;
     }

     /* POST /api/editor/patch — body: raw bytes, query: offset=N */
     if (strcmp(method, "POST") == 0 && strncmp(url, "/api/editor/patch", 17) == 0) {
         if (!g_ed_buf) { http_json(sock, "{\"error\":\"No file open\"}"); return; }
         size_t off = 0;
         char *op = strstr(url, "offset=");
         if (op) off = strtoul(op + 7, NULL, 10);

         size_t clen = 0;
         char *cl = strcasestr(req, "Content-Length:");
         if (cl) clen = strtoul(cl + 15, NULL, 10);

         char *body_start = strstr(req, "\r\n\r\n");
         if (!body_start) { http_json(sock, "{\"error\":\"Bad request\"}"); return; }
         body_start += 4;
         size_t body_in_buf = n - (body_start - req);

         /* Read remaining body if needed */
         char *patch = malloc(clen);
         if (!patch) { http_json(sock, "{\"error\":\"Out of memory\"}"); return; }
         size_t got = body_in_buf < clen ? body_in_buf : clen;
         memcpy(patch, body_start, got);
         while (got < clen) {
             ssize_t r = recv(sock, patch + got, clen - got, 0);
             if (r <= 0) break;
             got += r;
         }

         if (off + got > g_ed_size) {
             /* Grow buffer if patching past end */
             char *nb = realloc(g_ed_buf, off + got);
             if (!nb) { free(patch); http_json(sock, "{\"error\":\"Out of memory\"}"); return; }
             g_ed_buf = nb;
             if (off > g_ed_size) memset(g_ed_buf + g_ed_size, 0, off - g_ed_size);
             g_ed_size = off + got;
         }
         memcpy(g_ed_buf + off, patch, got);
         free(patch);
         g_ed_dirty = 1;
         char json[128];
         snprintf(json, sizeof(json), "{\"ok\":true,\"size\":%zu}", g_ed_size);
         http_json(sock, json);
         return;
     }

     /* GET /api/editor/save — write buffer back to file */
     if (strcmp(method, "GET") == 0 && strncmp(url, "/api/editor/save", 16) == 0) {
         if (!g_ed_buf || !g_ed_name[0]) { http_json(sock, "{\"error\":\"No file open\"}"); return; }
         if (!g_mounted) { http_json(sock, "{\"error\":\"No save mounted\"}"); return; }
         const char *image = g_local_copy[0] ? g_local_copy : g_mounted_path;
         if (strcmp(image, g_ed_image)) {
             http_json(sock, "{\"error\":\"Editor belongs to a different mounted save; reopen the file\"}"); return;
         }
         int real_sfo = ps5param_is_sfo_name(g_ed_name) && ps5param_cached_for_mount(g_mount_point);
         if (real_sfo && (!sfo_bytes_valid((const uint8_t *)g_ed_buf, g_ed_size) ||
                          g_ed_size > CMP_PS5PARAM_SFO_BYTES - 20)) {
             http_json(sock, "{\"error\":\"Invalid or oversized PS5 param.sfo; edits remain unsaved\"}"); return;
         }
         char filepath[MAX_PATH_LEN];
         snprintf(filepath, sizeof(filepath), "%s/%s", g_mount_point, g_ed_name);
         int fd = open(filepath, O_CREAT | O_WRONLY | O_TRUNC, 0777);
         if (fd < 0) { http_json(sock, "{\"error\":\"Cannot write file\"}"); return; }
         garlic_upload_t u = {.expected=g_ed_size, .received=g_ed_size, .crc=UINT32_C(0xffffffff)};
         uint8_t check[4096];
         garlic_upload_write(fd, g_ed_buf, g_ed_size, &u);
         if (garlic_upload_finish(fd, filepath, &u, check, sizeof(check)) < 0) {
             http_json(sock, "{\"error\":\"File write or verification failed; edits remain unsaved\"}"); return;
         }
         size_t written = u.written;
         if (real_sfo) {
             int wr = ps5param_write_sfo(image, (const uint8_t *)g_ed_buf, (uint32_t)g_ed_size);
             if (wr < 0) {
                 http_json(sock, "{\"error\":\"PS5PARAM write or read-back failed; edits remain unsaved\"}"); return;
             }
             if (ps5param_cache_replace((const uint8_t *)g_ed_buf,(uint32_t)g_ed_size) < 0) {
                 http_json(sock, "{\"error\":\"PS5PARAM cache update failed; edits remain unsaved\"}"); return;
             }
         }
         g_ed_dirty = 0;
         logprintf("[GarlicMgr] Editor saved: %s (%zu bytes)\n", g_ed_name, g_ed_size);
         char json[128];
         snprintf(json, sizeof(json), "{\"ok\":true,\"written\":%zu}", written);
         http_json(sock, json);
         return;
     }

     /* GET /api/editor/close — free buffer */
     if (strcmp(method, "GET") == 0 && strncmp(url, "/api/editor/close", 17) == 0) {
         if (g_ed_buf) { free(g_ed_buf); g_ed_buf = NULL; }
         g_ed_size = 0; g_ed_dirty = 0; g_ed_name[0] = 0;
         http_json(sock, "{\"ok\":true}");
         return;
     }

     /* GET /api/editor/status — check editor state */
     if (strcmp(method, "GET") == 0 && strncmp(url, "/api/editor/status", 18) == 0) {
         char json[512];
         snprintf(json, sizeof(json), "{\"open\":%s,\"name\":\"%s\",\"size\":%zu,\"dirty\":%s}",
             g_ed_buf ? "true" : "false", g_ed_name, g_ed_size, g_ed_dirty ? "true" : "false");
         http_json(sock, json);
         return;
     }

     /* Shutdown is handled by the early, graceful lifecycle endpoint. */
     /* GET /api/status */
     if (strcmp(method, "GET") == 0 && strcmp(url, "/api/status") == 0) {
         char json[512];
         snprintf(json, sizeof(json),
             "{\"mounted\":%s,\"mount_point\":\"%s\",\"save_path\":\"%s\"}",
             g_mounted ? "true" : "false", g_mount_point, g_mounted_path);
         http_json(sock, json);
         return;
     }

     /* GET/POST /api/settings/cloud -> read/write cloud backup settings */
     if (strcmp(method, "GET") == 0 && strcmp(url, "/api/settings/cloud") == 0) {
         cloud_send_settings(sock);
         return;
     }
     if (strcmp(method, "GET") == 0 && strcmp(url, "/api/settings/cloud/oauth") == 0) {
         cloud_send_oauth_settings(sock);
         return;
     }
     if (strcmp(method, "POST") == 0 && strcmp(url, "/api/settings/cloud") == 0) {
         cloud_handle_settings_post(sock, iobuf, req, n);
         return;
     }

     /* GET /api/cloud/status -> redacted config + background job status */
     if (strcmp(method, "GET") == 0 && strcmp(url, "/api/cloud/status") == 0) {
         cloud_send_status(sock);
         return;
     }

     /* Direct Google Drive OAuth placeholders: direct mode needs a TLS backend in this payload. */
     if (strcmp(method, "GET") == 0 && strncmp(url, "/api/cloud/google/", 18) == 0) {
         http_json(sock, "{\"error\":\"Direct Google Drive OAuth needs HTTPS/TLS support not available in this payload build\",\"direct_drive_supported\":false}");
         return;
     }

     /* GET /api/cloud/package_title?id=<title_id> -> encrypted ZIP for browser Drive upload */
     if (strcmp(method, "GET") == 0 && strncmp(url, "/api/cloud/package_title", 24) == 0) {
         char tid[64] = {0};
         char *tp = strstr(url, "id=");
         if (tp) url_param_decode(tp + 3, tid, sizeof(tid));
         if (!tid[0]) { http_json(sock, "{\"error\":\"Missing id\"}"); return; }

         mem_buf_t pkg;
         char filename[256], err[256] = {0};
         if (cloud_package_title(tid, iobuf, &pkg, filename, sizeof(filename), err, sizeof(err)) < 0) {
             char eesc[512], json[768];
             json_escape(err, eesc, sizeof(eesc));
             snprintf(json, sizeof(json), "{\"error\":\"%s\"}", eesc);
             http_json(sock, json);
             return;
         }
         cloud_send_package_response(sock, filename, &pkg);
         free(pkg.data);
         return;
     }

     /* GET /api/cloud/package?idx=N -> encrypted ZIP for browser Drive upload */
     if (strcmp(method, "GET") == 0 && strncmp(url, "/api/cloud/package", 18) == 0) {
         int idx = -1;
         char *p = strstr(url, "idx=");
         if (p) idx = atoi(p + 4);

         mem_buf_t pkg;
         char filename[256], err[256] = {0};
         if (cloud_package_single(idx, iobuf, &pkg, filename, sizeof(filename), err, sizeof(err)) < 0) {
             char eesc[512], json[768];
             json_escape(err, eesc, sizeof(eesc));
             snprintf(json, sizeof(json), "{\"error\":\"%s\"}", eesc);
             http_json(sock, json);
             return;
         }
         cloud_send_package_response(sock, filename, &pkg);
         free(pkg.data);
         return;
     }

     /* GET /api/cloud/upload_title?id=<title_id>&mode=enc -> FTP encrypted title backup */
     if (strcmp(method, "GET") == 0 && strncmp(url, "/api/cloud/upload_title", 23) == 0) {
         char tid[64] = {0};
         char mode[16] = "enc";
         char *tp = strstr(url, "id=");
         if (tp) url_param_decode(tp + 3, tid, sizeof(tid));
         char *mp = strstr(url, "mode=");
         if (mp) url_param_decode(mp + 5, mode, sizeof(mode));
         if (!tid[0]) { http_json(sock, "{\"error\":\"Missing id\"}"); return; }
         if (strcmp(mode, "enc") != 0) {
             http_json(sock, "{\"error\":\"Only encrypted cloud backups are supported in Phase 1\"}");
             return;
         }

         cloud_job_args_t *job = calloc(1, sizeof(*job));
         if (!job) { http_json(sock, "{\"error\":\"Out of memory\"}"); return; }
         job->is_title = 1;
         snprintf(job->title_id, sizeof(job->title_id), "%s", tid);

         char err[256] = {0};
         if (cloud_start_job(job, err, sizeof(err)) < 0) {
             free(job);
             char eesc[512], json[768];
             json_escape(err, eesc, sizeof(eesc));
             snprintf(json, sizeof(json), "{\"error\":\"%s\"}", eesc);
             http_json(sock, json);
             return;
         }
         http_json(sock, "{\"ok\":true}");
         return;
     }

     /* GET /api/cloud/upload?idx=N&mode=enc -> FTP encrypted single-save backup */
     if (strcmp(method, "GET") == 0 && strncmp(url, "/api/cloud/upload", 17) == 0) {
         int idx = -1;
         char mode[16] = "enc";
         char *p = strstr(url, "idx=");
         if (p) idx = atoi(p + 4);
         char *mp = strstr(url, "mode=");
         if (mp) url_param_decode(mp + 5, mode, sizeof(mode));
         if (strcmp(mode, "enc") != 0) {
             http_json(sock, "{\"error\":\"Only encrypted cloud backups are supported in Phase 1\"}");
             return;
         }

         scan_saves();
         if (idx < 0 || idx >= g_save_count || g_saves[idx].is_usb) {
             http_json(sock, "{\"error\":\"Invalid system save index\"}");
             return;
         }

         cloud_job_args_t *job = calloc(1, sizeof(*job));
         if (!job) { http_json(sock, "{\"error\":\"Out of memory\"}"); return; }
         job->is_title = 0;
         job->save = g_saves[idx];

         char err[256] = {0};
         if (cloud_start_job(job, err, sizeof(err)) < 0) {
             free(job);
             char eesc[512], json[768];
             json_escape(err, eesc, sizeof(eesc));
             snprintf(json, sizeof(json), "{\"error\":\"%s\"}", eesc);
             http_json(sock, json);
             return;
         }
         http_json(sock, "{\"ok\":true}");
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
         if(receive_web_image(sock,fd,"/data/save_files/_tmp_key.bin",body_start,body_in_buf,clen,iobuf)<0)return;
         size_t received=clen;
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
         if(receive_web_image(sock,fd,tmp,body_start,body_in_buf,clen,iobuf)<0)return;
         size_t received=clen;
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
         char sfo_path[MAX_PATH_LEN], json[256];
         sfo_info_t sfo;
         snprintf(sfo_path, sizeof(sfo_path), "%s/sce_sys/param.sfo", g_mount_point);
         /* PS5: restore real metadata from the header blob (in-PFS is zeroed) */
         if (!is_ps4_dec && ps5param_cached_for_mount(g_mount_point)) {
             if (install_sfo_file(sfo_path, ps5param_cache_data(), ps5param_cache_size()) < 0) {
                 http_json(sock, "{\"error\":\"Cannot restore real PS5 metadata\"}"); return;
             }
             cache_params_hmac_mem(ps5param_cache_data(), ps5param_cache_size());
         }
         parse_sfo(sfo_path, &sfo);
         /* Only include a safe title ID; missing/zeroed SFOs can still be downloaded. */
         if (strlen(sfo.title_id) != 9 ||
             (strncmp(sfo.title_id, "CUSA", 4) != 0 && strncmp(sfo.title_id, "PPSA", 4) != 0) ||
             strspn(sfo.title_id + 4, "0123456789") != 5)
             sfo.title_id[0] = '\0';
         snprintf(json, sizeof(json),
                  "{\"ok\":true,\"download\":\"/api/download\",\"title_id\":\"%s\"}", sfo.title_id);
         http_json(sock, json);
         return;
     }

     /* POST /api/import_encrypted?uid=<hex>&ps4=1 -> upload encrypted save, mount, check SFO + AID */
     if (strcmp(method, "POST") == 0 && strncmp(url, "/api/import_encrypted", 21) == 0) {
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

         int is_ps4_imp = (strstr(url, "ps4=1") != NULL);
         mkdir("/data/save_files", 0777);
         const char *tmp = is_ps4_imp ? "/data/save_files/sdimg__tmp_import" : "/data/save_files/_tmp_import";
         int fd = open(tmp, O_CREAT | O_WRONLY | O_TRUNC, 0755);
         if (fd < 0) { http_json(sock, "{\"error\":\"Cannot create temp file\"}"); return; }
         if (body_in_buf > clen) body_in_buf = clen;
         write(fd, body_start, body_in_buf);
         size_t received = body_in_buf;
         while (received < clen) {
             char *buf = iobuf;
             size_t want = BUF_SIZE < (clen - received) ? BUF_SIZE : (clen - received);
             ssize_t r = recv_all(sock, buf, want);
             if (r <= 0) break;
             write(fd, buf, r);
             received += r;
         }
         close(fd);
         printf("[GarlicMgr] import_encrypted: received %zu bytes (ps4=%d)\n", received, is_ps4_imp);

         /* For PS4, rename uploaded key to match */
         if (is_ps4_imp)
             rename("/data/save_files/_tmp_key.bin", "/data/save_files/_tmp_import.bin");

         /* Mount the encrypted image */
         int ret = mount_by_path(tmp);
         if (ret < 0) {
             unlink(tmp);
             char json[128];
             snprintf(json, sizeof(json), "{\"error\":\"Mount failed: %d\"}", ret);
             http_json(sock, json); return;
         }

         /* Parse param.sfo from mounted save */
         char sfo_path[MAX_PATH_LEN];
         snprintf(sfo_path, sizeof(sfo_path), "%s/sce_sys/param.sfo", g_mount_point);
         /* PS5: restore real metadata from the header blob before parsing so the
          * UI sees title/dir/account instead of a zeroed placeholder. */
         if (!is_ps4_imp && ps5param_cached_for_mount(g_mount_point)) {
             if (install_sfo_file(sfo_path, ps5param_cache_data(), ps5param_cache_size()) < 0) {
                 http_json(sock, "{\"error\":\"Cannot restore real PS5 metadata\"}"); return;
             }
             cache_params_hmac_mem(ps5param_cache_data(), ps5param_cache_size());
         }
         sfo_info_t sfo;
         int sfo_ret = parse_sfo(sfo_path, &sfo);
         if (sfo_ret == -1 && !is_ps4_imp && mount_nested_save_image(tmp,g_mount_point) >= 0) {
             if (ps5param_cached_for_mount(g_mount_point)) {
                 if (install_sfo_file(sfo_path,ps5param_cache_data(),ps5param_cache_size()) < 0) {
                     http_json(sock,"{\"error\":\"Cannot restore real PS5 metadata\"}"); return;
                 }
                 cache_params_hmac_mem(ps5param_cache_data(),ps5param_cache_size());
             }
             sfo_ret=parse_sfo(sfo_path,&sfo);
         }
         if (sfo_ret == -2) {
             /* Zeroed SFO — keep mounted, let UI handle via doImportFinish */
             printf("[GarlicMgr] import_encrypted: zeroed param.sfo, passing to UI\n");
             char json[128];
             snprintf(json, sizeof(json),
                      "{\"ok\":true,\"sfo_zeroed\":true,\"title_id\":\"\",\"dir_name\":\"\","
                      "\"main_title\":\"\",\"match\":true,\"exists\":false}");
             http_json(sock, json);
             return;
         }
         if (sfo_ret < 0) {
             unmount_save(); unlink(tmp);
             http_json(sock, "{\"error\":\"Cannot parse param.sfo\"}"); return;
         }
         if (!sfo.title_id[0] || !sfo.dir_name[0]) {
             unmount_save(); unlink(tmp);
             http_json(sock, "{\"error\":\"param.sfo missing TITLE_ID or SAVEDATA_DIRECTORY\"}"); return;
         }

         /* Detect PS4 vs PS5 from SFO FORMAT field: "obs"=PS4, "ppr"=PS5 */
         g_enc_ps4 = sfo_is_ps4(&sfo, g_enc_ps4);
         printf("[GarlicMgr] import_encrypted: FORMAT=%s -> %s\n",
                sfo.format, g_enc_ps4 ? "PS4" : "PS5");

         /* Get user's account_id for comparison */
         char uid_hex[16] = {0};
         char *uidp = strstr(url, "uid=");
         if (uidp) {
             strncpy(uid_hex, uidp + 4, sizeof(uid_hex) - 1);
             char *amp = strchr(uid_hex, '&');
             if (amp) *amp = 0;
         }
         if (!uid_hex[0]) {
             int local_uid = 0;
             sceUserServiceGetForegroundUser(&local_uid);
             snprintf(uid_hex, sizeof(uid_hex), "%x", (uint32_t)local_uid);
         }

         uint64_t user_aid = 0;
         int user_aid_known = get_account_id_for_user(uid_hex, &user_aid) == 0;

         int match = !user_aid_known || (sfo.account_id == user_aid);

         /* Check if save already exists on system */
         char exist_path[MAX_PATH_LEN];
         snprintf(exist_path, sizeof(exist_path), "/user/home/%s/%s/%s/sdimg_%s",
                  uid_hex, g_enc_ps4 ? "savedata" : "savedata_prospero",
                  sfo.title_id, sfo.dir_name);
         struct stat ex_st;
         int exists = (stat(exist_path, &ex_st) == 0) ? 1 : 0;

         logprintf("[GarlicMgr] import_encrypted: title=%s dir=%s save_aid=%llx user_aid=%llx match=%d exists=%d\n",
                sfo.title_id, sfo.dir_name,
                (unsigned long long)sfo.account_id, (unsigned long long)user_aid, match, exists);

         char json[512];
         snprintf(json, sizeof(json),
                  "{\"ok\":true,\"title_id\":\"%s\",\"dir_name\":\"%s\",\"main_title\":\"%s\","
                  "\"save_aid\":\"%016llX\",\"user_aid\":\"%016llX\",\"match\":%s,\"exists\":%s}",
                  sfo.title_id, sfo.dir_name, sfo.main_title,
                  (unsigned long long)sfo.account_id, (unsigned long long)user_aid,
                  match ? "true" : "false", exists ? "true" : "false");
         http_json(sock, json);
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
         chives_geometry_t original;
         int preserve_geometry = chives_zip_geometry(tar_data,received,&original);
         if (received != clen || preserve_geometry < 0 || (preserve_geometry && original.is_ps4)) {
             free(tar_data);
             http_json(sock,"{\"error\":\"Invalid ZIP or incompatible PS5 save metadata\"}"); return;
         }

         if (g_mounted && unmount_save() < 0) {
             free(tar_data);
             http_json(sock,"{\"error\":\"Cannot finalize the previous mount; new image was not created\"}"); return;
         }
         mkdir("/data/save_files", 0777);
         const char *tmp = "/data/save_files/_tmp_enc";
         unlink(tmp);
         kernel_set_ucred_authid(getpid(), 0x4800000000000010ULL);

         /* Size: data + 25% overhead + 4MB, min 32MB, aligned to 32K */
         uint64_t img_size = clen + (clen / 4) + (4 * 1024 * 1024);
         if (img_size < 32 * 1024 * 1024)
             img_size = 32 * 1024 * 1024;
         img_size = ((img_size + 32767) / 32768) * 32768;
         if (preserve_geometry)
             img_size = original.block_count * (uint64_t)original.block_size_bytes;

         int native_allocation = preserve_geometry && chives_zip_physical_sfo(tar_data,received,&original);

         /* Step 1: Create file and allocate space (same as mkpfs) */
         int imgfd = open(tmp, O_CREAT | O_TRUNC | O_RDWR, 0777);
         if (imgfd < 0) {
             free(tar_data);
             http_json(sock, "{\"error\":\"Cannot create temp file\"}"); return;
         }
         int ret = sceFsUfsAllocateSaveData(imgfd, img_size, native_allocation ? 0x80 : 0, NULL);
         if (ret < 0 && native_allocation) {
             int allocation_errno = errno;
             close(imgfd); free(tar_data); unlink(tmp);
             char json[256];
             snprintf(json,sizeof(json),"{\"error\":\"Native PS5 allocation flags=0x80 failed: ret=%d (0x%x) errno=%d; ordinary-file fallback blocked\"}",ret,(unsigned)ret,allocation_errno);
             http_json(sock,json); return;
         }
         if (ret < 0) {
             printf("[GarlicMgr] UfsAllocate failed (0x%x), using ftruncate\n", ret);
             if (ftruncate(imgfd, img_size) < 0) {
                 close(imgfd); free(tar_data); unlink(tmp);
                 http_json(sock, "{\"error\":\"Cannot allocate image\"}"); return;
             }
         }
         close(imgfd);
         printf("[GarlicMgr] Created image file %llu bytes\n", (unsigned long long)img_size);

         /* Step 2: Format PPR and initialize its metadata region. */
         CreateOpt copt;
         memset(&copt, 0, sizeof(copt));
         sceFsInitCreatePfsSaveDataOpt(&copt);
         if (preserve_geometry) chives_apply_opt(&copt,&original);
         copt.flags[1] = native_allocation ? 0 : 0x02;
         if (!g_pprCreate) {
             free(tar_data); unlink(tmp);
             http_json(sock, "{\"error\":\"PprCreate not available\"}"); return;
         }
         ret = chives_ppr_create(&copt, tmp, img_size, preserve_geometry ? &original : NULL, native_allocation);
         printf("[GarlicMgr] PprCreate returned 0x%x\n", ret);
         if (ret < 0) {
             free(tar_data); unlink(tmp);
             char json[128];
             snprintf(json, sizeof(json), "{\"error\":\"Format PFS failed: 0x%x\"}", ret);
             http_json(sock, json); return;
         }
         if (preserve_geometry && chives_verify_created(tmp,&original) < 0) {
             free(tar_data); unlink(tmp);
             http_json(sock,"{\"error\":\"Formatter geometry mismatch\"}"); return;
         }
         printf("[GarlicMgr] Formatted PFS image OK\n");

         /* Step 3: Recover the sealed key generated by the native PPR formatter. */
         snprintf(g_mount_point, sizeof(g_mount_point), "/data/mount_sd");
         mkdir(g_mount_point, 0777);
         MountOpt emopt;
         memset(&emopt, 0, sizeof(emopt));
         sceFsInitMountSaveDataOpt(&emopt);
         emopt.budgetid = "system";
         signal(SIGPIPE, SIG_DFL);
         g_mount_error[0] = 0;
         ret = mount_by_path_at_checked(tmp, "/data/mount_sd", 1, 1);
         signal(SIGPIPE, SIG_IGN);
         if (ret < 0) {
             free(tar_data); unlink(tmp);
             char json[1024];
             if (g_mount_error[0]) {
                 char escaped[768]; chives_escape(g_mount_error,escaped,sizeof(escaped));
                 snprintf(json,sizeof(json),"{\"error\":\"%s\"}",escaped);
             } else snprintf(json, sizeof(json), "{\"error\":\"Mount failed: 0x%x\"}", ret);
             http_json(sock, json); return;
         }
         snprintf(g_mounted_path, sizeof(g_mounted_path), "%s", tmp);
         g_local_copy[0] = 0;
         g_mounted = 1;
         printf("[GarlicMgr] Mounted new PFS (handle=%d)\n", ret);

         /* Step 4: Extract zip into mounted PFS */
         int files = extract_zip(g_mount_point, tar_data, received);
         if (files >= 0 && restore_legacy_sfo_from_zip(tar_data,received,g_mount_point) < 0)
             files = -1;
         free(tar_data);
         if (files < 0) {
             if (unmount_save() >= 0) unlink(tmp);
             http_json(sock,"{\"error\":\"Failed to copy ZIP files into the original image capacity\"}"); return;
         }
         sync();
         printf("[GarlicMgr] Extracted %d files for encrypt\n", files);

         /* A decrypted save downloaded from a PS5 console carries the real
          * param.sfo (recovered from the PS5PARAM blob).  Make sure it lands at
          * the PFS root even if the zip is rooted at <title_id>/<save_name>/. */
         {
             char found_sfo[MAX_PATH_LEN];
             char root_sfo[MAX_PATH_LEN];
             snprintf(root_sfo, sizeof(root_sfo), "%s/sce_sys/param.sfo", g_mount_point);
             if (find_real_sfo(g_mount_point, found_sfo, sizeof(found_sfo), 0) == 0) {
                 if (strcmp(found_sfo, root_sfo) != 0) {
                     int rfd = open(found_sfo, O_RDONLY);
                     if (rfd >= 0) {
                         struct stat rs;
                         if (fstat(rfd, &rs) == 0 && rs.st_size >= 20 && rs.st_size <= 0x8000) {
                             uint8_t *rb = malloc((size_t)rs.st_size);
                             if (rb) {
                                 ssize_t rn = read(rfd, rb, (size_t)rs.st_size);
                                 if (rn == rs.st_size)
                                     install_sfo_file(root_sfo, rb, (uint32_t)rn);
                                 free(rb);
                             }
                         }
                         close(rfd);
                     }
                 }
             } else {
                 logprintf("[GarlicMgr] encrypt_upload: no real param.sfo in upload; leaving PFS copy as-is\n");
             }
         }

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
                 if (sfo_account_from_hex(hs, new_aid) < 0) {
                     http_json(sock, "{\"error\":\"Invalid Account ID\"}"); return;
                 }
                 char sfo_path[MAX_PATH_LEN];
                 snprintf(sfo_path, sizeof(sfo_path), "%s/sce_sys/param.sfo", g_mount_point);
                 if (patch_sfo_account(sfo_path, new_aid, NULL) < 0) {
                     http_json(sock, "{\"error\":\"Failed to write and verify Account ID in param.sfo\"}"); return;
                 }
             }
         }

         /* Capture the final SFO (including any account patch) for the header
          * blob before unmounting clears the mount point. */
         int enc_blob_sfo_fresh = g_image_fresh;
         uint8_t enc_blob_sfo[0x8000];
         uint32_t enc_blob_sfo_len = 0;
         {
             char root_sfo[MAX_PATH_LEN];
             snprintf(root_sfo, sizeof(root_sfo), "%s/sce_sys/param.sfo", g_mount_point);
             int sn = read_sfo_file(root_sfo, enc_blob_sfo, sizeof(enc_blob_sfo) - 20);
             if (sn <= 0) {
                 if (preserve_geometry && original.has_fs_ext && !original.fs_ext) {
                     logprintf("[GarlicMgr] Physical container has no param.sfo; preserving its original layout\n");
                 } else {
                     logprintf("[GarlicMgr] final SFO read failed: path=%s result=%d\n", root_sfo, sn);
                     http_json(sock, "{\"error\":\"Cannot read complete final PS5 param.sfo; output was not published or installed\"}"); return;
                 }
             } else enc_blob_sfo_len = (uint32_t)sn;
         }

         if(unmount_save()<0){
             http_json(sock,"{\"error\":\"Native save finalization failed; encrypted output was not published\"}");return;
         }

         /* Store and verify the real metadata before accepting encrypted output. */
         if (enc_blob_sfo_len) {
             int wr = finalize_ps5_sfo(tmp, enc_blob_sfo, enc_blob_sfo_len, enc_blob_sfo_fresh);
             if (wr < 0) {
                 http_ps5param_failure(sock); return;
             } else
                 logprintf("[GarlicMgr] PS5PARAM: finalized real param.sfo (%u B)\n",
                           enc_blob_sfo_len);
         }

         struct stat est;
         if (stat(tmp, &est) < 0) {
             unlink(tmp);
             http_json(sock, "{\"error\":\"Encrypted image not found\"}"); return;
         }
         char json[1024],warning[768];
         json_escape(ps5param_warning(),warning,sizeof(warning));
         snprintf(json,sizeof(json),"{\"ok\":true,\"size\":%lld,\"warning\":\"%s\"}",
                  (long long)est.st_size,warning);
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
         char *buf = iobuf;
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
             zip_send_files(sock, zfiles, 2, iobuf);
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
             char *buf = iobuf;
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
         if (!chives_path_safe(fname) || chives_is_sidecar(fname)) {
             http_json(sock,"{\"error\":\"chives.json is metadata and cannot be uploaded into PFS\"}"); return;
         }

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

         int fd = open(filepath, O_CREAT | O_WRONLY | O_TRUNC, 0777);
         if (fd < 0) {
             char json[256];
             snprintf(json, sizeof(json), "{\"error\":\"Cannot create %s\"}", fname);
             http_json(sock, json); return;
         }

         if (body_in_buf > clen) body_in_buf = clen;
         pfs_log_snapshot_t log_before = pfs_log_snapshot();
         garlic_upload_t progress = { .expected = clen,
                                      .crc = UINT32_C(0xffffffff) };
         garlic_upload_receive(fd,body_start,body_in_buf,&progress,iobuf,BUF_SIZE,
                               upload_socket_receive,&sock);
         if (garlic_upload_finish(fd,filepath,&progress,iobuf,BUF_SIZE) < 0) {
             pfs_log_snapshot_t log_after = pfs_log_snapshot();
             garlic_pfs_diag_t native_diag;
             memset(&native_diag,0,sizeof(native_diag));
             int has_native_diag = log_after.bytes && garlic_pfs_diag_find(
                 log_before.bytes,log_before.size,log_after.bytes,log_after.size,
                 progress.error,&native_diag);
             int log_error = log_after.error ? log_after.error : log_before.error;
             free(log_before.bytes); free(log_after.bytes);
             char error_text[1024], escaped[2048], json[3584];
             snprintf(error_text,sizeof(error_text),
                 "Upload %s failed: errno=%d (%s); received=%zu/%zu, written=%zu/%zu, file_size=%lld; offset=%zu request=%zu result=%lld",
                 progress.stage,progress.error,strerror(progress.error),progress.received,
                 progress.expected,progress.written,progress.expected,(long long)progress.actual_size,
                 progress.last_write_offset,progress.last_write_request,(long long)progress.last_write_result);
             size_t error_len = strlen(error_text);
             if (has_native_diag) {
                 snprintf(error_text+error_len,sizeof(error_text)-error_len,"; %s kernel: %s",
                          native_diag.fresh ? "new" : "recent (freshness unknown)",native_diag.text);
             } else if (log_error) {
                 snprintf(error_text+error_len,sizeof(error_text)-error_len,
                          "; kernel log unavailable errno=%d",log_error);
             } else {
                 snprintf(error_text+error_len,sizeof(error_text)-error_len,
                          "; no matching new PFS kernel record");
             }
             logprintf("[GarlicMgr] %s: %s\n",fname,error_text);
             chives_escape(error_text,escaped,sizeof(escaped));
             snprintf(json,sizeof(json),"{\"error\":\"%s\",\"stage\":\"%s\",\"errno\":%d,"
                 "\"expected\":%zu,\"received\":%zu,\"written\":%zu,\"file_size\":%lld,"
                 "\"write_offset\":%zu,\"write_request\":%zu,\"write_result\":%lld,"
                 "\"kernel_kind\":%d,\"kernel_line\":%d,\"kernel_log_fresh\":%s,\"kernel_log_error\":%d}",
                 escaped,progress.stage,progress.error,progress.expected,progress.received,progress.written,
                 (long long)progress.actual_size,progress.last_write_offset,
                 progress.last_write_request,(long long)progress.last_write_result,
                 native_diag.kind,native_diag.line,native_diag.fresh ? "true" : "false",log_error);
             unlink(filepath);
             http_json(sock,json); return;
         }
         free(log_before.bytes);
         if (!progress.sync_warning) sync();
         else logprintf("[GarlicMgr] %s: fsync errno=%d; sync + length/CRC readback passed\n",
                        fname,progress.sync_warning);
         logprintf("[GarlicMgr] %s: buffered upload complete, bytes=%zu writes=%zu block=%u\n",
                   fname,progress.written,progress.write_calls,GARLIC_UPLOAD_BLOCK);

         char json[1280], escaped_name[1024];
         chives_escape(fname,escaped_name,sizeof(escaped_name));
         snprintf(json, sizeof(json), "{\"ok\":true,\"name\":\"%s\",\"size\":%zu,\"sync_fallback_errno\":%d}",
                  escaped_name,progress.received,progress.sync_warning);
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
         if (received != clen || files < 0) {
             http_json(sock,"{\"error\":\"ZIP extraction failed; check ZIP layout and image capacity\"}"); return;
         }
         sync();

         char json[128];
         snprintf(json, sizeof(json), "{\"files\":%d}", files);
         http_json(sock, json);
         return;
     }

     /* GET creates an estimated image. POST carries the original chives.json. */
     if ((strcmp(method, "GET") == 0 || strcmp(method, "POST") == 0) &&
         strncmp(url, "/api/create_pfs", 15) == 0) {
         chives_geometry_t original;
         int preserve_geometry = strcmp(method,"POST") == 0;
         if (preserve_geometry) {
             size_t clen=0;
             char *cl=strcasestr(req,"Content-Length:");
             if (cl) clen=strtoul(cl+15,NULL,10);
             char *body=strstr(req,"\r\n\r\n");
             if (!body || !clen || clen > CHIVES_MAX_JSON) {
                 http_json(sock,"{\"error\":\"Invalid chives.json size\"}"); return;
             }
             body+=4;
             char json[CHIVES_MAX_JSON+1];
             size_t got=n-(size_t)(body-req);
             if (got > clen) got=clen;
             memcpy(json,body,got);
             while (got < clen) {
                 ssize_t r=recv_all(sock,json+got,clen-got);
                 if (r <= 0) break;
                 got+=(size_t)r;
             }
             if (got != clen || chives_parse(json,clen,&original) < 0 ||
                 original.is_ps4 != (strstr(url,"ps4=1") != NULL)) {
                 http_json(sock,"{\"error\":\"Invalid or incompatible chives.json geometry\"}"); return;
             }
         }
         if (g_mounted && unmount_save() < 0) {
             http_json(sock,"{\"error\":\"Cannot finalize the previous mount; new image was not created\"}"); return;
         }
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
         if (preserve_geometry) {
             img_size = original.block_count * (uint64_t)original.block_size_bytes;
             logprintf("[GarlicMgr] Restoring PFS: blocks=%llu blockSize=%u logical=%llu physical_original=%llu\n",
                 (unsigned long long)original.block_count,original.block_size_bytes,
                 (unsigned long long)img_size,(unsigned long long)original.original_image_size_bytes);
         } else {
             logprintf("[GarlicMgr] No chives.json: using estimated image size; SFO blocks do not describe PFS geometry\n");
         }
         if (img_size > CHIVES_MAX_IMAGE) {
             http_json(sock,"{\"error\":\"Requested image exceeds supported size\"}"); return;
         }

         int native_allocation = !is_ps4 && preserve_geometry && original.block_size_bytes == 65536;

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
         int ret = sceFsUfsAllocateSaveData(imgfd, img_size, native_allocation ? 0x80 : 0, NULL);
         if (ret < 0 && native_allocation) {
             int allocation_errno = errno;
             close(imgfd); unlink(tmp);
             char json[256];
             snprintf(json,sizeof(json),"{\"error\":\"Native PS5 allocation flags=0x80 failed: ret=%d (0x%x) errno=%d; ordinary-file fallback blocked\"}",ret,(unsigned)ret,allocation_errno);
             http_json(sock,json); return;
         }
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
         if (preserve_geometry) chives_apply_opt(&copt,&original);

         if (is_ps4) {
             /* PS4: use non-Ppr create with decrypted key */
             ret = sceFsCreatePfsSaveDataImage(&copt, tmp, 0, img_size, ckey);
         } else {
             /* PS5: native PPR creation generates its own sealed key. */
             copt.flags[1] = native_allocation ? 0 : 0x02;
            if (!g_pprCreate) {
                 unlink(tmp);
                 http_json(sock, "{\"error\":\"PprCreate not available\"}"); return;
             }
             ret = chives_ppr_create(&copt, tmp, img_size, preserve_geometry ? &original : NULL, native_allocation);
         }
         if (ret < 0) {
             unlink(tmp);
             char json[128];
             snprintf(json, sizeof(json), "{\"error\":\"Format PFS failed: 0x%x\"}", ret);
             http_json(sock, json); return;
         }
         if (preserve_geometry && chives_verify_created(tmp,&original) < 0) {
             unlink(tmp);
             http_json(sock,"{\"error\":\"Formatter geometry mismatch\"}"); return;
         }
         printf("[GarlicMgr] create_pfs: formatted OK (%s)\n", is_ps4 ? "PS4" : "PS5");

         snprintf(g_mount_point, sizeof(g_mount_point), "/data/mount_sd");
         mkdir(g_mount_point, 0777);
         MountOpt emopt;
         memset(&emopt, 0, sizeof(emopt));
         sceFsInitMountSaveDataOpt(&emopt);
         emopt.budgetid = "system";
         signal(SIGPIPE, SIG_DFL);
         g_mount_error[0] = 0;
         ret = is_ps4 ? sceFsMountSaveData(&emopt, tmp, g_mount_point, ckey) :
               mount_by_path_at_checked(tmp, "/data/mount_sd", 1, 1);
         signal(SIGPIPE, SIG_IGN);
         if (ret < 0) {
             unlink(tmp);
             char json[1024];
             if (g_mount_error[0]) {
                 char escaped[768]; chives_escape(g_mount_error,escaped,sizeof(escaped));
                 snprintf(json,sizeof(json),"{\"error\":\"%s\"}",escaped);
             } else snprintf(json, sizeof(json), "{\"error\":\"Mount failed: 0x%x\"}", ret);
             http_json(sock, json); return;
         }
         snprintf(g_mounted_path, sizeof(g_mounted_path), "%s", tmp);
         g_local_copy[0] = 0;
         g_mounted = 1;
         printf("[GarlicMgr] create_pfs: mounted at %s\n", g_mount_point);

         http_json(sock, is_ps4 ? "{\"ok\":true}" : (native_allocation ? "{\"ok\":true,\"key_recovered\":true,\"native_allocation\":true}" : "{\"ok\":true,\"key_recovered\":true}"));
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

         uint8_t new_aid[8];
         int resign_account = encrypt_account_from_url(url,new_aid);
         if (resign_account < 0) {
             http_json(sock,"{\"error\":\"Account ID must contain exactly 16 hexadecimal digits\"}"); return;
         }

         /* Re-detect PS4 vs PS5 from SFO FORMAT field */
         {
             char sfo_chk[MAX_PATH_LEN];
             snprintf(sfo_chk, sizeof(sfo_chk), "%s/sce_sys/param.sfo", g_mount_point);
             sfo_info_t sfo_tmp;
             if (parse_sfo(sfo_chk, &sfo_tmp) == 0)
                g_enc_ps4 = sfo_is_ps4(&sfo_tmp, g_enc_ps4);
         }

         /* Apply the reviewed target only when ownership needs a change. */
         if (resign_account) {
             char sfo_path[MAX_PATH_LEN];
             snprintf(sfo_path,sizeof(sfo_path),"%s/sce_sys/param.sfo",g_mount_point);
             int local_uid = 0;
             int have_local_uid = sceUserServiceGetForegroundUser(&local_uid) == 0 && local_uid > 0;
             uint32_t uid = (uint32_t)local_uid;
             const uint32_t *uid_ptr = !g_enc_ps4 && have_local_uid ? &uid : NULL;
             int changes = g_enc_ps4 ? 1 : encrypt_sfo_owner_state(sfo_path,new_aid,uid_ptr);
             if (changes < 0) {
                 http_json(sock,"{\"error\":\"Cannot read Account ID or local user ownership from param.sfo\"}"); return;
             }
             if (!changes) {
                 logprintf(uid_ptr
                     ? "[GarlicMgr] Encrypt: Account ID and local user ownership already match; no ownership changes needed\n"
                     : "[GarlicMgr] Encrypt: Account ID already matches; active local user unavailable, local ownership left unchanged\n");
             } else {
                 int owner_ret = g_enc_ps4 ? (have_local_uid ? patch_local_sfo_owner(sfo_path,new_aid,
                     (uint32_t)local_uid,1) : -1) : patch_sfo_account(sfo_path,new_aid,uid_ptr);
                 if (owner_ret < 0) {
                     http_json(sock,"{\"error\":\"Cannot restore ownership. PS4 requires a fresh local save for the same game and slot under the target user.\"}"); return;
                 }
                 logprintf(changes == 2
                     ? "[GarlicMgr] Encrypt: Account ID already matches; local user ownership updated and verified\n"
                     : "[GarlicMgr] Encrypt: target Account ID applied and verified\n");
             }
         }

         int final_sfo_fresh = g_image_fresh;
         uint8_t final_sfo[0x8000];
         int final_sfo_len = 0;
         if (!g_enc_ps4) {
             char sfo_path[MAX_PATH_LEN];
             snprintf(sfo_path, sizeof(sfo_path), "%s/sce_sys/param.sfo", g_mount_point);
             final_sfo_len = read_sfo_file(sfo_path, final_sfo, sizeof(final_sfo) - 20);
             if (final_sfo_len <= 0) {
                 http_json(sock, "{\"error\":\"Cannot read complete final PS5 param.sfo; output was not published\"}"); return;
             }
         }

         /* Save path before unmount clears it */
         char tmp_path[MAX_PATH_LEN];
         snprintf(tmp_path, sizeof(tmp_path), "%s", g_mounted_path);
         if (unmount_save() < 0) {
             http_json(sock,"{\"error\":\"Native save finalization failed; encrypted output was not published\"}"); return;
         }

         if (!g_enc_ps4 && finalize_ps5_sfo(tmp_path, final_sfo, (uint32_t)final_sfo_len, final_sfo_fresh) < 0) {
             http_ps5param_failure(sock); return;
         }

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
             zip_send_files(sock, zfiles, 2, iobuf);
             unlink(tmp_path);
             unlink(bin_tmp);
         } else {
             /* PS5: stream raw image */
             int fd = open(tmp_path, O_RDONLY);
             if (fd < 0) {
                 unlink(tmp_path);
                 http_json(sock, "{\"error\":\"Cannot read file\"}"); return;
             }
             char hdr[2048];
             int hlen = snprintf(hdr, sizeof(hdr),
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Type: application/octet-stream\r\n"
                 "Content-Disposition: attachment; filename=\"%s\"\r\n"
                 "Content-Length: %lld\r\n"
                 "Access-Control-Allow-Origin: *\r\n"
                 "Access-Control-Expose-Headers: X-Garlic-Warning\r\n"
                 "%s%s%s"
                 "Connection: close\r\n\r\n", dlname, (long long)st.st_size,
                 ps5param_warning()[0] ? "X-Garlic-Warning: " : "",
                 ps5param_warning(), ps5param_warning()[0] ? "\r\n" : "");
             send(sock, hdr, hlen, 0);
             char *buf = iobuf;
             ssize_t nr;
             while ((nr = read(fd, buf, BUF_SIZE)) > 0)
                 if(save_socket_send(sock,buf,(size_t)nr)<0)break;
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
         if (sfo_account_from_hex(hex_str, new_aid) < 0) {
             http_json(sock, "{\"error\":\"Invalid Account ID\"}"); return;
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
             char *buf = iobuf;
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
         /* PS5: bring the real metadata in from the header blob first; the
          * in-PFS copy is a zero placeholder and would be "patched" blindly. */
         if (!is_ps4 && ps5param_cached_for_mount(g_mount_point)) {
             if (install_sfo_file(sfo_path, ps5param_cache_data(), ps5param_cache_size()) < 0) {
                 http_json(sock, "{\"error\":\"Cannot restore real PS5 metadata\"}"); return;
             }
             cache_params_hmac_mem(ps5param_cache_data(), ps5param_cache_size());
         }
         uint32_t resign_uid = 0;
         const uint32_t *resign_uid_ptr = NULL;
         {
             /* Resolve the target user for both PS4 and PS5 ownership. */
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
                 resign_uid = uid;
                 resign_uid_ptr = &resign_uid;
                 printf("[GarlicMgr] resign: patched user_id to 0x%x\n", uid);
             }
         }
         int owner_ret = is_ps4 ? (resign_uid_ptr ?
             patch_local_sfo_owner(sfo_path, new_aid, resign_uid, 1) : -1) :
             patch_sfo_account(sfo_path, new_aid, resign_uid_ptr);
         if (owner_ret < 0) {
             unmount_save(); unlink(tmp);
             if (is_ps4) unlink("/data/save_files/_tmp_resign.bin");
             http_json(sock, "{\"error\":\"Cannot restore ownership. PS4 requires a fresh local save for the same game and slot under the target user.\"}"); return;
         }
         printf("[GarlicMgr] resign: patched account ID to %s (%s)\n", aid_hex, is_ps4 ? "PS4" : "PS5");

         /* PS5: capture the patched SFO for the header blob before unmount. */
         uint8_t resign_sfo[0x8000];
         uint32_t resign_sfo_len = 0;
         if (!is_ps4) {
             int sn = read_sfo_file(sfo_path, resign_sfo, sizeof(resign_sfo) - 20);
             if (sn <= 0) {
                 http_json(sock, "{\"error\":\"Cannot read complete final PS5 param.sfo; output was not published or installed\"}"); return;
             }
             resign_sfo_len = (uint32_t)sn;
         }

         /* Unmount (re-encrypts) */
         if (unmount_save() < 0) {
             http_json(sock, "{\"error\":\"Native save finalization failed; output was not published or installed\"}"); return;
         }

         if (!is_ps4 && resign_sfo_len) {
             int wr = finalize_ps5_sfo(tmp, resign_sfo, resign_sfo_len, 0);
             if (wr < 0) {
                 http_ps5param_failure(sock); return;
             } else
                 logprintf("[GarlicMgr] PS5PARAM: finalized resigned param.sfo (%u B)\n",
                           resign_sfo_len);
         }

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

     /* GET /api/import_check?uid=<hex> -> check if mounted save already exists on system */
     if (strcmp(method, "GET") == 0 && strncmp(url, "/api/import_check", 17) == 0) {
         if (!g_mounted) { http_json(sock, "{\"error\":\"No save mounted\"}"); return; }
         char sfo_path[MAX_PATH_LEN];
         snprintf(sfo_path, sizeof(sfo_path), "%s/sce_sys/param.sfo", g_mount_point);
         sfo_info_t sfo;
         if (parse_sfo(sfo_path, &sfo) < 0 || !sfo.title_id[0] || !sfo.dir_name[0]) {
             http_json(sock, "{\"exists\":false}"); return;
         }
         char uid_hex[16] = {0};
         char *uidp = strstr(url, "uid=");
         if (uidp) {
             strncpy(uid_hex, uidp + 4, sizeof(uid_hex) - 1);
             char *amp = strchr(uid_hex, '&'); if (amp) *amp = 0;
         }
         if (!uid_hex[0]) {
             int local_uid = 0; sceUserServiceGetForegroundUser(&local_uid);
             snprintf(uid_hex, sizeof(uid_hex), "%x", (uint32_t)local_uid);
         }
         char dst[MAX_PATH_LEN];
         snprintf(dst, sizeof(dst), "/user/home/%s/%s/%s/sdimg_%s",
                  uid_hex, g_enc_ps4 ? "savedata" : "savedata_prospero",
                  sfo.title_id, sfo.dir_name);
         struct stat dst_st;
         int exists = (stat(dst, &dst_st) == 0) ? 1 : 0;
         char json[256];
         snprintf(json, sizeof(json),
                  "{\"exists\":%s,\"title_id\":\"%s\",\"dir_name\":\"%s\",\"main_title\":\"%s\"}",
                  exists ? "true" : "false", sfo.title_id, sfo.dir_name, sfo.main_title);
         http_json(sock, json);
         return;
     }

     /* GET /api/import_usb_save?idx=N&uid=<hex> -> import decrypted USB save to system */
     if (strcmp(method, "GET") == 0 && strncmp(url, "/api/import_usb_save", 20) == 0) {
         scan_saves();
         int idx = -1;
         char *p = strstr(url, "idx=");
         if (p) idx = atoi(p + 4);
         if (idx < 0 || idx >= g_save_count) {
             http_json(sock, "{\"error\":\"Invalid index\"}"); return;
         }
         save_entry_t *s = &g_saves[idx];

         /* Check if encrypted file or decrypted folder */
         struct stat path_st;
         if (stat(s->path, &path_st) < 0) {
             http_json(sock, "{\"error\":\"Save not found\"}"); return;
         }
         int is_encrypted = S_ISREG(path_st.st_mode);

         if (is_encrypted) {
             /* Encrypted USB save: mount, then use import_finish logic */
             if (g_mounted) unmount_save();
             int ret = mount_save(idx);
             if (ret < 0) {
                 char json[128];
                 snprintf(json, sizeof(json), "{\"error\":\"Mount failed: %d\"}", ret);
                 http_json(sock, json); return;
             }

             /* Parse param.sfo from mounted save */
             char sfo_path[MAX_PATH_LEN];
             snprintf(sfo_path, sizeof(sfo_path), "%s/sce_sys/param.sfo", g_mount_point);
             /* PS5: restore real metadata from the header blob (in-PFS is zero) */
             if (ps5param_cached_for_mount(g_mount_point)) {
                 if (install_sfo_file(sfo_path, ps5param_cache_data(), ps5param_cache_size()) < 0) {
                 http_json(sock, "{\"error\":\"Cannot restore real PS5 metadata\"}"); return;
             }
             cache_params_hmac_mem(ps5param_cache_data(), ps5param_cache_size());
             }
             sfo_info_t sfo;
             int sfo_ret2 = parse_sfo(sfo_path, &sfo);
             if (sfo_ret2 == -2) {
                 /* Zeroed SFO — regenerate from DB */
                 printf("[GarlicMgr] import_usb: zeroed param.sfo (encrypted), regenerating\n");
                 char uid_hex_tmp[16] = {0};
                 char *uidp_tmp = strstr(url, "uid=");
                 if (uidp_tmp) { strncpy(uid_hex_tmp, uidp_tmp + 4, sizeof(uid_hex_tmp) - 1);
                     char *amp = strchr(uid_hex_tmp, '&'); if (amp) *amp = 0; }
                 if (!uid_hex_tmp[0]) {
                     int lu = 0; sceUserServiceGetForegroundUser(&lu);
                     snprintf(uid_hex_tmp, sizeof(uid_hex_tmp), "%x", (uint32_t)lu);
                 }
                 /* Derive dir_name for DB: strip sdimg_ prefix from save_name */
                 const char *lookup_dir2 = s->save_name;
                 if (strncmp(lookup_dir2, "sdimg_", 6) == 0) lookup_dir2 += 6;

                 char db_main_title[128] = {0}, db_sub_title[128] = {0}, db_gtid[32] = {0};
                 uint64_t db_aid = 0, db_blocks = 96, db_sysblocks = 0;
                 uint32_t db_uid = (uint32_t)strtoul(uid_hex_tmp, NULL, 16);
                 int db_found = 0, db_is_ps4 = 0;
                 const char *db_types[] = {"savedata_prospero", "savedata"};
                 for (int dt = 0; dt < 2 && !db_found; dt++) {
                     char db_path[MAX_PATH_LEN];
                     snprintf(db_path, sizeof(db_path), "/system_data/%s/%s/db/user/savedata.db",
                              db_types[dt], uid_hex_tmp);
                     sqlite3 *db = NULL;
                     if (sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
                         char sql[512];
                         snprintf(sql, sizeof(sql),
                             "SELECT main_title, sub_title, blocks, account_id, system_blocks, user_id, game_title_id "
                             "FROM savedata WHERE title_id='%s' AND dir_name='%s' LIMIT 1",
                             s->title_id, lookup_dir2);
                         sqlite3_stmt *stmt = NULL;
                         if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK &&
                             sqlite3_step(stmt) == SQLITE_ROW) {
                             const char *mt = (const char *)sqlite3_column_text(stmt, 0);
                             const char *st2 = (const char *)sqlite3_column_text(stmt, 1);
                             const char *gt = (const char *)sqlite3_column_text(stmt, 6);
                             if (mt) strncpy(db_main_title, mt, sizeof(db_main_title) - 1);
                             if (st2) strncpy(db_sub_title, st2, sizeof(db_sub_title) - 1);
                             db_blocks = sqlite3_column_int64(stmt, 2);
                             db_aid = (uint64_t)sqlite3_column_int64(stmt, 3);
                             db_sysblocks = sqlite3_column_int64(stmt, 4);
                             db_uid = (uint32_t)sqlite3_column_int(stmt, 5);
                             if (gt) strncpy(db_gtid, gt, sizeof(db_gtid) - 1);
                             db_found = 1;
                             db_is_ps4 = (dt == 1);
                         }
                         if (stmt) sqlite3_finalize(stmt);
                         sqlite3_close(db);
                     }
                 }
                 if (!db_found) strncpy(db_main_title, s->title_id, sizeof(db_main_title) - 1);
                 generate_sfo(sfo_path, s->title_id, lookup_dir2,
                              db_main_title, db_sub_title, db_aid, db_blocks, db_sysblocks,
                              db_uid, db_gtid[0] ? db_gtid : NULL,
                              db_is_ps4 || s->is_ps4,
                              g_params_hmac_valid ? g_params_hmac : NULL);
                 sync();
                 sfo_ret2 = parse_sfo(sfo_path, &sfo);
             }
             if (sfo_ret2 < 0 || !sfo.title_id[0] || !sfo.dir_name[0]) {
                 unmount_save();
                 http_json(sock, "{\"error\":\"Cannot parse param.sfo\"}"); return;
             }

             /* Detect PS4/PS5 from FORMAT */
             g_enc_ps4 = sfo_is_ps4(&sfo, g_enc_ps4);
             printf("[GarlicMgr] import_usb: encrypted %s/%s FORMAT=%s %s\n",
                    sfo.title_id, sfo.dir_name, sfo.format, g_enc_ps4 ? "PS4" : "PS5");

             /* Get user info */
             char uid_hex[16] = {0};
             char *uidp = strstr(url, "uid=");
             if (uidp) {
                 strncpy(uid_hex, uidp + 4, sizeof(uid_hex) - 1);
                 char *amp = strchr(uid_hex, '&'); if (amp) *amp = 0;
             }
             uint32_t uid;
             if (uid_hex[0]) {
                 uid = (uint32_t)strtoul(uid_hex, NULL, 16);
             } else {
                 int local_uid = 0;
                 sceUserServiceGetForegroundUser(&local_uid);
                 uid = (uint32_t)local_uid;
                 snprintf(uid_hex, sizeof(uid_hex), "%x", uid);
             }

             /* Resign */
             uint64_t local_aid = 0;
             int owner_result = patch_import_sfo_owner(sfo_path, sfo.account_id, uid_hex, uid, g_enc_ps4, &local_aid);
             const char *owner_warning = import_owner_warning(owner_result);
             if (owner_warning[0]) logprintf("[GarlicMgr] WARNING: %s\n", owner_warning);
             printf("[GarlicMgr] import: resigned aid=%016llX uid=0x%x\n",
                    (unsigned long long)local_aid, uid);

             /* Copy icon before unmount */
             char icon_tmp[MAX_PATH_LEN] = {0};
             {
                 char icon_src[MAX_PATH_LEN];
                 snprintf(icon_src, sizeof(icon_src), "%s/sce_sys/icon0.png", g_mount_point);
                 struct stat ist;
                 if (stat(icon_src, &ist) == 0) {
                     snprintf(icon_tmp, sizeof(icon_tmp), "/data/save_files/_tmp_icon.png");
                     copy_file(icon_src, icon_tmp);
                 }
             }

             garlic_save_usage_t import_usage;
             if (capture_save_usage(&sfo,&import_usage) < 0) {
                 http_json(sock,"{\"error\":\"Cannot measure save allocation; existing database usage was not changed\"}"); return;
             }

             /* Save path before unmount */
             char tmp_path[MAX_PATH_LEN];
             snprintf(tmp_path, sizeof(tmp_path), "%s", g_mounted_path);
             /* PS5: capture the resigned SFO for the image's header blob */
             uint8_t usb_sfo[0x8000];
             uint32_t usb_sfo_len = 0;
             if (!g_enc_ps4) {
                 int sn = read_sfo_file(sfo_path, usb_sfo, sizeof(usb_sfo) - 20);
                 if (sn <= 0) {
                     http_json(sock, "{\"error\":\"Cannot read complete final PS5 param.sfo; output was not published or installed\"}"); return;
                 }
                 usb_sfo_len = (uint32_t)sn;
             }
             if (unmount_save() < 0) {
                 http_json(sock, "{\"error\":\"Native save finalization failed; save was not installed\"}"); return;
             }
             if (usb_sfo_len) {
                 int wr = finalize_ps5_sfo(tmp_path, usb_sfo, usb_sfo_len, 0);
                 if (wr < 0) {
                     http_ps5param_failure(sock); return;
                 } else
                     logprintf("[GarlicMgr] PS5PARAM: finalized imported param.sfo (%u B)\n",
                               usb_sfo_len);
             }

             /* Copy to system */
             char sd_dir[MAX_PATH_LEN], sd_dst[MAX_PATH_LEN];
             snprintf(sd_dir, sizeof(sd_dir), "/user/home/%s/%s/%s", uid_hex,
                      g_enc_ps4 ? "savedata" : "savedata_prospero", sfo.title_id);
             snprintf(sd_dst, sizeof(sd_dst), "%s/sdimg_%s", sd_dir, sfo.dir_name);
             recursive_mkdir(sd_dir);

             int from_usb = (strncmp(tmp_path, "/mnt/usb", 8) == 0);
             if (copy_file(tmp_path, sd_dst) < 0) {
                 if (!from_usb) unlink(tmp_path);
                 if (icon_tmp[0]) unlink(icon_tmp);
                 http_json(sock, "{\"error\":\"Failed to copy save\"}"); return;
             }
             if (!from_usb) unlink(tmp_path);
             chmod(sd_dst, 0644);

             /* PS4: copy .bin key */
             if (g_enc_ps4 && strncmp(s->save_name, "sdimg_", 6) == 0) {
                 const char *savename = s->save_name + 6;
                 char src_dir[MAX_PATH_LEN];
                 strncpy(src_dir, s->path, sizeof(src_dir) - 1);
                 src_dir[sizeof(src_dir) - 1] = 0;
                 char *sl = strrchr(src_dir, '/');
                 if (sl) *(sl + 1) = 0;
                 char bin_src[MAX_PATH_LEN], bin_dst[MAX_PATH_LEN];
                 snprintf(bin_src, sizeof(bin_src), "%s%s.bin", src_dir, savename);
                 snprintf(bin_dst, sizeof(bin_dst), "%s/%s.bin", sd_dir, sfo.dir_name);
                 struct stat bst;
                 if (stat(bin_src, &bst) == 0) copy_file(bin_src, bin_dst);
             }

             /* Copy icon */
             if (icon_tmp[0]) {
                 char icon_dir[MAX_PATH_LEN], icon_dst[MAX_PATH_LEN];
                 snprintf(icon_dir, sizeof(icon_dir),
                          "/user/home/%s/savedata_prospero_meta/user/%s", uid_hex, sfo.title_id);
                 snprintf(icon_dst, sizeof(icon_dst), "%s/%s_icon0.png", icon_dir, sfo.dir_name);
                 recursive_mkdir(icon_dir);
                 copy_file(icon_tmp, icon_dst);
                 unlink(icon_tmp);
             }

             /* Update DB */
             char db_path[MAX_PATH_LEN];
             snprintf(db_path, sizeof(db_path), "/system_data/%s/%s/db/user/savedata.db",
                      g_enc_ps4 ? "savedata" : "savedata_prospero", uid_hex);
             { char db_dir[MAX_PATH_LEN];
               snprintf(db_dir, sizeof(db_dir), "/system_data/%s/%s/db/user",
                        g_enc_ps4 ? "savedata" : "savedata_prospero", uid_hex);
               recursive_mkdir(db_dir); }
             sqlite3 *db = NULL;
             if (sqlite3_open(db_path, &db) == SQLITE_OK) {
                 char *err_msg = NULL;
                 sqlite3_exec(db,
                     "CREATE TABLE IF NOT EXISTS savedata ("
                     "id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,"
                     "title_id NOT NULL, dir_name NOT NULL, main_title NOT NULL,"
                     "sub_title, detail, tmp_dir_name, is_broken, user_param,"
                     "blocks, free_blocks, size_kib, mtime NOT NULL,"
                     "fake_broken, account_id, user_id, faked_owner,"
                     "cloud_icon_url, cloud_revision, game_title_id NOT NULL, system_blocks)",
                     NULL, 0, &err_msg);
                 if (err_msg) { sqlite3_free(err_msg); err_msg = NULL; }

                 char esc_title[256] = {0};
                 { char *src2 = sfo.main_title, *dst2 = esc_title;
                   while (*src2 && dst2 < esc_title + sizeof(esc_title) - 2) {
                       if (*src2 == '\'') *dst2++ = '\'';
                       *dst2++ = *src2++;
                   }
                   *dst2 = 0; }

                 char mtime[64];
                 { time_t now = time(NULL); struct tm *tm = gmtime(&now);
                   strftime(mtime, sizeof(mtime), "%Y-%m-%dT%H:%M:%S.00Z", tm); }

                 uint64_t aid_val = local_aid;

                 char check_sql[512];
                 snprintf(check_sql, sizeof(check_sql),
                          "SELECT COUNT(*) FROM savedata WHERE title_id='%s' AND dir_name='%s'",
                          sfo.title_id, sfo.dir_name);
                 sqlite3_stmt *stmt = NULL;
                 int db_exists = 0;
                 if (sqlite3_prepare_v2(db, check_sql, -1, &stmt, NULL) == SQLITE_OK) {
                     if (sqlite3_step(stmt) == SQLITE_ROW) db_exists = sqlite3_column_int(stmt, 0);
                     sqlite3_finalize(stmt);
                 }

                 char sql[2048];
                 if (db_exists) {
                     snprintf(sql, sizeof(sql),
                         "UPDATE savedata SET main_title='%s', mtime='%s', account_id=%lld, user_id=%u, is_broken=0, "
                         "blocks=%llu, free_blocks=%llu, size_kib=%llu, system_blocks=%llu "
                         "WHERE title_id='%s' AND dir_name='%s'",
                         esc_title, mtime, (long long)(int64_t)aid_val, uid,
                         (unsigned long long)import_usage.blocks,(unsigned long long)import_usage.free_blocks,
                         (unsigned long long)import_usage.size_kib,(unsigned long long)import_usage.system_blocks,
                         sfo.title_id, sfo.dir_name);
                 } else {
                     snprintf(sql, sizeof(sql),
                         "INSERT INTO savedata (title_id, dir_name, main_title, sub_title, detail,"
                         "is_broken, user_param, blocks, free_blocks, size_kib, mtime,"
                         "fake_broken, account_id, user_id, faked_owner, cloud_revision,"
                         "game_title_id, system_blocks) VALUES ("
                         "'%s','%s','%s','','',0,%u,%llu,%llu,%llu,'%s',0,%lld,%u,0,0,'%s',%llu)",
                         sfo.title_id, sfo.dir_name, esc_title,
                         sfo.list_param, (unsigned long long)import_usage.blocks,(unsigned long long)import_usage.free_blocks,
                         (unsigned long long)import_usage.size_kib,mtime,
                         (long long)(int64_t)aid_val, uid, sfo.title_id,(unsigned long long)import_usage.system_blocks);
                 }
                 ret = sqlite3_exec(db, sql, NULL, 0, &err_msg);
                 if (ret != SQLITE_OK) { printf("[GarlicMgr] import_usb: DB error: %s\n", err_msg); sqlite3_free(err_msg); }
                 else printf("[GarlicMgr] import_usb: DB %s OK\n", db_exists ? "updated" : "inserted");
                 sqlite3_close(db);
             }

             char json[1024];
             snprintf(json, sizeof(json),
                      "{\"ok\":true,\"title_id\":\"%s\",\"dir_name\":\"%s\",\"main_title\":\"%s\",\"warning\":\"%s\"}",
                      sfo.title_id, sfo.dir_name, sfo.main_title, owner_warning);
             http_json(sock, json);
             return;
         }

         /* Decrypted folder: parse param.sfo directly */
         char sfo_path[MAX_PATH_LEN];
         snprintf(sfo_path, sizeof(sfo_path), "%s/sce_sys/param.sfo", s->path);
         sfo_info_t sfo;
         int sfo_ret = parse_sfo(sfo_path, &sfo);
         if (sfo_ret == -2) {
             /* Zeroed param.sfo — regenerate from DB + save entry */
             printf("[GarlicMgr] import_usb: zeroed param.sfo, regenerating from DB\n");

             /* Get uid for DB lookup */
             char uid_hex_tmp[16] = {0};
             char *uidp_tmp = strstr(url, "uid=");
             if (uidp_tmp) { strncpy(uid_hex_tmp, uidp_tmp + 4, sizeof(uid_hex_tmp) - 1);
                 char *amp = strchr(uid_hex_tmp, '&'); if (amp) *amp = 0; }
             if (!uid_hex_tmp[0]) {
                 int lu = 0; sceUserServiceGetForegroundUser(&lu);
                 snprintf(uid_hex_tmp, sizeof(uid_hex_tmp), "%x", (uint32_t)lu);
             }

             /* Derive dir_name for DB lookup: save_name is the folder name for decrypted saves */
             const char *lookup_dir = s->save_name;

             /* Try both PS5 and PS4 DBs */
             char db_main_title[128] = {0}, db_sub_title[128] = {0}, db_gtid[32] = {0};
             uint64_t db_aid = 0, db_blocks = 96, db_sysblocks = 0;
             uint32_t db_uid = (uint32_t)strtoul(uid_hex_tmp, NULL, 16);
             int db_found = 0, db_is_ps4 = 0;
             const char *db_types[] = {"savedata_prospero", "savedata"};
             for (int dt = 0; dt < 2 && !db_found; dt++) {
                 char db_path[MAX_PATH_LEN];
                 snprintf(db_path, sizeof(db_path), "/system_data/%s/%s/db/user/savedata.db",
                          db_types[dt], uid_hex_tmp);
                 sqlite3 *db = NULL;
                 if (sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
                     char sql[512];
                     snprintf(sql, sizeof(sql),
                         "SELECT main_title, sub_title, blocks, account_id, system_blocks, user_id, game_title_id "
                         "FROM savedata WHERE title_id='%s' AND dir_name='%s' LIMIT 1",
                         s->title_id, lookup_dir);
                     sqlite3_stmt *stmt = NULL;
                     if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK &&
                         sqlite3_step(stmt) == SQLITE_ROW) {
                         const char *mt = (const char *)sqlite3_column_text(stmt, 0);
                         const char *st2 = (const char *)sqlite3_column_text(stmt, 1);
                         const char *gt = (const char *)sqlite3_column_text(stmt, 6);
                         if (mt) strncpy(db_main_title, mt, sizeof(db_main_title) - 1);
                         if (st2) strncpy(db_sub_title, st2, sizeof(db_sub_title) - 1);
                         db_blocks = sqlite3_column_int64(stmt, 2);
                         db_aid = (uint64_t)sqlite3_column_int64(stmt, 3);
                         db_sysblocks = sqlite3_column_int64(stmt, 4);
                         db_uid = (uint32_t)sqlite3_column_int(stmt, 5);
                         if (gt) strncpy(db_gtid, gt, sizeof(db_gtid) - 1);
                         db_found = 1;
                         db_is_ps4 = (dt == 1);
                     }
                     if (stmt) sqlite3_finalize(stmt);
                     sqlite3_close(db);
                 }
             }

             if (!db_found) {
                 /* No DB entry — use save entry fields with defaults */
                 strncpy(db_main_title, s->title_id, sizeof(db_main_title) - 1);
             }

             generate_sfo(sfo_path, s->title_id, lookup_dir,
                          db_main_title, db_sub_title,
                          db_aid, db_blocks, db_sysblocks,
                          db_uid, db_gtid[0] ? db_gtid : NULL,
                          db_is_ps4 || s->is_ps4,
                          g_params_hmac_valid ? g_params_hmac : NULL);
             printf("[GarlicMgr] import_usb: regenerated param.sfo for %s/%s\n",
                    s->title_id, lookup_dir);

             /* Re-parse the generated SFO */
             sfo_ret = parse_sfo(sfo_path, &sfo);
         }
         if (sfo_ret < 0 || !sfo.title_id[0] || !sfo.dir_name[0]) {
             http_json(sock, "{\"error\":\"Cannot parse param.sfo\"}"); return;
         }

         /* Detect PS4/PS5 from FORMAT */
         int is_ps4 = sfo_is_ps4(&sfo, 0);
         g_enc_ps4 = is_ps4;
         printf("[GarlicMgr] import_usb: %s/%s FORMAT=%s %s\n",
                sfo.title_id, sfo.dir_name, sfo.format, is_ps4 ? "PS4" : "PS5");

         /* Get user info */
         char uid_hex[16] = {0};
         char *uidp = strstr(url, "uid=");
         if (uidp) {
             strncpy(uid_hex, uidp + 4, sizeof(uid_hex) - 1);
             char *amp = strchr(uid_hex, '&'); if (amp) *amp = 0;
         }
         uint32_t uid;
         if (uid_hex[0]) {
             uid = (uint32_t)strtoul(uid_hex, NULL, 16);
         } else {
             int local_uid = 0;
             sceUserServiceGetForegroundUser(&local_uid);
             uid = (uint32_t)local_uid;
             snprintf(uid_hex, sizeof(uid_hex), "%x", uid);
         }

         pid_t rpid = getpid();
         kernel_set_ucred_uid(rpid, 0);
         kernel_set_ucred_authid(rpid, 0x4800000000000010ULL);

         /* Calculate total size of USB save folder */
         uint64_t total_size = 0;
         {
             DIR *sd = opendir(s->path);
             if (sd) {
                 struct dirent *se;
                 while ((se = readdir(sd))) {
                     if (se->d_name[0] == '.') continue;
                     char fp[MAX_PATH_LEN];
                     snprintf(fp, sizeof(fp), "%s/%s", s->path, se->d_name);
                     struct stat fst;
                     if (stat(fp, &fst) == 0) total_size += fst.st_size;
                 }
                 closedir(sd);
             }
         }
         if (total_size == 0) total_size = 1024 * 1024;

         /* Create PFS image: size + 25% overhead + 4MB, min 32MB */
         uint64_t img_size = total_size + (total_size / 4) + (4 * 1024 * 1024);
         if (img_size < 32 * 1024 * 1024) img_size = 32 * 1024 * 1024;
         img_size = ((img_size + 32767) / 32768) * 32768;
         chives_geometry_t original;
         int preserve_geometry = is_ps4 ? 0 : chives_read_file(s->path,&original);
         if (preserve_geometry < 0 || (preserve_geometry && original.is_ps4 != is_ps4)) {
             http_json(sock,"{\"error\":\"Invalid or incompatible chives.json in USB save\"}"); return;
         }
         if (preserve_geometry)
             img_size = original.block_count * (uint64_t)original.block_size_bytes;

         if (g_mounted && unmount_save() < 0) {
             http_json(sock,"{\"error\":\"Cannot finalize the previous mount; new image was not created\"}"); return;
         }
         int native_allocation = !is_ps4 && preserve_geometry && chives_file_physical_sfo(s->path,&original);

         mkdir("/data/save_files", 0777);
         const char *tmp = "/data/save_files/_tmp_usb_import";
         unlink(tmp);

         int imgfd = open(tmp, O_CREAT | O_TRUNC | O_RDWR, 0777);
         if (imgfd < 0) {
             http_json(sock, "{\"error\":\"Cannot create temp file\"}"); return;
         }
         int ret = sceFsUfsAllocateSaveData(imgfd, img_size, native_allocation ? 0x80 : 0, NULL);
         if (ret < 0 && native_allocation) {
             int allocation_errno = errno;
             close(imgfd); unlink(tmp);
             char json[256];
             snprintf(json,sizeof(json),"{\"error\":\"Native PS5 allocation flags=0x80 failed: ret=%d (0x%x) errno=%d; ordinary-file fallback blocked\"}",ret,(unsigned)ret,allocation_errno);
             http_json(sock,json); return;
         }
         if (ret < 0) {
             if (ftruncate(imgfd, img_size) < 0) {
                 close(imgfd); unlink(tmp);
                 http_json(sock, "{\"error\":\"Cannot allocate image\"}"); return;
             }
         }
         close(imgfd);

         /* Create PFS image — PS4 and PS5 use different key/format methods */
         uint8_t ckey[0x20] = {0};

         if (is_ps4) {
             /* PS4: generate sealed key, decrypt it */
             uint8_t *kbuf = malloc(0x100);
             if (!kbuf) { unlink(tmp); http_json(sock, "{\"error\":\"Out of memory\"}"); return; }
             memset(kbuf, 0, 0x100);

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
                 free(kbuf); unlink(tmp);
                 http_json(sock, "{\"error\":\"Cannot generate sealed key\"}"); return;
             }
             memcpy(g_sealed_key, kbuf, 96);
             printf("[GarlicMgr] import_usb: PS4 sealed key generated\n");

             /* Decrypt sealed key */
             memset(kbuf, 0, 0x100);
             memcpy(kbuf, g_sealed_key, 96);
             int pfsmgr = open("/dev/pfsmgr", O_RDWR);
             if (pfsmgr < 0) {
                 free(kbuf); unlink(tmp);
                 http_json(sock, "{\"error\":\"Cannot open pfsmgr\"}"); return;
             }
             ret = ioctl(pfsmgr, 0xc0845302, kbuf);
             close(pfsmgr);
             if (ret < 0) {
                 free(kbuf); unlink(tmp);
                 http_json(sock, "{\"error\":\"Cannot decrypt sealed key\"}"); return;
             }
             memcpy(ckey, kbuf + 0x60, 0x20);
             free(kbuf);

             /* Format with non-Ppr create */
             CreateOpt copt;
             memset(&copt, 0, sizeof(copt));
             sceFsInitCreatePfsSaveDataOpt(&copt);
             if (preserve_geometry) chives_apply_opt(&copt,&original);
             ret = sceFsCreatePfsSaveDataImage(&copt, tmp, 0, img_size, ckey);
         } else {
             /* PS5: native PPR creation generates its own sealed key. */
             CreateOpt copt;
             memset(&copt, 0, sizeof(copt));
             sceFsInitCreatePfsSaveDataOpt(&copt);
             if (preserve_geometry) chives_apply_opt(&copt,&original);
             copt.flags[1] = native_allocation ? 0 : 0x02;
            if (!g_pprCreate) {
                 unlink(tmp);
                 http_json(sock, "{\"error\":\"PprCreate not available\"}"); return;
             }
             ret = chives_ppr_create(&copt, tmp, img_size, preserve_geometry ? &original : NULL, native_allocation);
         }
         if (ret < 0) {
             unlink(tmp);
             char json[128];
             snprintf(json, sizeof(json), "{\"error\":\"Format PFS failed: 0x%x\"}", ret);
             http_json(sock, json); return;
         }
         if (preserve_geometry && chives_verify_created(tmp,&original) < 0) {
             unlink(tmp);
             http_json(sock,"{\"error\":\"Formatter geometry mismatch\"}"); return;
         }
         printf("[GarlicMgr] import_usb: PFS formatted (%s)\n", is_ps4 ? "PS4" : "PS5");

         /* Mount PFS */
         snprintf(g_mount_point, sizeof(g_mount_point), "/data/mount_sd");
         mkdir(g_mount_point, 0777);
         MountOpt mopt;
         memset(&mopt, 0, sizeof(mopt));
         sceFsInitMountSaveDataOpt(&mopt);
         mopt.budgetid = "system";
         signal(SIGPIPE, SIG_DFL);
         g_mount_error[0] = 0;
         ret = is_ps4 ? sceFsMountSaveData(&mopt, tmp, g_mount_point, ckey) :
               mount_by_path_at_checked(tmp, "/data/mount_sd", 1, 1);
         signal(SIGPIPE, SIG_IGN);
         if (ret < 0) {
             unlink(tmp);
             char json[1024];
             if (g_mount_error[0]) {
                 char escaped[768]; chives_escape(g_mount_error,escaped,sizeof(escaped));
                 snprintf(json,sizeof(json),"{\"error\":\"%s\"}",escaped);
             } else snprintf(json, sizeof(json), "{\"error\":\"Mount failed: 0x%x\"}", ret);
             http_json(sock, json); return;
         }
         snprintf(g_mounted_path, sizeof(g_mounted_path), "%s", tmp);
         g_local_copy[0] = 0;
         g_mounted = 1;

         /* Copy all files from USB save into PFS */
         if (copy_dir_recursive_impl(s->path,g_mount_point,1) < 0) {
             if (unmount_save() >= 0) unlink(tmp);
             http_json(sock,"{\"error\":\"Failed to copy USB files into image capacity\"}"); return;
         }
         sync();
         printf("[GarlicMgr] import_usb: copied files into PFS\n");

         /* Resign param.sfo */
         uint64_t local_aid = 0;
         char pfs_sfo[MAX_PATH_LEN];
         snprintf(pfs_sfo, sizeof(pfs_sfo), "%s/sce_sys/param.sfo", g_mount_point);
         int owner_result = patch_import_sfo_owner(pfs_sfo, sfo.account_id, uid_hex, uid, is_ps4, &local_aid);
         const char *owner_warning = import_owner_warning(owner_result);
         if (owner_warning[0]) logprintf("[GarlicMgr] WARNING: %s\n", owner_warning);
         printf("[GarlicMgr] import: resigned aid=%016llX uid=0x%x\n",
                (unsigned long long)local_aid, uid);

         /* Copy icon before unmount */
         char icon_tmp[MAX_PATH_LEN] = {0};
         {
             char icon_src[MAX_PATH_LEN];
             snprintf(icon_src, sizeof(icon_src), "%s/sce_sys/icon0.png", g_mount_point);
             struct stat ist;
             if (stat(icon_src, &ist) == 0) {
                 snprintf(icon_tmp, sizeof(icon_tmp), "/data/save_files/_tmp_icon.png");
                 copy_file(icon_src, icon_tmp);
             }
         }

         garlic_save_usage_t import_usage;
         if (capture_save_usage(&sfo,&import_usage) < 0) {
             http_json(sock,"{\"error\":\"Cannot measure save allocation; existing database usage was not changed\"}"); return;
         }

         /* PS5: capture the resigned SFO for the new image's header blob. */
         int usbimp_sfo_fresh = g_image_fresh;
         uint8_t usbimp_sfo[0x8000];
         uint32_t usbimp_sfo_len = 0;
         if (!is_ps4) {
             int sn = read_sfo_file(pfs_sfo, usbimp_sfo, sizeof(usbimp_sfo) - 20);
             if (sn <= 0) {
                 http_json(sock, "{\"error\":\"Cannot read complete final PS5 param.sfo; output was not published or installed\"}"); return;
             }
             usbimp_sfo_len = (uint32_t)sn;
         }

         /* Unmount (re-encrypts) */
         if (unmount_save() < 0) {
             if (icon_tmp[0]) unlink(icon_tmp);
             http_json(sock,"{\"error\":\"Native save finalization failed; save was not installed\"}"); return;
         }

         if (!is_ps4 && usbimp_sfo_len) {
             int wr = finalize_ps5_sfo(tmp, usbimp_sfo, usbimp_sfo_len, usbimp_sfo_fresh);
             if (wr < 0) {
                 http_ps5param_failure(sock); return;
             } else
                 logprintf("[GarlicMgr] PS5PARAM: finalized imported param.sfo (%u B)\n",
                           usbimp_sfo_len);
         }

         char metadata_warning[1024];
         if (!is_ps4 && ps5param_warning()[0]) {
             snprintf(metadata_warning,sizeof(metadata_warning),"%s%s%s",owner_warning,
                      owner_warning[0] ? "; " : "",ps5param_warning());
             owner_warning=metadata_warning;
         }

         /* Copy encrypted image to system save location */
         char sd_dir[MAX_PATH_LEN], sd_dst[MAX_PATH_LEN];
         snprintf(sd_dir, sizeof(sd_dir), "/user/home/%s/%s/%s", uid_hex,
                  is_ps4 ? "savedata" : "savedata_prospero", sfo.title_id);
         snprintf(sd_dst, sizeof(sd_dst), "%s/sdimg_%s", sd_dir, sfo.dir_name);
         recursive_mkdir(sd_dir);

         if (copy_file(tmp, sd_dst) < 0) {
             unlink(tmp);
             if (icon_tmp[0]) unlink(icon_tmp);
             http_json(sock, "{\"error\":\"Failed to copy save\"}"); return;
         }
         unlink(tmp);
         chmod(sd_dst, 0644);

         /* PS4: write .bin sealed key companion */
         if (is_ps4) {
             char bin_dst[MAX_PATH_LEN];
             snprintf(bin_dst, sizeof(bin_dst), "%s/%s.bin", sd_dir, sfo.dir_name);
             int bfd = open(bin_dst, O_CREAT | O_WRONLY | O_TRUNC, 0644);
             if (bfd >= 0) {
                 write(bfd, g_sealed_key, 96);
                 close(bfd);
                 printf("[GarlicMgr] import_usb: wrote PS4 .bin key -> %s\n", bin_dst);
             }
         }

         /* Copy icon */
         if (icon_tmp[0]) {
             char icon_dir[MAX_PATH_LEN], icon_dst[MAX_PATH_LEN];
             snprintf(icon_dir, sizeof(icon_dir),
                      "/user/home/%s/savedata_prospero_meta/user/%s", uid_hex, sfo.title_id);
             snprintf(icon_dst, sizeof(icon_dst), "%s/%s_icon0.png", icon_dir, sfo.dir_name);
             recursive_mkdir(icon_dir);
             copy_file(icon_tmp, icon_dst);
             unlink(icon_tmp);
         }

         /* Update savedata.db */
         char db_path[MAX_PATH_LEN];
         snprintf(db_path, sizeof(db_path), "/system_data/%s/%s/db/user/savedata.db",
                  is_ps4 ? "savedata" : "savedata_prospero", uid_hex);
         {
             char db_dir[MAX_PATH_LEN];
             snprintf(db_dir, sizeof(db_dir), "/system_data/%s/%s/db/user",
                      is_ps4 ? "savedata" : "savedata_prospero", uid_hex);
             recursive_mkdir(db_dir);
         }
         sqlite3 *db = NULL;
         ret = sqlite3_open(db_path, &db);
         if (ret == SQLITE_OK) {
             char *err_msg = NULL;
             sqlite3_exec(db,
                 "CREATE TABLE IF NOT EXISTS savedata ("
                 "id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,"
                 "title_id NOT NULL, dir_name NOT NULL, main_title NOT NULL,"
                 "sub_title, detail, tmp_dir_name, is_broken, user_param,"
                 "blocks, free_blocks, size_kib, mtime NOT NULL,"
                 "fake_broken, account_id, user_id, faked_owner,"
                 "cloud_icon_url, cloud_revision, game_title_id NOT NULL, system_blocks)",
                 NULL, 0, &err_msg);
             if (err_msg) { sqlite3_free(err_msg); err_msg = NULL; }

             /* Escape strings */
             char esc_title[256] = {0};
             {
                 char *src = sfo.main_title, *dst = esc_title;
                 while (*src && dst < esc_title + sizeof(esc_title) - 2) {
                     if (*src == '\'') *dst++ = '\'';
                     *dst++ = *src++;
                 }
                 *dst = 0;
             }

             char mtime[64];
             { time_t now = time(NULL); struct tm *tm = gmtime(&now);
               strftime(mtime, sizeof(mtime), "%Y-%m-%dT%H:%M:%S.00Z", tm); }

             uint64_t aid_val = local_aid;

             /* Check if exists */
             char check_sql[512];
             snprintf(check_sql, sizeof(check_sql),
                      "SELECT COUNT(*) FROM savedata WHERE title_id='%s' AND dir_name='%s'",
                      sfo.title_id, sfo.dir_name);
             sqlite3_stmt *stmt = NULL;
             int db_exists = 0;
             if (sqlite3_prepare_v2(db, check_sql, -1, &stmt, NULL) == SQLITE_OK) {
                 if (sqlite3_step(stmt) == SQLITE_ROW)
                     db_exists = sqlite3_column_int(stmt, 0);
                 sqlite3_finalize(stmt);
             }

             char sql[2048];
             if (db_exists) {
                 snprintf(sql, sizeof(sql),
                     "UPDATE savedata SET main_title='%s', mtime='%s', account_id=%lld, user_id=%u, is_broken=0, "
                         "blocks=%llu, free_blocks=%llu, size_kib=%llu, system_blocks=%llu "
                     "WHERE title_id='%s' AND dir_name='%s'",
                     esc_title, mtime, (long long)(int64_t)aid_val, uid,
                     (unsigned long long)import_usage.blocks,(unsigned long long)import_usage.free_blocks,
                     (unsigned long long)import_usage.size_kib,(unsigned long long)import_usage.system_blocks,
                     sfo.title_id, sfo.dir_name);
             } else {
                 snprintf(sql, sizeof(sql),
                     "INSERT INTO savedata (title_id, dir_name, main_title, sub_title, detail,"
                     "is_broken, user_param, blocks, free_blocks, size_kib, mtime,"
                     "fake_broken, account_id, user_id, faked_owner, cloud_revision,"
                     "game_title_id, system_blocks) VALUES ("
                     "'%s','%s','%s','','',0,%u,%llu,%llu,%llu,'%s',0,%lld,%u,0,0,'%s',%llu)",
                     sfo.title_id, sfo.dir_name, esc_title,
                     sfo.list_param, (unsigned long long)import_usage.blocks,(unsigned long long)import_usage.free_blocks,
                     (unsigned long long)import_usage.size_kib,mtime,
                     (long long)(int64_t)aid_val, uid, sfo.title_id,(unsigned long long)import_usage.system_blocks);
             }
             ret = sqlite3_exec(db, sql, NULL, 0, &err_msg);
             if (ret != SQLITE_OK) {
                 printf("[GarlicMgr] import_usb: DB error: %s\n", err_msg);
                 sqlite3_free(err_msg);
             } else {
                 printf("[GarlicMgr] import_usb: DB %s OK\n", db_exists ? "updated" : "inserted");
             }
             sqlite3_close(db);
         }

         char json[1024];
         snprintf(json, sizeof(json),
                  "{\"ok\":true,\"title_id\":\"%s\",\"dir_name\":\"%s\",\"main_title\":\"%s\",\"warning\":\"%s\"}",
                  sfo.title_id, sfo.dir_name, sfo.main_title, owner_warning);
         http_json(sock, json);
         return;
     }

     /* GET /api/import_finish -> parse SFO, resign, unmount, copy to final location, update DB */
     if (strcmp(method, "GET") == 0 && strncmp(url, "/api/import_finish", 18) == 0) {
         if (!g_mounted) {
             http_json(sock, "{\"error\":\"No save mounted\"}"); return;
         }

         /* Parse param.sfo from mounted save */
         char sfo_path[MAX_PATH_LEN];
         snprintf(sfo_path, sizeof(sfo_path), "%s/sce_sys/param.sfo", g_mount_point);
         /* PS5: restore real metadata from the header blob (in-PFS is zero). */
         if (ps5param_cached_for_mount(g_mount_point)) {
             if (install_sfo_file(sfo_path, ps5param_cache_data(), ps5param_cache_size()) < 0) {
                 http_json(sock, "{\"error\":\"Cannot restore real PS5 metadata\"}"); return;
             }
             cache_params_hmac_mem(ps5param_cache_data(), ps5param_cache_size());
         }
         sfo_info_t sfo;
         int sfo_ret = parse_sfo(sfo_path, &sfo);
         int force = (strstr(url, "force=1") != NULL);
         if (sfo_ret == -2 && !force) {
             /* Check if DB entry exists for regen */
             int has_db = 0;
             if (g_mounted_idx >= 0) {
                 save_entry_t *ms = &g_saves[g_mounted_idx];
                 char uid_hex_tmp[16] = {0};
                 char *uidp_tmp = strstr(url, "uid=");
                 if (uidp_tmp) { strncpy(uid_hex_tmp, uidp_tmp + 4, sizeof(uid_hex_tmp) - 1);
                     char *amp = strchr(uid_hex_tmp, '&'); if (amp) *amp = 0; }
                 if (!uid_hex_tmp[0]) {
                     int lu = 0; sceUserServiceGetForegroundUser(&lu);
                     snprintf(uid_hex_tmp, sizeof(uid_hex_tmp), "%x", (uint32_t)lu);
                 }
                 const char *db_types[] = {"savedata_prospero", "savedata"};
                 for (int dt = 0; dt < 2 && !has_db; dt++) {
                     char db_path[MAX_PATH_LEN];
                     snprintf(db_path, sizeof(db_path), "/system_data/%s/%s/db/user/savedata.db",
                              db_types[dt], uid_hex_tmp);
                     sqlite3 *db = NULL;
                     if (sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
                         char sql[512];
                         snprintf(sql, sizeof(sql),
                             "SELECT 1 FROM savedata WHERE title_id='%s' AND dir_name='%s' LIMIT 1",
                             ms->title_id, ms->save_name);
                         sqlite3_stmt *st = NULL;
                         if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK &&
                             sqlite3_step(st) == SQLITE_ROW) has_db = 1;
                         if (st) sqlite3_finalize(st);
                         sqlite3_close(db);
                     }
                 }
             }
             char resp[64];
             snprintf(resp, sizeof(resp), "{\"sfo_zeroed\":true,\"db_found\":%s}",
                      has_db ? "true" : "false");
             http_json(sock, resp);
             return;
         }
         if (sfo_ret < 0 && !force) {
             http_json(sock, "{\"error\":\"Cannot parse param.sfo — is sce_sys/param.sfo present?\"}");
             return;
         }
         /* Force mode with bad SFO: use mounted save entry or query params as fallback */
         if (sfo_ret < 0 && force) {
             if (g_mounted_idx >= 0) {
                 save_entry_t *ms = &g_saves[g_mounted_idx];
                 strncpy(sfo.title_id, ms->title_id, sizeof(sfo.title_id) - 1);
                 strncpy(sfo.dir_name, ms->save_name, sizeof(sfo.dir_name) - 1);
                 if (strncmp(sfo.dir_name, "sdimg_", 6) == 0)
                     memmove(sfo.dir_name, sfo.dir_name + 6, strlen(sfo.dir_name) - 5);
                 strncpy(sfo.main_title, ms->title_id, sizeof(sfo.main_title) - 1);
                 sfo.blocks = 96;
                 strcpy(sfo.format, ms->is_ps4 ? "obs" : "ppr");
             } else {
                 /* Try query params: title_id and dir_name */
                 char *tp = strstr(url, "title_id=");
                 char *dp = strstr(url, "dir_name=");
                 if (tp) {
                     tp += 9;
                     int ti = 0;
                     while (tp[ti] && tp[ti] != '&' && ti < (int)sizeof(sfo.title_id) - 1)
                         { sfo.title_id[ti] = tp[ti]; ti++; }
                     sfo.title_id[ti] = 0;
                 }
                 if (dp) {
                     dp += 9;
                     int di = 0;
                     while (dp[di] && dp[di] != '&' && di < (int)sizeof(sfo.dir_name) - 1)
                         { sfo.dir_name[di] = dp[di]; di++; }
                     sfo.dir_name[di] = 0;
                 }
                 if (sfo.title_id[0])
                     strncpy(sfo.main_title, sfo.title_id, sizeof(sfo.main_title) - 1);
                 sfo.blocks = 96;
                 strcpy(sfo.format, "ppr");
             }
         }
         if (!sfo.title_id[0] || !sfo.dir_name[0]) {
             http_json(sock, "{\"error\":\"param.sfo missing TITLE_ID or SAVEDATA_DIRECTORY\"}");
             return;
         }
         /* Detect PS4 vs PS5 from SFO FORMAT field: "obs"=PS4, "ppr"=PS5 */
         g_enc_ps4 = sfo_is_ps4(&sfo, g_enc_ps4);
         printf("[GarlicMgr] import: title_id=%s dir=%s title=%s blocks=%llu FORMAT=%s %s\n",
                sfo.title_id, sfo.dir_name, sfo.main_title, (unsigned long long)sfo.blocks,
                sfo.format, g_enc_ps4 ? "(PS4)" : "(PS5)");

         /* Get user info — prefer uid query param, fallback to foreground user */
         char uid_hex[16] = {0};
         char *uidp = strstr(url, "uid=");
         if (uidp) {
             strncpy(uid_hex, uidp + 4, sizeof(uid_hex) - 1);
             char *amp = strchr(uid_hex, '&');
             if (amp) *amp = 0;
         }
         uint32_t uid;
         if (uid_hex[0]) {
             uid = (uint32_t)strtoul(uid_hex, NULL, 16);
         } else {
             int local_uid = 0;
             sceUserServiceGetForegroundUser(&local_uid);
             uid = (uint32_t)local_uid;
             snprintf(uid_hex, sizeof(uid_hex), "%x", uid);
         }

         /* Read local account_id from registry */
         uint64_t local_aid = 0;
         int owner_result = patch_import_sfo_owner(sfo_path, sfo.account_id, uid_hex, uid, g_enc_ps4, &local_aid);
         const char *owner_warning = import_owner_warning(owner_result);
         if (owner_warning[0]) logprintf("[GarlicMgr] WARNING: %s\n", owner_warning);
         printf("[GarlicMgr] import: resigned aid=%016llX uid=0x%x\n",
                (unsigned long long)local_aid, uid);

         /* Copy icon before unmount */
         char icon_src[MAX_PATH_LEN];
         char icon_tmp[MAX_PATH_LEN] = {0};
         snprintf(icon_src, sizeof(icon_src), "%s/sce_sys/icon0.png", g_mount_point);
         struct stat icon_st;
         if (stat(icon_src, &icon_st) == 0) {
             snprintf(icon_tmp, sizeof(icon_tmp), "/data/save_files/_tmp_icon.png");
             copy_file(icon_src, icon_tmp);
         }

         /* Save mounted path before unmount clears it */
         char tmp_path[MAX_PATH_LEN];
         snprintf(tmp_path, sizeof(tmp_path), "%s", g_mounted_path);

         /* Decrypted PS4 imports created by create_pfs have a freshly generated
          * key, unlike encrypted imports whose companion was uploaded. Stage
          * that key before installing so we never reuse an old import's key. */
         if (g_enc_ps4 && strcmp(tmp_path, "/data/save_files/_tmp_enc") == 0) {
             const char *key_path = "/data/save_files/_tmp_import.bin";
             int key_fd = open(key_path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
             ssize_t key_written = key_fd >= 0 ? write(key_fd, g_sealed_key, sizeof(g_sealed_key)) : -1;
             if (key_fd >= 0) close(key_fd);
             if (key_written != (ssize_t)sizeof(g_sealed_key)) {
                 unlink(key_path);
                 if (icon_tmp[0]) unlink(icon_tmp);
                 http_json(sock, "{\"error\":\"Cannot stage PS4 sealed key for import\"}");
                 return;
             }
         }

         /* Refuse to replace the installed image when its required key is
          * missing. A successful image copy alone is not a valid PS4 import. */
         if (g_enc_ps4) {
             struct stat key_st;
             if (stat("/data/save_files/_tmp_import.bin", &key_st) < 0 || key_st.st_size < 96) {
                 if (icon_tmp[0]) unlink(icon_tmp);
                 http_json(sock, "{\"error\":\"PS4 import key is missing or incomplete; existing save was not replaced\"}");
                 return;
             }
         }

         garlic_save_usage_t import_usage;
         if (capture_save_usage(&sfo,&import_usage) < 0) {
             http_json(sock,"{\"error\":\"Cannot measure save allocation; existing database usage was not changed\"}"); return;
         }

         /* PS5: capture the resigned SFO for the image's header blob. */
         int imp_sfo_fresh = g_image_fresh;
         uint8_t imp_sfo[0x8000];
         uint32_t imp_sfo_len = 0;
         if (!g_enc_ps4) {
             int sn = read_sfo_file(sfo_path, imp_sfo, sizeof(imp_sfo) - 20);
             if (sn <= 0) {
                 http_json(sock, "{\"error\":\"Cannot read complete final PS5 param.sfo; output was not published or installed\"}"); return;
             }
             imp_sfo_len = (uint32_t)sn;
         }

         /* Unmount (re-encrypts the PFS image) */
         if (unmount_save() < 0) {
             if (icon_tmp[0]) unlink(icon_tmp);
             http_json(sock,"{\"error\":\"Native save finalization failed; save was not installed\"}"); return;
         }

         if (!g_enc_ps4 && imp_sfo_len) {
             int wr = finalize_ps5_sfo(tmp_path, imp_sfo, imp_sfo_len, imp_sfo_fresh);
             if (wr < 0) {
                 http_ps5param_failure(sock); return;
             } else
                 logprintf("[GarlicMgr] PS5PARAM: finalized imported param.sfo (%u B)\n",
                           imp_sfo_len);
         }

         char metadata_warning[1024];
         if (!g_enc_ps4 && ps5param_warning()[0]) {
             snprintf(metadata_warning,sizeof(metadata_warning),"%s%s%s",owner_warning,
                      owner_warning[0] ? "; " : "",ps5param_warning());
             owner_warning=metadata_warning;
         }

         /* Build destination paths — PS4: savedata/, PS5: savedata_prospero/ */
         char sd_dir[MAX_PATH_LEN], sd_dst[MAX_PATH_LEN];
         snprintf(sd_dir, sizeof(sd_dir),
                  "/user/home/%s/%s/%s", uid_hex,
                  g_enc_ps4 ? "savedata" : "savedata_prospero", sfo.title_id);
         snprintf(sd_dst, sizeof(sd_dst),
                  "%s/sdimg_%s", sd_dir, sfo.dir_name);

         /* Create directories */
         recursive_mkdir(sd_dir);

         /* Copy encrypted image to final location */
         int from_usb = (strncmp(tmp_path, "/mnt/usb", 8) == 0);
         printf("[GarlicMgr] import: copying %s -> %s\n", tmp_path, sd_dst);
         if (copy_file(tmp_path, sd_dst) < 0) {
             if (!from_usb) unlink(tmp_path);
             if (icon_tmp[0]) unlink(icon_tmp);
             http_json(sock, "{\"error\":\"Failed to copy save to destination\"}");
             return;
         }
         if (!from_usb) unlink(tmp_path);
         chmod(sd_dst, 0644);

         /* PS4: also copy the .bin sealed key companion */
         if (g_enc_ps4) {
             char bin_src[MAX_PATH_LEN], bin_dst[MAX_PATH_LEN];
             /* tmp_path was like /data/save_files/sdimg__tmp_import
              * .bin is at /data/save_files/_tmp_import.bin */
             snprintf(bin_src, sizeof(bin_src), "/data/save_files/_tmp_import.bin");
             snprintf(bin_dst, sizeof(bin_dst), "%s/%s.bin", sd_dir, sfo.dir_name);
             if (copy_file(bin_src, bin_dst) == 0) {
                 chmod(bin_dst, 0644);
                 printf("[GarlicMgr] import: PS4 .bin key -> %s\n", bin_dst);
             } else {
                 logprintf("[GarlicMgr] import: failed to copy .bin key %s -> %s (errno=%d)\n", bin_src, bin_dst, errno);
                 if (icon_tmp[0]) unlink(icon_tmp);
                 http_json(sock, "{\"error\":\"PS4 save image copied but companion key installation failed. Import is incomplete; re-import the save.\"}");
                 return;
             }
             if (!from_usb) unlink(bin_src);
         }

         /* Copy icon to meta directory */
         if (icon_tmp[0]) {
             char icon_dir[MAX_PATH_LEN], icon_dst[MAX_PATH_LEN];
             snprintf(icon_dir, sizeof(icon_dir),
                      "/user/home/%s/savedata_prospero_meta/user/%s", uid_hex, sfo.title_id);
             snprintf(icon_dst, sizeof(icon_dst),
                      "%s/%s_icon0.png", icon_dir, sfo.dir_name);
             recursive_mkdir(icon_dir);
             copy_file(icon_tmp, icon_dst);
             unlink(icon_tmp);
             printf("[GarlicMgr] import: icon -> %s\n", icon_dst);
         }

         /* Update savedata.db — PS4: savedata/, PS5: savedata_prospero/ */
         char db_path[MAX_PATH_LEN];
         snprintf(db_path, sizeof(db_path),
                  "/system_data/%s/%s/db/user/savedata.db",
                  g_enc_ps4 ? "savedata" : "savedata_prospero", uid_hex);

         /* Create DB dir if needed */
         {
             char db_dir[MAX_PATH_LEN];
             snprintf(db_dir, sizeof(db_dir),
                      "/system_data/%s/%s/db/user",
                      g_enc_ps4 ? "savedata" : "savedata_prospero", uid_hex);
             recursive_mkdir(db_dir);
         }

         sqlite3 *db = NULL;
         int ret = sqlite3_open(db_path, &db);
         if (ret != SQLITE_OK) {
             printf("[GarlicMgr] import: cannot open savedata.db: %s\n", sqlite3_errmsg(db));
             if (db) sqlite3_close(db);
             /* Save is already copied, just DB update failed */
             char json[1024];
             snprintf(json, sizeof(json),
                      "{\"ok\":true,\"warning\":\"Save imported but DB update failed. %s\","
                      "\"title_id\":\"%s\",\"dir_name\":\"%s\"}", owner_warning, sfo.title_id, sfo.dir_name);
             http_json(sock, json);
             return;
         }

         /* Create table if it doesn't exist */
         char *err_msg = NULL;
         sqlite3_exec(db,
             "CREATE TABLE IF NOT EXISTS savedata ("
             "id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,"
             "title_id NOT NULL, dir_name NOT NULL, main_title NOT NULL,"
             "sub_title, detail, tmp_dir_name, is_broken, user_param,"
             "blocks, free_blocks, size_kib, mtime NOT NULL,"
             "fake_broken, account_id, user_id, faked_owner,"
             "cloud_icon_url, cloud_revision, game_title_id NOT NULL, system_blocks)",
             NULL, 0, &err_msg);
         if (err_msg) { sqlite3_free(err_msg); err_msg = NULL; }

         sqlite3_exec(db,
             "CREATE INDEX IF NOT EXISTS savedata_index ON savedata"
             "(title_id, dir_name, user_param, size_kib, mtime, game_title_id)",
             NULL, 0, &err_msg);
         if (err_msg) { sqlite3_free(err_msg); err_msg = NULL; }

         /* Escape single quotes in strings */
         char esc_title[256], esc_sub[256], esc_detail[512];
         {
             char *src, *dst;
             src = sfo.main_title; dst = esc_title;
             while (*src && dst < esc_title + sizeof(esc_title) - 2) {
                 if (*src == '\'') *dst++ = '\'';
                 *dst++ = *src++;
             }
             *dst = 0;
             src = sfo.sub_title; dst = esc_sub;
             while (*src && dst < esc_sub + sizeof(esc_sub) - 2) {
                 if (*src == '\'') *dst++ = '\'';
                 *dst++ = *src++;
             }
             *dst = 0;
             src = sfo.detail; dst = esc_detail;
             while (*src && dst < esc_detail + sizeof(esc_detail) - 2) {
                 if (*src == '\'') *dst++ = '\'';
                 *dst++ = *src++;
             }
             *dst = 0;
         }

         /* Get current timestamp */
         char mtime[64];
         {
             time_t now = time(NULL);
             struct tm *tm = gmtime(&now);
             strftime(mtime, sizeof(mtime), "%Y-%m-%dT%H:%M:%S.00Z", tm);
         }

         /* Check if entry already exists */
         char check_sql[512];
         snprintf(check_sql, sizeof(check_sql),
                  "SELECT COUNT(*) FROM savedata WHERE title_id='%s' AND dir_name='%s'",
                  sfo.title_id, sfo.dir_name);
         sqlite3_stmt *stmt = NULL;
         int exists = 0;
         if (sqlite3_prepare_v2(db, check_sql, -1, &stmt, NULL) == SQLITE_OK) {
             if (sqlite3_step(stmt) == SQLITE_ROW)
                 exists = sqlite3_column_int(stmt, 0);
             sqlite3_finalize(stmt);
         }

         uint64_t aid_val = local_aid;

         char sql[2048];
         if (exists) {
             snprintf(sql, sizeof(sql),
                 "UPDATE savedata SET main_title='%s', sub_title='%s', detail='%s',"
                 "is_broken=0, user_param=%u, blocks=%llu, free_blocks=%llu, size_kib=%llu, system_blocks=%llu,"
                 "mtime='%s', account_id=%lld, user_id=%u "
                 "WHERE title_id='%s' AND dir_name='%s'",
                 esc_title, esc_sub, esc_detail,
                 sfo.list_param,(unsigned long long)import_usage.blocks,(unsigned long long)import_usage.free_blocks,
                 (unsigned long long)import_usage.size_kib,(unsigned long long)import_usage.system_blocks,
                 mtime, (long long)(int64_t)aid_val, uid,
                 sfo.title_id, sfo.dir_name);
         } else {
             snprintf(sql, sizeof(sql),
                 "INSERT INTO savedata (title_id, dir_name, main_title, sub_title, detail,"
                 "is_broken, user_param, blocks, free_blocks, size_kib, mtime,"
                 "fake_broken, account_id, user_id, faked_owner, cloud_revision,"
                 "game_title_id, system_blocks) VALUES ("
                 "'%s','%s','%s','%s','%s',"
                 "0,%u,%llu,%llu,%llu,'%s',"
                 "0,%lld,%u,0,0,"
                 "'%s',%llu)",
                 sfo.title_id, sfo.dir_name, esc_title, esc_sub, esc_detail,
                 sfo.list_param,(unsigned long long)import_usage.blocks,(unsigned long long)import_usage.free_blocks,
                 (unsigned long long)import_usage.size_kib,mtime,
                 (long long)(int64_t)aid_val, uid,
                 sfo.game_title_id,(unsigned long long)import_usage.system_blocks);
         }

         ret = sqlite3_exec(db, sql, NULL, 0, &err_msg);
         if (ret != SQLITE_OK) {
             printf("[GarlicMgr] import: DB error: %s\n", err_msg);
             sqlite3_free(err_msg);
         } else {
             printf("[GarlicMgr] import: DB %s OK\n", exists ? "updated" : "inserted");
         }
         sqlite3_close(db);

         char json[1024];
         snprintf(json, sizeof(json),
                  "{\"ok\":true,\"title_id\":\"%s\",\"dir_name\":\"%s\","
                  "\"main_title\":\"%s\",\"exists\":%s,\"warning\":\"%s\"}",
                  sfo.title_id, sfo.dir_name, sfo.main_title,
                  exists ? "true" : "false", owner_warning);
         http_json(sock, json);
         return;
     }

     /* GET /api/export_title?id=<title_id> -> zip all saves for a title */
     if (strcmp(method, "GET") == 0 && strncmp(url, "/api/export_title", 17) == 0 && url[17] != '_') {
         char tid[64] = {0};
         char *tp = strstr(url, "id=");
         if (tp) {
             strncpy(tid, tp + 3, sizeof(tid) - 1);
             char *amp = strchr(tid, '&');
             if (amp) *amp = 0;
             /* URL-decode */
             char *r = tid, *w = tid;
             while (*r) {
                 if (*r == '%' && r[1] && r[2]) {
                     char hex[3] = {r[1], r[2], 0};
                     *w++ = (char)strtol(hex, NULL, 16);
                     r += 3;
                 } else { *w++ = *r++; }
             }
             *w = 0;
         }
         if (!tid[0]) { http_json(sock, "{\"error\":\"Missing id\"}"); return; }

         scan_saves();
         kernel_set_ucred_authid(getpid(), 0x4800000000000010ULL);

         /* Collect all saves matching this title_id (x2 for PS4 .bin companions) */
         zip_file_t *zfiles = malloc(g_save_count * 2 * sizeof(zip_file_t));
         char **names = malloc(g_save_count * 2 * sizeof(char*));
         char **allocs = malloc(g_save_count * sizeof(char*));
         int nfiles = 0, nallocs = 0;
         for (int i = 0; i < g_save_count; i++) {
             if (strcmp(g_saves[i].title_id, tid) != 0) continue;
             struct stat fst;
             if (stat(g_saves[i].path, &fst) < 0) continue;
             zfiles[nfiles].path = g_saves[i].path;
             names[nfiles] = malloc(512);
             snprintf(names[nfiles], 512, "%s/%s", tid, g_saves[i].save_name);
             zfiles[nfiles].name = names[nfiles];

             /* For PS4 saves, also include .bin key if it exists */
             if (g_saves[i].is_ps4 && strncmp(g_saves[i].save_name, "sdimg_", 6) == 0) {
                 const char *savename = g_saves[i].save_name + 6;
                 char dir[MAX_PATH_LEN];
                 strncpy(dir, g_saves[i].path, sizeof(dir) - 1);
                 dir[sizeof(dir) - 1] = 0;
                 char *sl = strrchr(dir, '/');
                 if (sl) *(sl + 1) = 0;
                 char *bin_path = malloc(MAX_PATH_LEN);
                 snprintf(bin_path, MAX_PATH_LEN, "%s%s.bin", dir, savename);
                 if (stat(bin_path, &fst) == 0) {
                     nfiles++;
                     zfiles[nfiles].path = bin_path;
                     allocs[nallocs++] = bin_path;
                     names[nfiles] = malloc(512);
                     snprintf(names[nfiles], 512, "%s/%s.bin", tid, savename);
                     zfiles[nfiles].name = names[nfiles];
                 } else {
                     free(bin_path);
                 }
             }
             nfiles++;
         }

         if (nfiles == 0) {
             free(zfiles); free(names); free(allocs);
             http_json(sock, "{\"error\":\"No saves found for this title\"}");
             return;
         }

         char zip_name[128];
         snprintf(zip_name, sizeof(zip_name), "%s_saves.zip", tid);
         char hdr[512];
         int hlen = snprintf(hdr, sizeof(hdr),
             "HTTP/1.1 200 OK\r\n"
             "Content-Type: application/zip\r\n"
             "Content-Disposition: attachment; filename=\"%s\"\r\n"
             "Access-Control-Allow-Origin: *\r\n"
             "Connection: close\r\n\r\n", zip_name);
         send(sock, hdr, hlen, 0);
         zip_send_files(sock, zfiles, nfiles, iobuf);

         for (int i = 0; i < nfiles; i++) free(names[i]);
         for (int i = 0; i < nallocs; i++) free(allocs[i]);
         free(names); free(zfiles); free(allocs);
         return;
     }

     /* GET /api/export_title_dec?id=<title_id> -> mount each save, zip decrypted contents */
     if (strcmp(method, "GET") == 0 && strncmp(url, "/api/export_title_dec", 21) == 0) {
         char tid[64] = {0};
         char *tp = strstr(url, "id=");
         if (tp) {
             strncpy(tid, tp + 3, sizeof(tid) - 1);
             char *amp = strchr(tid, '&');
             if (amp) *amp = 0;
             char *r = tid, *w = tid;
             while (*r) {
                 if (*r == '%' && r[1] && r[2]) {
                     char hex[3] = {r[1], r[2], 0};
                     *w++ = (char)strtol(hex, NULL, 16);
                     r += 3;
                 } else { *w++ = *r++; }
             }
             *w = 0;
         }
         if (!tid[0]) { http_json(sock, "{\"error\":\"Missing id\"}"); return; }

         scan_saves();
         kernel_set_ucred_authid(getpid(), 0x4800000000000010ULL);

         /* Collect indices of saves matching this title */
         int *indices = malloc(g_save_count * sizeof(int));
         int nidx = 0;
         for (int i = 0; i < g_save_count; i++)
             if (strcmp(g_saves[i].title_id, tid) == 0)
                 indices[nidx++] = i;

         if (nidx == 0) {
             free(indices);
             http_json(sock, "{\"error\":\"No saves found for this title\"}");
             return;
         }

         /* For each save: mount, collect files into memory, unmount.
          * Store all entries with save_name/ prefix for the final zip. */
         typedef struct {
             char name[512];
             uint8_t *data;
             uint32_t size;
             uint32_t crc;
             uint32_t offset;
         } dec_entry_t;

         /* Sidecars have their own slots so they never displace game files. */
         int all_capacity = MAX_ZIP_ENTRIES + nidx;
         dec_entry_t *all_entries = malloc((size_t)all_capacity * sizeof(dec_entry_t));
         int total = 0, game_total = 0;
         if (!all_entries) {
             free(indices);
             http_json(sock,"{\"error\":\"Out of memory\"}"); return;
         }

         for (int n = 0; n < nidx && total < all_capacity; n++) {
             int idx = indices[n];
             if (g_mounted) unmount_save();

             int ret = mount_save(idx);
             if (ret < 0) continue;

             char metadata[2048];
             int metadata_len=chives_export_json(g_local_copy[0] ? g_local_copy : g_mounted_path,
                                                 g_mount_point,metadata,sizeof(metadata));
             if (metadata_len < 0) {
                 unmount_save();
                 for (int j=0;j<total;j++) free(all_entries[j].data);
                 free(all_entries); free(indices);
                 http_json(sock,"{\"error\":\"Cannot read original PFS geometry for title export\"}"); return;
             }
             if (metadata_len > 0) {
             dec_entry_t *meta_entry=&all_entries[total];
             memset(meta_entry,0,sizeof(*meta_entry));
             snprintf(meta_entry->name,sizeof(meta_entry->name),"%s/%s/chives.json",tid,g_saves[idx].save_name);
             meta_entry->size=(uint32_t)metadata_len;
             meta_entry->data=malloc((size_t)metadata_len);
             if (!meta_entry->data) {
                 unmount_save();
                 for (int j=0;j<total;j++) free(all_entries[j].data);
                 free(all_entries); free(indices);
                 http_json(sock,"{\"error\":\"Out of memory for save metadata\"}"); return;
             }
             memcpy(meta_entry->data,metadata,(size_t)metadata_len);
             meta_entry->crc=calc_crc(meta_entry->data,meta_entry->size);
             total++;
             }

             /* Collect file list from mounted save */
             zip_entry_t *tmp_entries = malloc(MAX_ZIP_ENTRIES * sizeof(zip_entry_t));
             int tmp_count = 0;
             collect_files(g_mount_point, "", tmp_entries, &tmp_count);
             if (tmp_count > MAX_ZIP_ENTRIES - game_total) {
                 free(tmp_entries); unmount_save();
                 for (int j=0;j<total;j++) free(all_entries[j].data);
                 free(all_entries); free(indices);
                 http_json(sock,"{\"error\":\"Too many files for title export\"}"); return;
             }
             game_total += tmp_count;

             const char *sname = g_saves[idx].save_name;
             for (int f = 0; f < tmp_count && total < all_capacity; f++) {
                 if (chives_is_sidecar(tmp_entries[f].name)) continue;
                 dec_entry_t *de = &all_entries[total];
                 snprintf(de->name, sizeof(de->name), "%s/%s/%s", tid, sname, tmp_entries[f].name);
                 de->size = tmp_entries[f].size;
                 de->data = NULL;

                 char fullpath[MAX_PATH_LEN];
                 snprintf(fullpath, sizeof(fullpath), "%s/%s", g_mount_point, tmp_entries[f].name);
                 if (de->size > 0) {
                     int fd = open(fullpath, O_RDONLY);
                     if (fd >= 0) {
                         de->data = malloc(de->size);
                         if (de->data) {
                             ssize_t rd = read(fd, de->data, de->size);
                             if (rd < (ssize_t)de->size) de->size = rd > 0 ? (uint32_t)rd : 0;
                         }
                         close(fd);
                     }
                 }
                 /* PS5: replace the zeroed in-PFS placeholder with the real
                  * metadata recovered from the image's PS5PARAM blob. */
                 if (ps5param_cached_for_mount(g_mount_point) &&
                     ps5param_is_sfo_name(tmp_entries[f].name)) {
                     uint32_t n2 = ps5param_cache_size();
                     uint8_t *nb = malloc(n2);
                     if (nb) {
                         memcpy(nb, ps5param_cache_data(), n2);
                         free(de->data);
                         de->data = nb;
                         de->size = n2;
                         cache_params_hmac_mem(de->data, de->size);
                     }
                 }
                 /* Cache HMAC from valid param.sfo for reuse */
                 if (!g_params_hmac_valid && de->data && de->size > 0 &&
                     ps5param_is_sfo_name(tmp_entries[f].name)) {
                     char sfo_tmp_path[MAX_PATH_LEN];
                     snprintf(sfo_tmp_path, sizeof(sfo_tmp_path), "%s/%s",
                              g_mount_point, tmp_entries[f].name);
                     cache_params_hmac(sfo_tmp_path);
                 }
                 /* Fix zeroed param.sfo: regenerate valid SFO in memory */
                 if (de->data && de->size > 0 &&
                     ps5param_is_sfo_name(tmp_entries[f].name)) {
                     int zeroed = 1;
                     for (uint32_t b = 0; b < de->size && b < 256; b++)
                         if (de->data[b]) { zeroed = 0; break; }
                     if (zeroed) {
                         logprintf("[GarlicMgr] Fixing zeroed param.sfo for %s/%s\n", tid, sname);
                         /* Query savedata DB for full metadata */
                         const char *sd = g_saves[idx].is_ps4 ? "savedata" : "savedata_prospero";
                         char db_path[MAX_PATH_LEN];
                         snprintf(db_path, sizeof(db_path),
                                  "/system_data/%s/%s/db/user/savedata.db",
                                  sd, g_saves[idx].user_id);
                         sqlite3 *sdb = NULL;
                         const char *db_title = NULL, *db_sub = NULL, *db_gtid = NULL;
                         int64_t db_blocks = 96, db_aid = 0, db_sysblk = 0;
                         uint32_t db_uid = 0;
                         if (sqlite3_open_v2(db_path, &sdb, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK) {
                             sqlite3_stmt *st3 = NULL;
                             const char *q = "SELECT main_title, sub_title, blocks, account_id, "
                                             "system_blocks, user_id, game_title_id "
                                             "FROM savedata WHERE title_id=? AND dir_name=? LIMIT 1";
                             if (sqlite3_prepare_v2(sdb, q, -1, &st3, NULL) == SQLITE_OK) {
                                 sqlite3_bind_text(st3, 1, tid, -1, SQLITE_STATIC);
                                 sqlite3_bind_text(st3, 2, sname, -1, SQLITE_STATIC);
                                 if (sqlite3_step(st3) == SQLITE_ROW) {
                                     db_title  = (const char *)sqlite3_column_text(st3, 0);
                                     db_sub    = (const char *)sqlite3_column_text(st3, 1);
                                     db_blocks = sqlite3_column_int64(st3, 2);
                                     db_aid    = sqlite3_column_int64(st3, 3);
                                     db_sysblk = sqlite3_column_int64(st3, 4);
                                     db_uid    = (uint32_t)sqlite3_column_int64(st3, 5);
                                     db_gtid   = (const char *)sqlite3_column_text(st3, 6);
                                 }
                             }
                             /* Generate replacement SFO in temp file, read back */
                             char tmp_sfo[128];
                             snprintf(tmp_sfo, sizeof(tmp_sfo), "/data/save_files/_tmp_sfo_%d.bin", n);
                             generate_sfo(tmp_sfo, tid, sname,
                                          db_title ? db_title : tid,
                                          db_sub ? db_sub : "",
                                          (uint64_t)db_aid, (uint64_t)db_blocks,
                                          (uint64_t)db_sysblk, db_uid,
                                          db_gtid, g_saves[idx].is_ps4,
                                          g_params_hmac_valid ? g_params_hmac : NULL);
                             if (st3) sqlite3_finalize(st3);
                             sqlite3_close(sdb);
                             int sfd = open(tmp_sfo, O_RDONLY);
                             if (sfd >= 0) {
                                 struct stat st2;
                                 if (fstat(sfd, &st2) == 0 && st2.st_size > 0) {
                                     free(de->data);
                                     de->size = st2.st_size;
                                     de->data = malloc(de->size);
                                     if (de->data) read(sfd, de->data, de->size);
                                 }
                                 close(sfd);
                                 unlink(tmp_sfo);
                             }
                         }
                     }
                 }

                 de->crc = de->data ? calc_crc(de->data, de->size) : 0;
                 total++;
             }
             free(tmp_entries);
             unmount_save();
         }
         free(indices);

         /* Stream the combined zip */
         char zip_name[128];
         snprintf(zip_name, sizeof(zip_name), "%s_saves_dec.zip", tid);
         char hdr[512];
         int hlen = snprintf(hdr, sizeof(hdr),
             "HTTP/1.1 200 OK\r\n"
             "Content-Type: application/zip\r\n"
             "Content-Disposition: attachment; filename=\"%s\"\r\n"
             "Access-Control-Allow-Origin: *\r\n"
             "Connection: close\r\n\r\n", zip_name);
         send(sock, hdr, hlen, 0);

         uint32_t offset = 0;
         for (int i = 0; i < total; i++) {
             dec_entry_t *e = &all_entries[i];
             e->offset = offset;
             uint16_t nlen = strlen(e->name);

             uint8_t lh[30]; memset(lh, 0, 30);
             lh[0]=0x50; lh[1]=0x4b; lh[2]=0x03; lh[3]=0x04;
             lh[4]=20;
             memcpy(lh+14, &e->crc, 4);
             memcpy(lh+18, &e->size, 4);
             memcpy(lh+22, &e->size, 4);
             memcpy(lh+26, &nlen, 2);
             send(sock, lh, 30, 0);
             send(sock, e->name, nlen, 0);
             if (e->data) { send(sock, e->data, e->size, 0); free(e->data); }
             offset += 30 + nlen + e->size;
         }

         uint32_t cd_offset = offset;
         for (int i = 0; i < total; i++) {
             dec_entry_t *e = &all_entries[i];
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
         uint16_t cnt16 = (uint16_t)total;
         memcpy(ecd+8, &cnt16, 2);
         memcpy(ecd+10, &cnt16, 2);
         memcpy(ecd+12, &cd_size, 4);
         memcpy(ecd+16, &cd_offset, 4);
         send(sock, ecd, 22, 0);

         free(all_entries);
         return;
     }

     /* GET /api/delete_save?idx=N -> delete a single save from disk and DB */
     if (strcmp(method, "GET") == 0 && strncmp(url, "/api/delete_save", 16) == 0) {
         scan_saves();
         int idx = -1;
         char *p = strstr(url, "idx=");
         if (p) idx = atoi(p + 4);
         if (idx < 0 || idx >= g_save_count) {
             http_json(sock, "{\"error\":\"Invalid index\"}"); return;
         }

         pid_t rpid = getpid();
         kernel_set_ucred_uid(rpid, 0);
         kernel_set_ucred_authid(rpid, 0x4800000000000010ULL);

         save_entry_t *s = &g_saves[idx];

         /* Delete the save file */
         unlink(s->path);
         printf("[GarlicMgr] delete_save: %s\n", s->path);

         /* Delete .bin companion for PS4 */
         if (s->is_ps4 && strncmp(s->save_name, "sdimg_", 6) == 0) {
             const char *sname = s->save_name + 6;
             char dir[MAX_PATH_LEN];
             strncpy(dir, s->path, sizeof(dir) - 1);
             dir[sizeof(dir) - 1] = 0;
             char *sl = strrchr(dir, '/');
             if (sl) *(sl + 1) = 0;
             char bin_path[MAX_PATH_LEN];
             snprintf(bin_path, sizeof(bin_path), "%s%s.bin", dir, sname);
             unlink(bin_path);
         }

         /* Delete from DB if not a USB save */
         if (!s->is_usb && strncmp(s->save_name, "sdimg_", 6) == 0) {
             const char *dir_name = s->save_name + 6;
             const char *sd = s->is_ps4 ? "savedata" : "savedata_prospero";
             char db_path[MAX_PATH_LEN];
             snprintf(db_path, sizeof(db_path),
                      "/system_data/%s/%s/db/user/savedata.db", sd, s->user_id);
             sqlite3 *db = NULL;
             if (sqlite3_open(db_path, &db) == SQLITE_OK) {
                 char sql[512];
                 snprintf(sql, sizeof(sql),
                          "DELETE FROM savedata WHERE title_id='%s' AND dir_name='%s'",
                          s->title_id, dir_name);
                 char *err_msg = NULL;
                 int ret = sqlite3_exec(db, sql, NULL, 0, &err_msg);
                 if (ret != SQLITE_OK) {
                     printf("[GarlicMgr] delete_save DB error: %s\n", err_msg);
                     sqlite3_free(err_msg);
                 } else {
                     printf("[GarlicMgr] delete_save: removed %s/%s from %s DB\n",
                            s->title_id, dir_name, sd);
                 }
                 sqlite3_close(db);
             }
         }

         /* Try to remove title dir if now empty */
         {
             char title_dir[MAX_PATH_LEN];
             strncpy(title_dir, s->path, sizeof(title_dir) - 1);
             title_dir[sizeof(title_dir) - 1] = 0;
             char *sl = strrchr(title_dir, '/');
             if (sl) *sl = 0;
             rmdir(title_dir); /* only succeeds if empty */
         }

         http_json(sock, "{\"ok\":true}");
         return;
     }

     /* GET /api/delete_title?id=<title_id> -> delete all saves for a title from disk and DB */
     if (strcmp(method, "GET") == 0 && strncmp(url, "/api/delete_title", 17) == 0) {
         char tid[64] = {0};
         char *tp = strstr(url, "id=");
         if (tp) {
             strncpy(tid, tp + 3, sizeof(tid) - 1);
             char *amp = strchr(tid, '&');
             if (amp) *amp = 0;
             char *r = tid, *w = tid;
             while (*r) {
                 if (*r == '%' && r[1] && r[2]) {
                     char hex[3] = {r[1], r[2], 0};
                     *w++ = (char)strtol(hex, NULL, 16);
                     r += 3;
                 } else { *w++ = *r++; }
             }
             *w = 0;
         }
         if (!tid[0]) { http_json(sock, "{\"error\":\"Missing id\"}"); return; }

         scan_saves();
         pid_t rpid = getpid();
         kernel_set_ucred_uid(rpid, 0);
         kernel_set_ucred_authid(rpid, 0x4800000000000010ULL);

         int deleted = 0;
         /* Track unique (uid, is_ps4) pairs for DB cleanup */
         typedef struct { char uid[16]; int is_ps4; } uid_entry_t;
         uid_entry_t uids[32];
         int nuid = 0;

         for (int i = 0; i < g_save_count; i++) {
             if (strcmp(g_saves[i].title_id, tid) != 0) continue;
             if (g_saves[i].is_usb) continue; /* don't delete USB saves */

             /* Delete the save file */
             unlink(g_saves[i].path);
             printf("[GarlicMgr] delete: %s\n", g_saves[i].path);

             /* Delete .bin companion for PS4 */
             if (g_saves[i].is_ps4 && strncmp(g_saves[i].save_name, "sdimg_", 6) == 0) {
                 const char *sname = g_saves[i].save_name + 6;
                 char dir[MAX_PATH_LEN];
                 strncpy(dir, g_saves[i].path, sizeof(dir) - 1);
                 dir[sizeof(dir) - 1] = 0;
                 char *sl = strrchr(dir, '/');
                 if (sl) *(sl + 1) = 0;
                 char bin_path[MAX_PATH_LEN];
                 snprintf(bin_path, sizeof(bin_path), "%s%s.bin", dir, sname);
                 unlink(bin_path);
             }

             /* Track uid for DB cleanup */
             int found = 0;
             for (int u = 0; u < nuid; u++) {
                 if (strcmp(uids[u].uid, g_saves[i].user_id) == 0 && uids[u].is_ps4 == g_saves[i].is_ps4) {
                     found = 1; break;
                 }
             }
             if (!found && nuid < 32) {
                 strncpy(uids[nuid].uid, g_saves[i].user_id, sizeof(uids[nuid].uid) - 1);
                 uids[nuid].is_ps4 = g_saves[i].is_ps4;
                 nuid++;
             }
             deleted++;
         }

         /* Remove title directories if empty */
         for (int u = 0; u < nuid; u++) {
             const char *sd = uids[u].is_ps4 ? "savedata" : "savedata_prospero";
             char title_dir[MAX_PATH_LEN];
             snprintf(title_dir, sizeof(title_dir), "/user/home/%s/%s/%s", uids[u].uid, sd, tid);
             rmdir(title_dir); /* only succeeds if empty */

             /* Delete from savedata.db */
             char db_path[MAX_PATH_LEN];
             snprintf(db_path, sizeof(db_path),
                      "/system_data/%s/%s/db/user/savedata.db", sd, uids[u].uid);
             sqlite3 *db = NULL;
             if (sqlite3_open(db_path, &db) == SQLITE_OK) {
                 char sql[256];
                 snprintf(sql, sizeof(sql),
                          "DELETE FROM savedata WHERE title_id='%s'", tid);
                 char *err_msg = NULL;
                 int ret = sqlite3_exec(db, sql, NULL, 0, &err_msg);
                 if (ret != SQLITE_OK) {
                     printf("[GarlicMgr] delete DB error: %s\n", err_msg);
                     sqlite3_free(err_msg);
                 } else {
                     printf("[GarlicMgr] delete: removed %s from %s DB\n", tid, sd);
                 }
                 sqlite3_close(db);
             }
         }

         char json[128];
         snprintf(json, sizeof(json), "{\"ok\":true,\"deleted\":%d}", deleted);
         http_json(sock, json);
         return;
     }

     /* GET /api/dump_title_usb?id=<title_id>&usb=N -> copy all encrypted saves for a title to USB */
     if (strcmp(method, "GET") == 0 && strncmp(url, "/api/dump_title_usb", 19) == 0 && url[19] != '_') {
         char tid[64] = {0};
         int usb_num = 0;
         char *tp = strstr(url, "id=");
         if (tp) {
             strncpy(tid, tp + 3, sizeof(tid) - 1);
             char *amp = strchr(tid, '&');
             if (amp) *amp = 0;
             char *r = tid, *w = tid;
             while (*r) {
                 if (*r == '%' && r[1] && r[2]) {
                     char hex[3] = {r[1], r[2], 0};
                     *w++ = (char)strtol(hex, NULL, 16);
                     r += 3;
                 } else { *w++ = *r++; }
             }
             *w = 0;
         }
         tp = strstr(url, "usb=");
         if (tp) usb_num = atoi(tp + 4);
         if (usb_num < 0 || usb_num > 7) usb_num = 0;
         if (!tid[0]) { http_json(sock, "{\"error\":\"Missing id\"}"); return; }

         scan_saves();
         kernel_set_ucred_authid(getpid(), 0x4800000000000010ULL);

         char usb_base[64];
         snprintf(usb_base, sizeof(usb_base), "/mnt/usb%d", usb_num);
         char tmp[MAX_PATH_LEN];
         snprintf(tmp, sizeof(tmp), "%s/PS5", usb_base); mkdir(tmp, 0777);
         snprintf(tmp, sizeof(tmp), "%s/PS5/SAVEDATA", usb_base); mkdir(tmp, 0777);
         snprintf(tmp, sizeof(tmp), "%s/PS5/SAVEDATA/GARLIC", usb_base); mkdir(tmp, 0777);
         char title_dir[MAX_PATH_LEN];
         snprintf(title_dir, sizeof(title_dir), "%s/PS5/SAVEDATA/GARLIC/%s", usb_base, tid);
         mkdir(title_dir, 0777);

         int copied = 0, failed = 0;
         for (int i = 0; i < g_save_count; i++) {
             if (strcmp(g_saves[i].title_id, tid) != 0) continue;
             char dst[MAX_PATH_LEN];
             snprintf(dst, sizeof(dst), "%s/%s", title_dir, g_saves[i].save_name);
             if (copy_file(g_saves[i].path, dst) == 0) {
                 copied++;
                 /* For PS4 saves, also copy .bin key */
                 if (g_saves[i].is_ps4 && strncmp(g_saves[i].save_name, "sdimg_", 6) == 0) {
                     const char *savename = g_saves[i].save_name + 6;
                     char dir[MAX_PATH_LEN];
                     strncpy(dir, g_saves[i].path, sizeof(dir) - 1);
                     dir[sizeof(dir) - 1] = 0;
                     char *sl = strrchr(dir, '/');
                     if (sl) *(sl + 1) = 0;
                     char bin_src[MAX_PATH_LEN], bin_dst[MAX_PATH_LEN];
                     snprintf(bin_src, sizeof(bin_src), "%s%s.bin", dir, savename);
                     snprintf(bin_dst, sizeof(bin_dst), "%s/%s.bin", title_dir, savename);
                     struct stat bst;
                     if (stat(bin_src, &bst) == 0) copy_file(bin_src, bin_dst);
                 }
             } else {
                 failed++;
             }
         }

         char json[256];
         snprintf(json, sizeof(json), "{\"ok\":true,\"copied\":%d,\"failed\":%d,\"path\":\"%s\"}", copied, failed, title_dir);
         http_json(sock, json);
         return;
     }

     /* GET /api/dump_title_dec_usb?id=<title_id>&usb=N -> mount each save, copy decrypted to USB */
     if (strcmp(method, "GET") == 0 && strncmp(url, "/api/dump_title_dec_usb", 23) == 0) {
         char tid[64] = {0};
         int usb_num = 0;
         char *tp = strstr(url, "id=");
         if (tp) {
             strncpy(tid, tp + 3, sizeof(tid) - 1);
             char *amp = strchr(tid, '&');
             if (amp) *amp = 0;
             char *r = tid, *w = tid;
             while (*r) {
                 if (*r == '%' && r[1] && r[2]) {
                     char hex[3] = {r[1], r[2], 0};
                     *w++ = (char)strtol(hex, NULL, 16);
                     r += 3;
                 } else { *w++ = *r++; }
             }
             *w = 0;
         }
         tp = strstr(url, "usb=");
         if (tp) usb_num = atoi(tp + 4);
         if (usb_num < 0 || usb_num > 7) usb_num = 0;
         if (!tid[0]) { http_json(sock, "{\"error\":\"Missing id\"}"); return; }

         scan_saves();
         kernel_set_ucred_authid(getpid(), 0x4800000000000010ULL);

         char usb_base[64];
         snprintf(usb_base, sizeof(usb_base), "/mnt/usb%d", usb_num);
         char tmp[MAX_PATH_LEN];
         snprintf(tmp, sizeof(tmp), "%s/PS5", usb_base); mkdir(tmp, 0777);
         snprintf(tmp, sizeof(tmp), "%s/PS5/SAVEDATA", usb_base); mkdir(tmp, 0777);
         snprintf(tmp, sizeof(tmp), "%s/PS5/SAVEDATA/GARLIC", usb_base); mkdir(tmp, 0777);
         char title_dir[MAX_PATH_LEN];
         snprintf(title_dir, sizeof(title_dir), "%s/PS5/SAVEDATA/GARLIC/%s", usb_base, tid);
         mkdir(title_dir, 0777);

         int copied = 0, failed = 0;
         for (int i = 0; i < g_save_count; i++) {
             if (strcmp(g_saves[i].title_id, tid) != 0) continue;

             if (g_mounted) unmount_save();
             int ret = mount_save(i);
             if (ret < 0) { failed++; continue; }

             char save_dir[MAX_PATH_LEN];
             snprintf(save_dir, sizeof(save_dir), "%s/%s", title_dir, g_saves[i].save_name);
             int cpret = copy_dir_recursive(g_mount_point, save_dir);
             if (cpret == 0) cpret = chives_write_export(g_local_copy[0] ? g_local_copy : g_mounted_path,
                                                        g_mount_point,save_dir);
             unmount_save();

             if (cpret == 0) copied++;
             else failed++;
         }

         char json[256];
         snprintf(json, sizeof(json), "{\"ok\":true,\"copied\":%d,\"failed\":%d,\"path\":\"%s\"}", copied, failed, title_dir);
         http_json(sock, json);
         return;
     }

     /* 404 */
     http_send(sock, "404 Not Found", "application/json", "{\"error\":\"Not found\"}", 20);
 }


 /* CMP bridge to Garlic's existing background-job state. */
 int cmp_cloud_running(void) {
     pthread_mutex_lock(&g_cloud_mtx);
     int running=g_cloud_state.running;
     pthread_mutex_unlock(&g_cloud_mtx);
     return running;
 }

 /* CMP worker draining and cleanup: CMP/lifecycle.c. */

  /* ── HTTP listener recovery ──────────────────────────────────────── */
 int g_srvfd = -1;

 uint64_t mono_ms(void) {
     struct timespec ts;
     if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
     return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
 }

 static int server_open_listener(void) {
     int fd = socket(AF_INET, SOCK_STREAM, 0);
     if (fd < 0) return -1;
     setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));

     struct sockaddr_in addr = {0};
     addr.sin_family = AF_INET;
     addr.sin_addr.s_addr = htonl(INADDR_ANY);
     addr.sin_port = htons(PORT);

     if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0 ||
         listen(fd, 16) < 0) {
         int error=errno;close(fd);errno=error;
         return -1;
     }
     return fd;
 }

 static void server_recover(const char *reason) {
     if (g_srvfd >= 0) {
         close(g_srvfd);
         g_srvfd = -1;
     }
     int fd = server_open_listener();
     if (fd < 0) {
         logprintf("[GarlicMgr] listener recovery failed (%s): %s\n",
                   reason, strerror(errno));
         return;
     }
     g_srvfd = fd;
     logprintf("[GarlicMgr] listener recovered (%s) on port %d\n", reason, PORT);
 }

 /* CMP polling-safe lifecycle handover: CMP/lifecycle.c. */

/* ── Main ───────────────────────────────────────────────────────── */
 int main(void) {
     /* Keep job IDs distinct across normal payload restarts as well. */
     struct timespec transfer_seed;
     if(clock_gettime(CLOCK_MONOTONIC,&transfer_seed)==0)
         g_transfer.serial=((uint64_t)transfer_seed.tv_sec<<32)^(uint64_t)transfer_seed.tv_nsec;
     else g_transfer.serial=((uint64_t)time(NULL)<<20)^(uint64_t)getpid();
     /* Zero the umask so open(..., 0777) really lands at 0777. Files inside
      * a mounted PFS need world-write to pass the game's save-verify at load;
      * default umask 022 quietly strips those bits — see garlic-worker
      * v1.1.6 for the equivalent bug in the worker. */
     umask(0);

     sceUserServiceInitialize(0);
     kernel_set_ucred_authid(getpid(), 0x4800000000000010ULL);
     signal(SIGPIPE, SIG_IGN);
     signal(SIGHUP, SIG_IGN);
     signal(SIGTERM, SIG_IGN);
     signal(SIGALRM, SIG_IGN);
     signal(SIGCONT, handle_sigcont);
     char instance_error[256];
     if(garlic_lifecycle_start("/data/garlic-savemgr.instance.lock",PORT,INSTANCE_HANDOVER_WAIT_MS,instance_error,sizeof(instance_error))<0){
         notify("Garlic SaveMgr: %s",instance_error);return 1;
     }
     g_srvfd=server_open_listener();
     if(g_srvfd<0){
         notify("Garlic SaveMgr: port 8082 occupied. Stop the older/other server with Kill GarlicMgr first.");
         garlic_lifecycle_release_instance();return 1;
     }
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
     if (stat("/data/mount_owner", &st0) == 0) {
         UmountOpt u0; memset(&u0, 0, sizeof(u0));
         sceFsInitUmountSaveDataOpt(&u0);
         sceFsUmountSaveData(&u0, "/data/mount_owner", 0, 0);
     }

     /* Get OpenPsId for PARAMS HMAC */
     SceKernelOpenPsId g_open_psid;
     memset(&g_open_psid, 0, sizeof(g_open_psid));
     if (sceKernelGetOpenPsId(&g_open_psid) == 0) {
         printf("[GarlicMgr] OpenPsId: ");
         for (int i = 0; i < 16; i++) printf("%02x", g_open_psid.id[i]);
         printf("\n");
     }

     printf("=== Garlic SaveMgr for PS5 by earthonion ===\n");
     if (net_init_once() == 0)
         printf("[GarlicMgr] sceNetInit OK (outbound FTP enabled)\n");
     else
         printf("[GarlicMgr] sceNetInit failed; cloud FTP uploads may not work\n");
     notify("Garlic SaveMgr: port %d", PORT);
     start_auto_watcher();

     printf("Listening on port %d\n", PORT);

     uint64_t last_mono = mono_ms();
     while (1) {
         if(garlic_lifecycle_try_exit())return 0;
         if(garlic_lifecycle_stopping())g_resume_signal=0;
         if (g_resume_signal) {
             g_resume_signal = 0;
             logprintf("[GarlicMgr] resume signal (SIGCONT)\n");
             if (g_srvfd >= 0) { close(g_srvfd); g_srvfd = -1; }
             usleep(1000000);
             server_recover("SIGCONT");
             g_resume_pending = 1;
             last_mono = mono_ms();
             if (g_srvfd >= 0)
                 notify("Garlic SaveMgr: resumed\nPort: %d", PORT);
             else
                 notify("Garlic SaveMgr: resume recovery failed");
             continue;
         }

         if (g_srvfd < 0) {
             server_recover("listener unavailable");
             sleep(1);
             continue;
         }

         fd_set rfds;
         FD_ZERO(&rfds);
         FD_SET(g_srvfd, &rfds);
         struct timeval tv = { .tv_sec = 0, .tv_usec = 250000 };
         int sel = select(g_srvfd + 1, &rfds, NULL, NULL, &tv);
         int select_error = sel < 0 ? errno : 0;
         uint64_t now = mono_ms();
         /* A worker can finish during select while the next identity poll is
          * already queued. Give cleanup priority before counting that poll. */
         if(garlic_lifecycle_try_exit())return 0;

         /* A large monotonic jump means the process was suspended (rest mode).
          * Recover the listener and tell the auto watcher to rescan. */
         if (!garlic_lifecycle_stopping() && last_mono && now > last_mono + 30000) {
             logprintf("[GarlicMgr] resume detected (%llu ms gap)\n",
                       (unsigned long long)(now - last_mono));
             if (g_srvfd >= 0) { close(g_srvfd); g_srvfd = -1; }
             usleep(1000000);
             server_recover("resume");
             g_resume_pending = 1;
             last_mono = now;
             if (g_srvfd >= 0)
                 notify("Garlic SaveMgr: resumed\nPort: %d", PORT);
             continue;
         }
         last_mono = now;

         if (sel < 0) {
             if (select_error == EINTR) continue;
             logprintf("[GarlicMgr] select failed: %s; recreating listener\n", strerror(select_error));
             server_recover("select");
             sleep(1);
             continue;
         }
         if (sel == 0) continue;

         struct sockaddr_in client;
         socklen_t clen = sizeof(client);
         int conn = accept(g_srvfd, (struct sockaddr*)&client, &clen);
         if (conn < 0) {
             if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
             logprintf("[GarlicMgr] accept failed: %s; recreating listener\n", strerror(errno));
             server_recover("accept");
             sleep(1);
             continue;
         }

         int *fd_ptr = malloc(sizeof(int));
         if (!fd_ptr) { close(conn); continue; }
         *fd_ptr = conn;

         pthread_t tid;
         pthread_attr_t attr;
         pthread_attr_init(&attr);
         pthread_attr_setstacksize(&attr, 2 * 1024 * 1024);
         garlic_lifecycle_reserve_worker();
         if (pthread_create(&tid, &attr, garlic_lifecycle_worker, fd_ptr) != 0) {
             /* Retain transfer registration/cancellation guards in fallback. */
             garlic_lifecycle_worker(fd_ptr);
         } else {
             pthread_detach(tid);
         }
         pthread_attr_destroy(&attr);
     }

     return 0;
 }
