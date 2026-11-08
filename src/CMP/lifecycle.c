/* CMP cooperative instance lifetime and shutdown addition.
 * Extracted from Rebuild4; the private bridge retains Garlic's native services. */
#include "lifecycle.h"
#include "internal/lifecycle_bridge.h"
#include "instance_control.h"
#include "internal/instance_protocol.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifndef GARLIC_VERSION
#define GARLIC_VERSION "unversioned"
#endif

typedef enum {
    CMP_LIFECYCLE_RUNNING = 0,
    CMP_LIFECYCLE_DRAINING = 1,
    CMP_LIFECYCLE_FAILED = 2
} cmp_lifecycle_phase_t;

/* Shutdown gates are independent of the save mutex so Kill can drain uploads. */
static atomic_int g_shutdown_phase = CMP_LIFECYCLE_RUNNING;
static atomic_uint g_request_workers = 0;
static atomic_int g_watcher_active = 0;
static pthread_mutex_t g_lifecycle_mtx = PTHREAD_MUTEX_INITIALIZER;
static char g_shutdown_error[256];
static char g_instance_cookie[CMP_INSTANCE_COOKIE_TEXT_BYTES];
static int g_instance_lock_fd = -1;
int garlic_lifecycle_start(const char *lock_path, unsigned port, unsigned wait_ms, char *error,
                           size_t capacity) {
    g_instance_lock_fd = garlic_instance_acquire(lock_path, port, wait_ms, error, capacity);
    if (g_instance_lock_fd < 0)
        return -1;
    uint8_t cookie_bytes[CMP_INSTANCE_COOKIE_BYTES];
    arc4random_buf(cookie_bytes, sizeof(cookie_bytes));
    for (int i = 0; i < CMP_INSTANCE_COOKIE_BYTES; i++)
        snprintf(g_instance_cookie + i * 2, 3, "%02x", cookie_bytes[i]);
    memset(cookie_bytes, 0, sizeof(cookie_bytes));
    return 0;
}
void garlic_lifecycle_release_instance(void) {
    if (g_instance_lock_fd >= 0) {
        garlic_instance_release(g_instance_lock_fd);
        g_instance_lock_fd = -1;
    }
}
void garlic_lifecycle_reserve_worker(void) {
    atomic_fetch_add(&g_request_workers, 1);
}
void garlic_lifecycle_set_watcher_active(int active) {
    atomic_store(&g_watcher_active, active);
}
int garlic_lifecycle_stopping(void) {
    return atomic_load(&g_shutdown_phase) != CMP_LIFECYCLE_RUNNING;
}
int garlic_lifecycle_pause(unsigned seconds) {
    for (uint64_t tick = 0; tick < (uint64_t)seconds * 10; tick++) {
        if (garlic_lifecycle_stopping())
            return -1;
        struct timespec delay = {0, 100000000};
        nanosleep(&delay, NULL);
    }
    return garlic_lifecycle_stopping() ? -1 : 0;
}

/* Identity is loopback-only. Replacement reuses the existing Kill endpoint. */
static int garlic_lifecycle_loopback(int sock) {
    struct sockaddr_in peer;
    socklen_t n = sizeof(peer);
    memset(&peer, 0, sizeof(peer));
    return !getpeername(sock, (struct sockaddr *)&peer, &n) && peer.sin_family == AF_INET &&
           (ntohl(peer.sin_addr.s_addr) >> 24) == 127;
}
static int garlic_lifecycle_cookie_header(const char *req,
                                          char out[CMP_INSTANCE_COOKIE_TEXT_BYTES]) {
    const char *line = req;
    int found = 0;
    out[0] = 0;
    while (line && *line) {
        const char *end = strstr(line, "\r\n");
        if (!end)
            return -1;
        if (end == line)
            break;
        if ((size_t)(end - line) >= CMP_INSTANCE_COOKIE_HEADER_BYTES &&
            !strncasecmp(line, CMP_INSTANCE_COOKIE_HEADER, CMP_INSTANCE_COOKIE_HEADER_BYTES)) {
            if (found++)
                return -1;
            const char *v = line + CMP_INSTANCE_COOKIE_HEADER_BYTES;
            while (v < end && (*v == ' ' || *v == '\t'))
                v++;
            const char *last = end;
            while (last > v && (last[-1] == ' ' || last[-1] == '\t'))
                last--;
            if (last - v != CMP_INSTANCE_COOKIE_HEX_BYTES)
                return -1;
            for (int i = 0; i < CMP_INSTANCE_COOKIE_HEX_BYTES; i++)
                if (!((v[i] >= '0' && v[i] <= '9') || (v[i] >= 'a' && v[i] <= 'f')))
                    return -1;
            memcpy(out, v, CMP_INSTANCE_COOKIE_HEX_BYTES);
            out[CMP_INSTANCE_COOKIE_HEX_BYTES] = 0;
        }
        line = end + 2;
    }
    return found;
}
static void garlic_lifecycle_request(void) {
    pthread_mutex_lock(&g_lifecycle_mtx);
    g_shutdown_error[0] = 0;
    atomic_store(&g_shutdown_phase, CMP_LIFECYCLE_DRAINING);
    pthread_mutex_unlock(&g_lifecycle_mtx);
}
static void garlic_lifecycle_state(int sock, int identity) {
    char error[256], escaped[512], json[1024];
    int phase;
    pthread_mutex_lock(&g_lifecycle_mtx);
    phase = atomic_load(&g_shutdown_phase);
    snprintf(error, sizeof(error), "%s", g_shutdown_error);
    pthread_mutex_unlock(&g_lifecycle_mtx);
    chives_escape(error, escaped, sizeof(escaped));
    const char *state = phase == CMP_LIFECYCLE_FAILED    ? "failed"
                        : phase != CMP_LIFECYCLE_RUNNING ? "draining"
                                                         : "running";
    if (identity)
        snprintf(
            json, sizeof(json),
            "{\"app\":\"" CMP_INSTANCE_APP_NAME
            "\",\"takeover_protocol\":" CMP_INSTANCE_PROTOCOL_TEXT
            ",\"version\":\"%s\",\"pid\":%d,\"cookie\":\"%s\",\"phase\":\"%s\",\"error\":\"%s\"}",
            GARLIC_VERSION, getpid(), g_instance_cookie, state, escaped);
    else
        snprintf(json, sizeof(json), "{\"state\":\"%s\",\"pid\":%d,\"error\":\"%s\"}", state,
                 getpid(), escaped);
    http_json(sock, json);
}
int garlic_lifecycle_http(int sock, const char *method, const char *url, const char *req,
                          size_t size) {
    if (!strcmp(method, "GET") && !strcmp(url, "/api/instance")) {
        if (garlic_lifecycle_loopback(sock))
            garlic_lifecycle_state(sock, 1);
        else
            http_json(sock, "{\"error\":\"Instance identity is local-only\"}");
        close(sock);
        return 1;
    }
    if (!strcmp(method, "GET") && !strcmp(url, "/api/shutdown/status")) {
        garlic_lifecycle_state(sock, 0);
        close(sock);
        return 1;
    }
    if (!strcmp(method, "GET") && !strcmp(url, "/api/shutdown")) {
        uint64_t job = 0;
        char cookie[CMP_INSTANCE_COOKIE_TEXT_BYTES];
        int header = garlic_lifecycle_cookie_header(req, cookie);
        if (garlic_transfer_header(req, size, &job) != 0 || header < 0 ||
            (header && (!garlic_lifecycle_loopback(sock) || strcmp(cookie, g_instance_cookie)))) {
            http_json(sock, "{\"error\":\"Invalid shutdown request\"}");
            close(sock);
            return 1;
        }
        /* Queue only after acknowledgement is sent: do not tear down this reply. */
        http_json(sock, "{\"ok\":true,\"shutdown\":\"pending\"}");
        close(sock);
        garlic_lifecycle_request();
        return 1;
    }
    /* Keep the static page reachable so a failed cleanup can be retried. */
    if (!strcmp(method, "GET") && (!strcmp(url, "/") || !strcmp(url, "/index.html")))
        return 0;
    if (garlic_lifecycle_stopping()) {
        http_json(
            sock,
            "{\"error\":\"Garlic SaveMgr is shutting down; wait for cleanup or retry Kill GarlicMgr\"}");
        close(sock);
        return 1;
    }
    return 0;
}

/* Reservations are made before pthread_create, including synchronous fallback. */
void *garlic_lifecycle_worker(void *arg) {
    void *result = request_thread(arg);
    atomic_fetch_sub(&g_request_workers, 1);
    return result;
}
static void garlic_lifecycle_cancel_active(void) {
    uint64_t id = 0;
    pthread_mutex_lock(&g_transfer.mutex);
    if (g_transfer.active)
        id = g_transfer.id;
    pthread_mutex_unlock(&g_transfer.mutex);
    if (id)
        garlic_transfer_cancel(&g_transfer, id);
}
static void garlic_lifecycle_fail(const char *error) {
    pthread_mutex_lock(&g_lifecycle_mtx);
    snprintf(g_shutdown_error, sizeof(g_shutdown_error), "%s", error);
    atomic_store(&g_shutdown_phase, CMP_LIFECYCLE_FAILED);
    pthread_mutex_unlock(&g_lifecycle_mtx);
    logprintf("[GarlicMgr] Shutdown stopped: %s\n", error);
    notify("Garlic SaveMgr: shutdown cleanup failed; old instance kept running");
}
static int garlic_lifecycle_finish(void) {
    /* Watcher may start a cloud job while exiting; check it before cloud state. */
    if (atomic_load(&g_request_workers) || atomic_load(&g_watcher_active))
        return 0;
    int cloud = cmp_cloud_running();
    if (cloud)
        return 0;
    if (pthread_mutex_trylock(&g_mtx))
        return 0;
    char error[256] = {0};
    uint64_t id = 0;
    pthread_mutex_lock(&g_transfer.mutex);
    if (g_transfer.active)
        id = g_transfer.id;
    pthread_mutex_unlock(&g_transfer.mutex);
    if (id) {
        garlic_transfer_cancel(&g_transfer, id);
        if (cleanup_web_transfer_job(&g_transfer, id, "/data/save_files", error, sizeof(error)) <
            0) {
            pthread_mutex_unlock(&g_mtx);
            garlic_lifecycle_fail(error[0] ? error : "Temporary save cleanup failed");
            return 0;
        }
        garlic_transfer_end(&g_transfer, id, 1);
    }
    if (g_mounted) {
        logprintf("[GarlicMgr] Shutdown unmounting the tracked save\n");
        if (unmount_save() < 0) {
            pthread_mutex_unlock(&g_mtx);
            garlic_lifecycle_fail("Native save unmount failed");
            return 0;
        }
    }
    if (g_owner_mount_active) {
        logprintf("[GarlicMgr] Shutdown unmounting the owner-template save\n");
        UmountOpt owner;
        memset(&owner, 0, sizeof(owner));
        sceFsInitUmountSaveDataOpt(&owner);
        if (sceFsUmountSaveData(&owner, "/data/mount_owner", 0, 0) < 0) {
            pthread_mutex_unlock(&g_mtx);
            garlic_lifecycle_fail("Owner-template save unmount failed");
            return 0;
        }
        g_owner_mount_active = 0;
        unlink("/data/save_files/sdimg__owner_template");
        unlink("/data/save_files/_owner_template.bin");
    }
    logprintf("[GarlicMgr] Shutdown flushing filesystem changes\n");
    sync();
    pthread_mutex_unlock(&g_mtx);
    logprintf("[GarlicMgr] Shutdown cleanup complete; releasing instance ownership\n");
    return 1;
}

/* Polling control requests must not starve the zero-worker handover point.
 * Call both before select and after it wakes, before accepting another client. */
int garlic_lifecycle_try_exit(void) {
    static uint64_t last_wait_log;
    if (atomic_load(&g_shutdown_phase) != CMP_LIFECYCLE_DRAINING) {
        last_wait_log = 0;
        return 0;
    }
    if (g_instance_lock_fd < 0)
        return 1; /* already released; never close twice */
    garlic_lifecycle_cancel_active();
    if (!garlic_lifecycle_finish()) {
        uint64_t now = mono_ms();
        if (atomic_load(&g_shutdown_phase) == CMP_LIFECYCLE_DRAINING &&
            (!last_wait_log || (now && now - last_wait_log >= 5000))) {
            int cloud = cmp_cloud_running();
            logprintf("[GarlicMgr] Shutdown waiting: requests=%u watcher=%d cloud=%d\n",
                      atomic_load(&g_request_workers), atomic_load(&g_watcher_active), cloud);
            last_wait_log = now;
        }
        return 0;
    }
    if (g_srvfd >= 0) {
        close(g_srvfd);
        g_srvfd = -1;
    }
    garlic_lifecycle_release_instance();
    return 1;
}
