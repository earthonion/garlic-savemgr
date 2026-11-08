/* CMP add-in implementation; declarations are in instance_control.h.
 * Extracted without algorithm changes from CMP Rebuild4. */
#include "instance_control.h"
#include "internal/instance_protocol.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>

#define GARLIC_INSTANCE_BODY_MAX 2048
#define GARLIC_INSTANCE_DISCOVERY_POLL_MS 100
#define GARLIC_INSTANCE_DRAIN_POLL_MS 600

typedef struct {
    char app[32], cookie[CMP_INSTANCE_COOKIE_TEXT_BYTES], phase[16];
    unsigned protocol;
    int ok, pending;
    unsigned seen;
} garlic_instance_identity_t;

static uint64_t garlic_instance_now_ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t))
        return 0;
    return (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
}

static void garlic_instance_pause(uint64_t until, unsigned interval_ms) {
    uint64_t now = garlic_instance_now_ms();
    if (!now || now >= until)
        return;
    uint64_t ms = until - now;
    if (ms > interval_ms)
        ms = interval_ms;
    struct timespec t = {(time_t)(ms / 1000), (long)(ms % 1000) * 1000000L};
    while (nanosleep(&t, &t) && errno == EINTR) {
    }
}

static int garlic_instance_wait(int fd, int writing, uint64_t deadline) {
    for (;;) {
        uint64_t now = garlic_instance_now_ms();
        if (!now || now >= deadline) {
            errno = ETIMEDOUT;
            return -1;
        }
        uint64_t left = deadline - now;
        struct timeval tv = {(time_t)(left / 1000), (suseconds_t)(left % 1000) * 1000};
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(fd, &fds);
        int r = select(fd + 1, writing ? NULL : &fds, writing ? &fds : NULL, NULL, &tv);
        if (r > 0)
            return 0;
        if (!r) {
            errno = ETIMEDOUT;
            return -1;
        }
        if (errno != EINTR)
            return -1;
    }
}

static const char *garlic_instance_ws(const char *p) {
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
        p++;
    return p;
}

/* Complete bounded strings, including escaped unknown/error values. */
static int garlic_instance_string(const char **cursor, char *out, size_t cap) {
    const char *p = *cursor;
    size_t n = 0;
    if (*p++ != '"')
        return -1;
    while (*p && *p != '"') {
        unsigned char c = (unsigned char)*p++;
        if (c < 32)
            return -1;
        if (c == '\\') {
            c = (unsigned char)*p++;
            if (!c)
                return -1;
            if (c == 'u') {
                for (unsigned i = 0; i < 4; i++) {
                    char h = *p++;
                    if (!h || !((h >= '0' && h <= '9') || (h >= 'a' && h <= 'f') ||
                                (h >= 'A' && h <= 'F')))
                        return -1;
                }
                c = '?';
            } else if (c == 'b')
                c = '\b';
            else if (c == 'f')
                c = '\f';
            else if (c == 'n')
                c = '\n';
            else if (c == 'r')
                c = '\r';
            else if (c == 't')
                c = '\t';
            else if (c != '"' && c != '\\' && c != '/')
                return -1;
        }
        if (n + 1 >= cap)
            return -1;
        out[n++] = (char)c;
    }
    if (*p++ != '"')
        return -1;
    out[n] = 0;
    *cursor = p;
    return 0;
}

static int garlic_instance_json(const char *body, garlic_instance_identity_t *id) {
    const char *p = garlic_instance_ws(body);
    memset(id, 0, sizeof(*id));
    if (*p++ != '{')
        return -1;
    p = garlic_instance_ws(p);
    if (*p == '}')
        return -1;
    for (unsigned fields = 0; fields < 24; fields++) {
        char key[64], value[GARLIC_INSTANCE_BODY_MAX + 1];
        unsigned bit = 0;
        if (garlic_instance_string(&p, key, sizeof(key)))
            return -1;
        p = garlic_instance_ws(p);
        if (*p++ != ':')
            return -1;
        p = garlic_instance_ws(p);
        int string_value = *p == '"';
        if (string_value) {
            if (garlic_instance_string(&p, value, sizeof(value)))
                return -1;
        } else {
            const char *start = p;
            while (*p && *p != ',' && *p != '}' && *p != ' ' && *p != '\t' && *p != '\r' &&
                   *p != '\n')
                p++;
            size_t n = (size_t)(p - start);
            if (!n || n >= sizeof(value))
                return -1;
            memcpy(value, start, n);
            value[n] = 0;
            if (strcmp(value, "true") && strcmp(value, "false") && strcmp(value, "null")) {
                const char *v = value;
                if (*v == '-')
                    v++;
                if (!*v)
                    return -1;
                if (*v == '0' && v[1])
                    return -1;
                while (*v >= '0' && *v <= '9')
                    v++;
                if (*v)
                    return -1;
            }
        }
        if (!strcmp(key, "app")) {
            bit = 1;
            if (!string_value || strlen(value) >= sizeof(id->app))
                return -1;
            strcpy(id->app, value);
        } else if (!strcmp(key, "takeover_protocol")) {
            bit = 2;
            if (string_value || strcmp(value, CMP_INSTANCE_PROTOCOL_TEXT))
                return -1;
            id->protocol = CMP_INSTANCE_PROTOCOL_VERSION;
        } else if (!strcmp(key, "cookie")) {
            bit = 4;
            if (!string_value || strlen(value) != CMP_INSTANCE_COOKIE_HEX_BYTES)
                return -1;
            for (unsigned i = 0; i < CMP_INSTANCE_COOKIE_HEX_BYTES; i++)
                if (!((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f')))
                    return -1;
            strcpy(id->cookie, value);
        } else if (!strcmp(key, "phase")) {
            bit = 8;
            if (!string_value || strlen(value) >= sizeof(id->phase))
                return -1;
            strcpy(id->phase, value);
        } else if (!strcmp(key, "ok")) {
            bit = 16;
            if (string_value || (strcmp(value, "true") && strcmp(value, "false")))
                return -1;
            id->ok = !strcmp(value, "true");
        } else if (!strcmp(key, "shutdown")) {
            bit = 32;
            if (!string_value)
                return -1;
            id->pending = !strcmp(value, "pending");
        }
        if (bit && (id->seen & bit))
            return -1;
        id->seen |= bit;
        p = garlic_instance_ws(p);
        if (*p == '}') {
            p = garlic_instance_ws(p + 1);
            return *p ? -1 : 0;
        }
        if (*p++ != ',')
            return -1;
        p = garlic_instance_ws(p);
    }
    return -1;
}

static int garlic_instance_header(const char *raw, size_t head, int *status, size_t *length,
                                  int *has_length) {
    int code = 0, minor = 0, consumed = 0;
    if (sscanf(raw, "HTTP/1.%d %d%n", &minor, &code, &consumed) != 2 ||
        (minor != 0 && minor != 1) || code < 100 || code > 599 || raw[consumed] != ' ')
        return -1;
    *status = code;
    *length = 0;
    *has_length = 0;
    const char *p = strstr(raw, "\r\n");
    if (!p)
        return -1;
    p += 2;
    const char *end = raw + head - 2;
    while (p < end && p[0] != '\r') {
        const char *e = strstr(p, "\r\n");
        if (!e || e > end)
            return -1;
        if (!strncasecmp(p, "Content-Length:", 15)) {
            if (*has_length)
                return -1;
            const char *v = p + 15;
            while (v < e && (*v == ' ' || *v == '\t'))
                v++;
            size_t n = 0;
            int digits = 0;
            while (v < e && *v >= '0' && *v <= '9') {
                n = n * 10 + (unsigned)(*v++ - '0');
                if (n > GARLIC_INSTANCE_BODY_MAX)
                    return -1;
                digits++;
            }
            while (v < e && (*v == ' ' || *v == '\t'))
                v++;
            if (!digits || v != e)
                return -1;
            *length = n;
            *has_length = 1;
        } else if (!strncasecmp(p, "Transfer-Encoding:", 18))
            return -1;
        p = e + 2;
    }
    return 0;
}

static int garlic_instance_http(unsigned port, const char *path, const char *cookie,
                                uint64_t deadline, int *status,
                                char body[GARLIC_INSTANCE_BODY_MAX + 1]) {
    int fd = -1, result = -1, flags;
    char request[256], raw[4097];
    size_t used = 0, head = 0, content = 0;
    int have_length = 0;
    uint64_t now = garlic_instance_now_ms();
    if (!now || now >= deadline)
        return -1;
    if (deadline - now > 1500)
        deadline = now + 1500;
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    if (fd >= FD_SETSIZE)
        goto done;
    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        goto done;
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons((uint16_t)port);
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) < 0) {
        if (errno != EINPROGRESS && errno != EWOULDBLOCK)
            goto done;
        if (garlic_instance_wait(fd, 1, deadline))
            goto done;
        int error = 0;
        socklen_t n = sizeof(error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &n) || error)
            goto done;
    }
    int n = snprintf(request, sizeof(request),
                     "GET %s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n%s%s%s\r\n", path,
                     cookie ? CMP_INSTANCE_COOKIE_HEADER " " : "", cookie ? cookie : "",
                     cookie ? "\r\n" : "");
    if (n < 0 || (size_t)n >= sizeof(request))
        goto done;
    for (size_t sent = 0; sent < (size_t)n;) {
        int send_flags = 0;
#ifdef MSG_NOSIGNAL
        send_flags = MSG_NOSIGNAL;
#endif
        ssize_t written = send(fd, request + sent, (size_t)n - sent, send_flags);
        if (written > 0) {
            sent += (size_t)written;
            continue;
        }
        if (written < 0 && errno == EINTR)
            continue;
        if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (!garlic_instance_wait(fd, 1, deadline))
                continue;
        }
        goto done;
    }
    while (used < sizeof(raw) - 1) {
        if (head && have_length && used - head >= content)
            break;
        ssize_t got = recv(fd, raw + used, sizeof(raw) - 1 - used, 0);
        if (got > 0) {
            if (memchr(raw + used, 0, (size_t)got))
                goto done;
            used += (size_t)got;
            raw[used] = 0;
            if (!head) {
                char *p = strstr(raw, "\r\n\r\n");
                if (p) {
                    head = (size_t)(p - raw) + 4;
                    if (head > 2048 ||
                        garlic_instance_header(raw, head, status, &content, &have_length))
                        goto done;
                }
            }
            if (head && used - head > GARLIC_INSTANCE_BODY_MAX)
                goto done;
            continue;
        }
        if (!got) {
            if (!head || (have_length && used - head != content))
                goto done;
            break;
        }
        if (errno == EINTR)
            continue;
        if ((errno == EAGAIN || errno == EWOULDBLOCK) && !garlic_instance_wait(fd, 0, deadline))
            continue;
        goto done;
    }
    if (!head || (have_length && used - head != content) || used - head > GARLIC_INSTANCE_BODY_MAX)
        goto done;
    memcpy(body, raw + head, used - head);
    body[used - head] = 0;
    result = 0;
done:
    close(fd);
    return result;
}

static int garlic_instance_same_file(int fd, const char *path) {
    struct stat opened, current;
    return fstat(fd, &opened) == 0 && lstat(path, &current) == 0 && S_ISREG(opened.st_mode) &&
           S_ISREG(current.st_mode) && opened.st_nlink == 1 && current.st_dev == opened.st_dev &&
           current.st_ino == opened.st_ino;
}

static int garlic_instance_try_lock(int fd) {
    struct flock l;
    memset(&l, 0, sizeof(l));
    l.l_type = F_WRLCK;
    l.l_whence = SEEK_SET;
    if (!fcntl(fd, F_SETLK, &l))
        return 0;
    return errno == EACCES || errno == EAGAIN ? 1 : -1;
}

void garlic_instance_release(int fd) {
    if (fd >= 0)
        close(fd);
}

static int garlic_instance_failure(int fd, char *error, size_t cap, const char *message) {
    if (error && cap)
        snprintf(error, cap, "%s", message);
    garlic_instance_release(fd);
    return -1;
}

int garlic_instance_acquire(const char *lock_path, unsigned port, unsigned wait_ms, char *error,
                            size_t cap) {
    if (error && cap)
        error[0] = 0;
    if (!lock_path || !*lock_path || !port || port > 65535)
        return garlic_instance_failure(-1, error, cap, "Invalid instance lock or listener port.");
    int fd = open(lock_path, O_CREAT | O_RDWR | O_NOFOLLOW, 0600);
    if (fd < 0)
        return garlic_instance_failure(-1, error, cap,
                                       "Cannot open the local Garlic instance lock safely.");
    if (!garlic_instance_same_file(fd, lock_path))
        return garlic_instance_failure(
            fd, error, cap, "The instance lock is linked, replaced or not a regular file.");
    uint64_t start = garlic_instance_now_ms();
    if (!start)
        return garlic_instance_failure(fd, error, cap, "Cannot read the monotonic instance clock.");
    uint64_t deadline = start + wait_ms;
    int accepted = 0;
    char old_cookie[CMP_INSTANCE_COOKIE_TEXT_BYTES] = {0};
    for (;;) {
        if (!garlic_instance_same_file(fd, lock_path))
            return garlic_instance_failure(
                fd, error, cap,
                "The instance lock changed while waiting; replacement was stopped.");
        int locked = garlic_instance_try_lock(fd);
        if (!locked) {
            if (!garlic_instance_same_file(fd, lock_path))
                return garlic_instance_failure(fd, error, cap,
                                               "The instance lock changed during acquisition.");
            return fd;
        }
        if (locked < 0)
            return garlic_instance_failure(fd, error, cap,
                                           "The system could not claim the Garlic instance lock.");
        if (garlic_instance_now_ms() >= deadline)
            return garlic_instance_failure(
                fd, error, cap,
                "Timed out waiting for the old Garlic instance to shut down safely.");
        char body[GARLIC_INSTANCE_BODY_MAX + 1];
        int status = 0;
        garlic_instance_identity_t identity;
        if (!garlic_instance_http(port, "/api/instance", NULL, deadline, &status, body)) {
            if (status != 200 || garlic_instance_json(body, &identity) ||
                (identity.seen & 15) != 15 || strcmp(identity.app, CMP_INSTANCE_APP_NAME) ||
                identity.protocol != CMP_INSTANCE_PROTOCOL_VERSION ||
                (strcmp(identity.phase, "running") && strcmp(identity.phase, "draining") &&
                 strcmp(identity.phase, "failed")))
                return garlic_instance_failure(
                    fd, error, cap,
                    "The running service does not support safe Garlic replacement. Stop the older instance manually once.");
            if (!strcmp(identity.phase, "failed"))
                return garlic_instance_failure(
                    fd, error, cap,
                    "The old Garlic instance reported cleanup failure; replacement was stopped.");
            if (accepted && strcmp(old_cookie, identity.cookie))
                return garlic_instance_failure(
                    fd, error, cap,
                    "A different Garlic instance took ownership while waiting; this launch stopped.");
            if (!accepted) {
                memcpy(old_cookie, identity.cookie, sizeof(old_cookie));
                if (!strcmp(identity.phase, "draining"))
                    accepted = 1;
                else {
                    garlic_instance_identity_t reply;
                    if (!garlic_instance_http(port, "/api/shutdown", identity.cookie, deadline,
                                              &status, body)) {
                        if (status != 200 || garlic_instance_json(body, &reply) ||
                            (reply.seen & 48) != 48 || !reply.ok || !reply.pending)
                            return garlic_instance_failure(
                                fd, error, cap, "The old Garlic instance refused a safe shutdown.");
                        accepted = 1;
                    }
                }
            }
        }
        /* Rebuild2/3 only recheck cleanup after their 250 ms listener wait.
         * Frequent identity requests can keep that wait from expiring. Leave
         * a quiet interval after shutdown is accepted so those versions can
         * observe zero workers, finish native cleanup and release ownership. */
        garlic_instance_pause(deadline, accepted ? GARLIC_INSTANCE_DRAIN_POLL_MS
                                                 : GARLIC_INSTANCE_DISCOVERY_POLL_MS);
    }
}
