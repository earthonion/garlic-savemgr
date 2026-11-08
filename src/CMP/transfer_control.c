/* CMP add-in implementation; declarations are in transfer_control.h.
 * Extracted without algorithm changes from CMP Rebuild4. */
#include "transfer_control.h"
#include <strings.h>
#include <sys/socket.h>

int garlic_transfer_header(const char *req, size_t n, uint64_t *id) {
    const char *p = req, *end = req + n;
    int found = 0;
    *id = 0;
    while (p < end) {
        const char *line = p;
        while (p < end && *p != '\r' && *p != '\n')
            p++;
        size_t len = (size_t)(p - line);
        if (!len)
            break;
        if (len >= 18 && !strncasecmp(line, "X-Garlic-Transfer:", 18)) {
            uint64_t value = 0;
            size_t k = 18;
            unsigned count = 0;
            if (found++)
                return -1;
            while (k < len && (line[k] == ' ' || line[k] == '\t'))
                k++;
            for (; k < len && line[k] != ' ' && line[k] != '\t'; k++) {
                unsigned c = (unsigned char)line[k], digit;
                if (c >= '0' && c <= '9')
                    digit = c - '0';
                else if (c >= 'a' && c <= 'f')
                    digit = c - 'a' + 10;
                else if (c >= 'A' && c <= 'F')
                    digit = c - 'A' + 10;
                else
                    return -1;
                if (++count > 16)
                    return -1;
                value = (value << 4) | digit;
            }
            while (k < len && (line[k] == ' ' || line[k] == '\t'))
                k++;
            if (k != len || count != 16 || !value)
                return -1;
            *id = value;
        }
        if (p < end && *p == '\r')
            p++;
        if (p < end && *p == '\n')
            p++;
    }
    return found ? 1 : 0;
}

int garlic_transfer_begin(garlic_transfer_control_t *c, uint64_t *id) {
    int ok = 0;
    pthread_mutex_lock(&c->mutex);
    if (!c->active) {
        if (!++c->serial)
            ++c->serial;
        c->id = c->serial;
        c->active = 1;
        c->cancelled = 0;
        *id = c->id;
        ok = 1;
    }
    pthread_mutex_unlock(&c->mutex);
    return ok;
}

int garlic_transfer_allowed(garlic_transfer_control_t *c, uint64_t id) {
    int ok;
    pthread_mutex_lock(&c->mutex);
    ok = c->active && c->id == id && !c->cancelled;
    pthread_mutex_unlock(&c->mutex);
    return ok;
}

int garlic_transfer_cleanup_allowed(garlic_transfer_control_t *c, uint64_t id) {
    int ok;
    pthread_mutex_lock(&c->mutex);
    ok = c->id == id && c->cancelled;
    pthread_mutex_unlock(&c->mutex);
    return ok;
}

int garlic_transfer_busy(garlic_transfer_control_t *c) {
    int busy;
    pthread_mutex_lock(&c->mutex);
    busy = c->active;
    pthread_mutex_unlock(&c->mutex);
    return busy;
}

int garlic_transfer_attach(garlic_transfer_control_t *c, uint64_t id, int fd) {
    int slot = -1;
    pthread_mutex_lock(&c->mutex);
    if (c->active && c->id == id && !c->cancelled)
        for (int i = 0; i < GARLIC_TRANSFER_SOCKETS; i++)
            if (!c->sockets[i].used) {
                c->sockets[i] = (garlic_transfer_socket_t){1, fd, id};
                slot = i;
                break;
            }
    pthread_mutex_unlock(&c->mutex);
    return slot;
}

void garlic_transfer_detach(garlic_transfer_control_t *c, int slot, uint64_t id, int fd) {
    pthread_mutex_lock(&c->mutex);
    if (slot >= 0 && slot < GARLIC_TRANSFER_SOCKETS && c->sockets[slot].used &&
        c->sockets[slot].id == id && c->sockets[slot].fd == fd)
        c->sockets[slot].used = 0;
    pthread_mutex_unlock(&c->mutex);
}

int garlic_transfer_cancel(garlic_transfer_control_t *c, uint64_t id) {
    int ok = 0;
    pthread_mutex_lock(&c->mutex);
    if (c->id == id && id) {
        c->cancelled = 1;
        c->active = 1;
        ok = 1;
        for (int i = 0; i < GARLIC_TRANSFER_SOCKETS; i++)
            if (c->sockets[i].used && c->sockets[i].id == id)
                shutdown(c->sockets[i].fd, SHUT_RDWR);
    }
    pthread_mutex_unlock(&c->mutex);
    return ok;
}

int garlic_transfer_end(garlic_transfer_control_t *c, uint64_t id, int cancelled) {
    int ok = 0;
    pthread_mutex_lock(&c->mutex);
    if (c->id == id && (cancelled ? c->cancelled : !c->cancelled)) {
        c->active = 0;
        ok = 1;
    }
    pthread_mutex_unlock(&c->mutex);
    return ok;
}
