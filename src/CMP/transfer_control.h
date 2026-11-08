#ifndef GARLIC_TRANSFER_CONTROL_H
#define GARLIC_TRANSFER_CONTROL_H
/* Job IDs isolate late queued requests from a cancelled Encrypt/Decrypt job.
 * Socket shutdown wakes a blocked receive; native filesystem calls finish
 * under the existing mount mutex before cancellation cleanup is acknowledged. */
#include <stdint.h>
#include <stddef.h>
#include <pthread.h>
#define GARLIC_TRANSFER_SOCKETS 32

typedef struct {
    int used, fd;
    uint64_t id;
} garlic_transfer_socket_t;
typedef struct {
    pthread_mutex_t mutex;
    uint64_t serial, id;
    int active, cancelled;
    garlic_transfer_socket_t sockets[GARLIC_TRANSFER_SOCKETS];
} garlic_transfer_control_t;
#define GARLIC_TRANSFER_INITIALIZER                                                                \
    { .mutex = PTHREAD_MUTEX_INITIALIZER }

/* 0 absent, 1 valid, -1 malformed; inspect headers only, never upload bytes. */
int garlic_transfer_header(const char *req, size_t n, uint64_t *id);
int garlic_transfer_begin(garlic_transfer_control_t *c, uint64_t *id);
int garlic_transfer_allowed(garlic_transfer_control_t *c, uint64_t id);
int garlic_transfer_cleanup_allowed(garlic_transfer_control_t *c, uint64_t id);
int garlic_transfer_busy(garlic_transfer_control_t *c);
int garlic_transfer_attach(garlic_transfer_control_t *c, uint64_t id, int fd);
void garlic_transfer_detach(garlic_transfer_control_t *c, int slot, uint64_t id, int fd);
int garlic_transfer_cancel(garlic_transfer_control_t *c, uint64_t id);
int garlic_transfer_end(garlic_transfer_control_t *c, uint64_t id, int cancelled);
#endif
