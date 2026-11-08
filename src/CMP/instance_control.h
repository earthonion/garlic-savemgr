#ifndef GARLIC_INSTANCE_CONTROL_H
#define GARLIC_INSTANCE_CONTROL_H
/* Process-lifetime advisory ownership and cooperative loopback replacement.
 * No PID signalling, stale-lock deletion, or legacy shutdown fallback. */
#include <stddef.h>

void garlic_instance_release(int fd);
int garlic_instance_acquire(const char *lock_path, unsigned port, unsigned wait_ms, char *error,
                            size_t cap);
#endif
