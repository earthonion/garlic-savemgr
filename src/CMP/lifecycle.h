#ifndef CMP_LIFECYCLE_H
#define CMP_LIFECYCLE_H
#include <stddef.h>

/* One process-wide state owner. Main only reserves workers and publishes
 * watcher transitions; the CMP module owns shutdown and safe handover. */
/* Startup must finish before listener reservation or save-state work. */
int garlic_lifecycle_start(const char *lock_path, unsigned port, unsigned wait_ms, char *error,
                           size_t capacity);
void garlic_lifecycle_release_instance(void);
/* Reserve before pthread_create; the worker wrapper releases every outcome. */
void garlic_lifecycle_reserve_worker(void);
void garlic_lifecycle_set_watcher_active(int active);
int garlic_lifecycle_stopping(void);
int garlic_lifecycle_pause(unsigned seconds);
int garlic_lifecycle_http(int sock, const char *method, const char *url, const char *request,
                          size_t size);
void *garlic_lifecycle_worker(void *argument);
int garlic_lifecycle_try_exit(void);
#endif
