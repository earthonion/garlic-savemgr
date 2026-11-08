#ifndef CMP_LIFECYCLE_BRIDGE_H
#define CMP_LIFECYCLE_BRIDGE_H
/* Private adapter to Garlic's HTTP, mount and background-job services. */
#include <pthread.h>
#include <stddef.h>
#include "../transfer_control.h"
#include "../native_types.h"
extern pthread_mutex_t g_mtx;
extern garlic_transfer_control_t g_transfer;
extern int g_mounted, g_owner_mount_active, g_srvfd;
int cmp_cloud_running(void);
void http_json(int sock, const char *json);
void chives_escape(const char *input, char *output, size_t capacity);
void logprintf(const char *format, ...);
void notify(const char *format, ...);
void *request_thread(void *argument);
int cleanup_web_transfer_job(garlic_transfer_control_t *control, uint64_t id, const char *base,
                             char *error, size_t capacity);
int unmount_save(void);
uint64_t mono_ms(void);
#endif
