#ifndef CMP_PS5PARAM_BRIDGE_H
#define CMP_PS5PARAM_BRIDGE_H

/* Internal bridge to Garlic's tracked mount and normal generated-key cache.
 * Mount definitions remain in main.c; key-cache ownership is in native_key.c.
 * No second copy of application state exists.
 * This bridge intentionally preserves Rebuild4's shared-cache reset behavior. */
#include <stdint.h>
#include "../ps5param.h"
#include "../native_key.h"

extern int g_mounted;
extern char g_local_copy[CMP_PS5PARAM_PATH_BYTES];
extern char g_mounted_path[CMP_PS5PARAM_PATH_BYTES];
extern char g_mount_point[CMP_PS5PARAM_PATH_BYTES];
void logprintf(const char *fmt, ...);

#endif
