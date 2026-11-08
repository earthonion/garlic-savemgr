#ifndef CMP_PFS_REBUILD_BRIDGE_H
#define CMP_PFS_REBUILD_BRIDGE_H

/* Private integration boundary. Garlic owns native mounting and the active
 * save; the CMP rebuild module owns conversion/provenance/finalization. */
#include "../native_types.h"
#include "../chives.h"
#include "../common.h"

extern PprCreateFn g_pprCreate;
extern int g_mounted;
extern char g_mount_point[CMP_PATH_BYTES];

void logprintf(const char *fmt, ...);
int chives_read_image(const char *image, chives_geometry_t *geometry);
int chives_verify_created(const char *image, const chives_geometry_t *expected);
int mount_by_path_at_checked(const char *path, const char *mount_point, int track, int require_key);
int unmount_save(void);
int read_sfo_file(const char *path, uint8_t *buffer, uint32_t capacity);

#endif
