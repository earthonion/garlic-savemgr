#ifndef CMP_PFS_REBUILD_H
#define CMP_PFS_REBUILD_H

#include <stdint.h>
#include "native_types.h"
#include "chives.h"

/* Native CoW conversion and guarded physical-SFO reconstruction.
 * Calls are serialized by Garlic's existing save-operation mutex. */
int chives_ppr_create(CreateOpt *opt, const char *path, uint64_t size,
                      const chives_geometry_t *expected);
int finalize_ps5_sfo(const char *image, const uint8_t *sfo, uint32_t size, int fresh);

#endif
