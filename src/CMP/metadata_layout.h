#ifndef GARLIC_METADATA_LAYOUT_H
#define GARLIC_METADATA_LAYOUT_H

/* Conservative physical-SFO profile, based on an original version-2 save.
 * A zero fs_ext alone is insufficient: an unconverted PPR image also has it.
 * The caller must additionally bind this decision to the source geometry and
 * verify the encrypted image has no protected PS5PARAM region. No SFO bytes
 * are changed here. This is classification evidence, not image authentication.
 */
#include "chives.h"

int garlic_legacy_geometry_matches(const chives_geometry_t *geometry);

int garlic_legacy_sfo_matches(const chives_geometry_t *geometry, const uint8_t *sfo, size_t size);

#endif
