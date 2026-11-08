#ifndef CMP_INTERNAL_SAVE_FORMAT_H
#define CMP_INTERNAL_SAVE_FORMAT_H

#include <stdint.h>

/* Existing native on-image records. These constants describe byte layouts;
 * they do not supply an independent encryption/authentication implementation. */
#define CMP_PFS_SEALED_KEY_OFFSET 0x800u
#define CMP_PFS_SEALED_KEY_BYTES 96u
#define CMP_PFS_NATIVE_BLOCK_BYTES 65536u

#define CMP_PS5PARAM_MAGIC UINT64_C(0x4D41524150355350)
#define CMP_PS5PARAM_BLOB_BYTES 0x8000u
#define CMP_PS5PARAM_HEADER_BYTES 20u
#define CMP_PS5PARAM_MAX_SFO_BYTES (CMP_PS5PARAM_BLOB_BYTES - CMP_PS5PARAM_HEADER_BYTES)
#define CMP_PS5PARAM_IMAGE_OFFSET 0xC00u
#define CMP_PS5PARAM_IMAGE_END (CMP_PS5PARAM_IMAGE_OFFSET + CMP_PS5PARAM_BLOB_BYTES)

/* The physical-SFO profile requires the observed extra 32 bytes to be blank.
 * Their universal meaning is unproven; this is not an authentication-tag ABI. */
#define CMP_LEGACY_BLANK_GUARD_END 0x8C20u

/* The PSF file header and PS5PARAM wrapper are separate formats even though
 * their current headers happen to have the same byte length. */
#define CMP_SFO_HEADER_BYTES 20u

#define CMP_PFS_COW_CONVERT_IOCTL 0x80109115UL
#define CMP_PS5PARAM_ERR_BAD_BLOB (-1002)
#define CMP_PS5PARAM_ERR_BAD_SFO (-1003)

#endif
