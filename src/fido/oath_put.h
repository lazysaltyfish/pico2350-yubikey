/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef FIDO_OATH_PUT_H
#define FIDO_OATH_PUT_H

#include <stddef.h>
#include <stdint.h>

/* The caller owns the normalized credential and must clear it before freeing. */
int oath_normalize_put_data(const uint8_t *in, size_t in_len,
                            uint8_t **out_buf, size_t *out_len);

#endif
