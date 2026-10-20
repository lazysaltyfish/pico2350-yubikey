/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef APPLET_STORAGE_H
#define APPLET_STORAGE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define APPLET_STORAGE_OVERHEAD 36u

/* Versioned AES-GCM records bind the complete payload to its file ID and size.
 * There is deliberately no unauthenticated legacy/plaintext fallback.
 * Loads clear output on failure, including failed authentication. */
bool applet_storage_load(uint16_t fid, void *plain, size_t expected_len);
bool applet_storage_load_variable(uint16_t fid, void *plain, size_t capacity, size_t *len);
bool applet_storage_save(uint16_t fid, const void *plain, size_t len);
#endif
