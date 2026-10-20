/* SPDX-License-Identifier: AGPL-3.0-only */
#include "picokeys.h"
#include "fido.h"
#include "files.h"
#include "flash.h"

static bool counter_storage_fault;

static int sign_counter_read(uint32_t *counter) {
    if (!ef_counter || !file_has_data(ef_counter) || file_get_size(ef_counter) != sizeof(uint32_t)) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    uint8_t encoded[4];
    int ret = file_read_at(ef_counter, 0, BYTE_ARRAY(encoded, sizeof(encoded)));
    if (ret == PICOKEYS_OK) *counter = get_uint32_le(encoded);
    return ret;
}

uint32_t get_sign_counter(void) {
    uint32_t counter = 0;
    (void)sign_counter_read(&counter);
    return counter;
}

int bump_sign_counter(uint32_t *counter) {
    if (!counter) return PICOKEYS_ERR_NULL_PARAM;
    if (counter_storage_fault) return PICOKEYS_ERR_MEMORY_FATAL;
    uint32_t current;
    int ret = sign_counter_read(&current);
    if (ret != PICOKEYS_OK) return ret;
    if (current == UINT32_MAX) return PICOKEYS_ERR_MEMORY_FATAL;
    uint8_t encoded[4];
    put_uint32_le(current + 1, encoded);
    ret = file_put_data(ef_counter, CONST_BYTE_ARRAY(encoded, sizeof(encoded)));
    if (ret == PICOKEYS_OK && !flash_commit_sync(5000u)) ret = PICOKEYS_ERR_MEMORY_FATAL;
    if (ret != PICOKEYS_OK) {
        /* A timed-out commit may still finish. Never issue another counter
         * from this ambiguous cache until a reboot reloads durable state. */
        counter_storage_fault = true;
        return ret;
    }
    *counter = current + 1;
    return PICOKEYS_OK;
}
