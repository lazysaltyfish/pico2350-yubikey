/*
 * Pico-YubiKey (RP2350)
 * Copyright (c) 2026 lazysaltyfish
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#include "picokeys.h"
#if defined(PICO_PLATFORM)
#include "pico/stdlib.h"
#endif
#include "applet_storage.h"
#include "applet_txn.h"
#include "mbedtls/platform_util.h"

#define APPLET_TXN_COMMIT_TIMEOUT_MS 5000u
static const uint8_t clean_record[8] = { 'P', 'A', 'T', 1, 0, 0, 0, 0 };

void applet_txn_fail(applet_txn_t *txn) {
    if (txn) {
        txn->active = false;
        txn->faulted = true;
    }
}

bool applet_txn_ready(applet_txn_t *txn) {
    if (!txn || txn->faulted) return false;
    if (txn->active) return true;
    file_t *marker = file_search(txn->marker_fid);
    if (!file_has_data(marker)) return true;
    uint8_t record[sizeof(clean_record)];
    bool ok = applet_storage_load(txn->marker_fid, record, sizeof(record)) &&
              memcmp(record, clean_record, sizeof(record)) == 0;
    mbedtls_platform_zeroize(record, sizeof(record));
    if (!ok) applet_txn_fail(txn);
    return ok;
}

static bool save_marker(applet_txn_t *txn, bool dirty) {
#if defined(PICO_PLATFORM)
    if (get_core_num() != 1) {
        return false;
    }
#endif
    uint8_t record[sizeof(clean_record)];
    memcpy(record, clean_record, sizeof(record));
    record[4] = dirty ? 1 : 0;
    bool ok = applet_storage_save(txn->marker_fid, record, sizeof(record)) &&
              flash_commit_sync(APPLET_TXN_COMMIT_TIMEOUT_MS);
    mbedtls_platform_zeroize(record, sizeof(record));
    if (!ok) applet_txn_fail(txn);
    return ok;
}

bool applet_txn_begin(applet_txn_t *txn) {
    if (!txn || txn->active || !applet_txn_ready(txn)) return false;
    if (!save_marker(txn, true)) return false;
    txn->active = true;
    return true;
}

bool applet_txn_commit(applet_txn_t *txn) {
    if (!txn || txn->faulted || !txn->active) return false;
    /* A durable clean marker is allowed only after every data write is
     * durable. Timeout can never publish a partially completed operation. */
    if (!flash_commit_sync(APPLET_TXN_COMMIT_TIMEOUT_MS)) {
        applet_txn_fail(txn);
        return false;
    }
    if (!save_marker(txn, false)) return false;
    txn->active = false;
    return true;
}

bool applet_txn_recover_begin(applet_txn_t *txn) {
    if (!txn) return false;
    txn->active = false;
    txn->faulted = false;
    if (!save_marker(txn, true)) return false;
    txn->active = true;
    return true;
}
