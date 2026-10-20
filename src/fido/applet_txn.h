/*
 * Pico-YubiKey (RP2350)
 * Copyright (c) 2026 lazysaltyfish
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#ifndef APPLET_TXN_H
#define APPLET_TXN_H
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    uint16_t marker_fid;
    bool active;
    bool faulted;
} applet_txn_t;

#define APPLET_TXN_INITIALIZER(fid) { .marker_fid = (fid) }

/* Serialize callers on the applet worker. The marker FID must be private to
 * this applet. begin durably authenticates an intent before any multi-file
 * mutation; commit flushes all data before durably clearing that intent.
 *
 * A reboot during an operation leaves an authenticated dirty marker. ready
 * then refuses ordinary applet access instead of exposing mixed key/policy
 * records. There is no automatic rollback or restoration of default policy.
 * Recovery must explicitly authorize physical presence and destruction of all
 * applet records, then use recover_begin and commit only after that destruction.
 * Existing installations without a marker migrate on their first transaction.
 * This provides crash consistency, not whole-Flash replay protection. */
bool applet_txn_ready(applet_txn_t *txn);
bool applet_txn_begin(applet_txn_t *txn);
bool applet_txn_commit(applet_txn_t *txn);
/* Caller must first require explicit destructive intent and physical presence.
 * Reassert DIRTY despite a previous fault, erase all applet records, then commit.
 * Never use this to continue a failed operation with its old credentials. */
bool applet_txn_recover_begin(applet_txn_t *txn);
/* A failed write/timeout can leave dirty cache contents: require reboot before
 * inspecting even an otherwise clean single-record operation again. */
void applet_txn_fail(applet_txn_t *txn);
#endif
