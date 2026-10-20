/*
 * Pico-YubiKey (RP2350)
 * Copyright (c) 2026 lazysaltyfish
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

/* Security Domain is intentionally unavailable until SCP authentication,
 * authenticated key storage and secure messaging are implemented together.
 * In particular, authentication probes must never erase persistent data. */
#include "picokeys.h"
#include "apdu.h"

static int sd_process_apdu(void) {
    return SW_INS_NOT_SUPPORTED();
}

static int sd_select(app_t *a, uint8_t force) {
    (void)a;
    (void)force;
    return PICOKEYS_ERR_FILE_NOT_FOUND;
}

static const uint8_t sd_aid[] = {8, 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00};
INITIALIZER(sd_ctor) {
    /* A disabled tombstone also protects builds with a stale ON cache entry. */
    (void)sd_process_apdu;
    register_app(sd_select, sd_aid);
}
