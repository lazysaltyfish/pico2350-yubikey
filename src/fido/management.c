/*
 * This file is part of the Pico FIDO distribution (https://github.com/polhenarejos/pico-fido).
 * Copyright (c) 2022 Pol Henarejos.
 * Copyright (c) 2026 lazysaltyfish. Modified for RP2350 & YubiKey 5 alignment (2026-10).
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

#include <stdio.h>
#include "picokeys.h"
#include "serial.h"
#include "fido.h"
#include "apdu.h"
#include "version.h"
#include "files.h"
#include "tlv.h"
#include "management.h"
#include "mbedtls/constant_time.h"
#include "mbedtls/platform_util.h"

bool is_gpg = true;

static int man_process_apdu(void);
static int man_unload(void);

const uint8_t man_aid[] = {
    8,
    0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17
};
static int man_select(app_t *a, uint8_t force) {
    a->process_apdu = man_process_apdu;
    a->unload = man_unload;
    sprintf((char *) res_APDU, "%d.%d.0", PICO_FIDO_VERSION_MAJOR, PICO_FIDO_VERSION_MINOR);
    res_APDU_size = (uint16_t)strlen((char *) res_APDU);
    apdu.ne = res_APDU_size;
    if (force) {
        scan_all();
#ifdef ENABLE_OTP_APP
        init_otp();
#endif
    }
    is_gpg = false;
    return PICOKEYS_OK;
}

INITIALIZER ( man_ctor ) {
    register_app(man_select, man_aid);
}

static int man_unload(void) {
    return PICOKEYS_OK;
}

static const uint8_t _openpgp_aid[] = {
    6,
    0xD2, 0x76, 0x00, 0x01, 0x24, 0x01,
};
static const uint8_t _piv_aid[] = {
    5,
    0xA0, 0x00, 0x00, 0x03, 0x08,
};
static const uint8_t _hsmauth_aid[] = {
    8,
    0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x07, 0x01,
};

#define MAN_LOCK_CODE_LEN 16

typedef struct {
    uint16_t usb_enabled;
    uint16_t nfc_enabled;
    uint16_t auto_eject_timeout;
    uint8_t chalresp_timeout;
    uint8_t device_flags;
    uint8_t nfc_restricted;
    bool is_locked;
    uint8_t lock_code[MAN_LOCK_CODE_LEN];
} man_config_state_t;

static bool man_lock_code_is_nonzero(const uint8_t code[MAN_LOCK_CODE_LEN]) {
    uint8_t acc = 0;
    for (size_t i = 0; i < MAN_LOCK_CODE_LEN; i++) {
        acc |= code[i];
    }
    return acc != 0;
}

uint16_t man_supported_usb_caps(void) {
    uint16_t caps = CAP_FIDO2 | CAP_U2F;
#ifdef ENABLE_OTP_APP
    caps |= CAP_OTP;
#endif
#ifdef ENABLE_OATH_APP
    caps |= CAP_OATH;
#endif
    if (app_exists(CONST_BYTE_ARRAY(_openpgp_aid + 1, _openpgp_aid[0]))) {
        caps |= CAP_OPENPGP;
    }
    if (app_exists(CONST_BYTE_ARRAY(_piv_aid + 1, _piv_aid[0]))) {
        caps |= CAP_PIV;
    }
    if (app_exists(CONST_BYTE_ARRAY(_hsmauth_aid + 1, _hsmauth_aid[0]))) {
        caps |= CAP_HSMAUTH;
    }
    return caps;
}

static void man_load_state(man_config_state_t *state) {
    memset(state, 0, sizeof(*state));
    state->usb_enabled = 0xFFFF;
    state->device_flags = FLAG_EJECT;
    state->is_locked = false;

    file_t *ef = file_search(EF_DEV_CONF);
    if (!file_has_data(ef)) {
        return;
    }
    uint8_t *p = NULL;
    tlv_item_t item;
    tlv_ctx_t ctxi;
    tlv_ctx_init(BYTE_ARRAY(file_get_data(ef), file_get_size(ef)), &ctxi);
    while (tlv_walk(&ctxi, &p, &item)) {
        switch (item.tag) {
            case TAG_USB_ENABLED:
                if (item.value.len == 1) {
                    state->usb_enabled = item.value.data[0];
                }
                else if (item.value.len == 2) {
                    state->usb_enabled = get_uint16_be(item.value.data);
                }
                break;
            case TAG_AUTO_EJECT_TIMEOUT:
                if (item.value.len == 1) {
                    state->auto_eject_timeout = item.value.data[0];
                }
                else if (item.value.len == 2) {
                    state->auto_eject_timeout = get_uint16_be(item.value.data);
                }
                break;
            case TAG_CHALRESP_TIMEOUT:
                if (item.value.len >= 1) {
                    state->chalresp_timeout = item.value.data[0];
                }
                break;
            case TAG_DEVICE_FLAGS:
                if (item.value.len >= 1) {
                    state->device_flags = item.value.data[0];
                }
                break;
            case TAG_CONFIG_LOCK:
                if (item.value.len == MAN_LOCK_CODE_LEN && man_lock_code_is_nonzero(item.value.data)) {
                    state->is_locked = true;
                    memcpy(state->lock_code, item.value.data, MAN_LOCK_CODE_LEN);
                }
                else if (item.value.len == 1 && item.value.data[0] == 0) {
                    state->is_locked = false;
                    memset(state->lock_code, 0, MAN_LOCK_CODE_LEN);
                }
                break;
            case TAG_NFC_ENABLED:
                if (item.value.len == 1) {
                    state->nfc_enabled = item.value.data[0];
                }
                else if (item.value.len == 2) {
                    state->nfc_enabled = get_uint16_be(item.value.data);
                }
                break;
            case TAG_NFC_RESTRICTED:
                if (item.value.len >= 1) {
                    state->nfc_restricted = item.value.data[0];
                }
                break;
            default:
                break;
        }
    }
}

static int man_save_state(const man_config_state_t *state) {
    uint8_t buf[64];
    uint16_t len = 0;

    buf[len++] = TAG_USB_ENABLED;
    buf[len++] = 2;
    buf[len++] = (uint8_t)(state->usb_enabled >> 8);
    buf[len++] = (uint8_t)(state->usb_enabled & 0xFF);

    buf[len++] = TAG_AUTO_EJECT_TIMEOUT;
    buf[len++] = 2;
    buf[len++] = (uint8_t)(state->auto_eject_timeout >> 8);
    buf[len++] = (uint8_t)(state->auto_eject_timeout & 0xFF);

    buf[len++] = TAG_CHALRESP_TIMEOUT;
    buf[len++] = 1;
    buf[len++] = state->chalresp_timeout;

    buf[len++] = TAG_DEVICE_FLAGS;
    buf[len++] = 1;
    buf[len++] = state->device_flags;

    if (state->is_locked) {
        buf[len++] = TAG_CONFIG_LOCK;
        buf[len++] = MAN_LOCK_CODE_LEN;
        memcpy(buf + len, state->lock_code, MAN_LOCK_CODE_LEN);
        len += MAN_LOCK_CODE_LEN;
    }

    if (state->nfc_enabled != 0) {
        buf[len++] = TAG_NFC_ENABLED;
        buf[len++] = 2;
        buf[len++] = (uint8_t)(state->nfc_enabled >> 8);
        buf[len++] = (uint8_t)(state->nfc_enabled & 0xFF);
    }

    if (state->nfc_restricted != 0) {
        buf[len++] = TAG_NFC_RESTRICTED;
        buf[len++] = 1;
        buf[len++] = state->nfc_restricted;
    }

    file_t *ef = file_search(EF_DEV_CONF);
    if (!ef) {
        ef = file_new(EF_DEV_CONF);
    }
    if (!ef || file_put_data(ef, CONST_BYTE_ARRAY(buf, len)) != PICOKEYS_OK) {
        mbedtls_platform_zeroize(buf, sizeof(buf));
        return PICOKEYS_ERR_MEMORY_FATAL;
    }
    mbedtls_platform_zeroize(buf, sizeof(buf));
    flash_commit();

#ifndef ENABLE_EMULATION
    if (cap_supported(CAP_OTP)) {
        phy_data.enabled_usb_itf |= PHY_USB_ITF_KB;
    }
    else {
        phy_data.enabled_usb_itf &= ~PHY_USB_ITF_KB;
    }
    phy_save();
#endif
    return PICOKEYS_OK;
}

bool cap_supported(uint16_t cap) {
    uint16_t supported = man_supported_usb_caps();
    if (!(supported & cap)) {
        return false;
    }
    man_config_state_t state;
    man_load_state(&state);
    bool ret = ((state.usb_enabled & supported) & cap) != 0;
    mbedtls_platform_zeroize(&state, sizeof(state));
    return ret;
}

int man_get_config(void) {
    man_config_state_t state;
    man_load_state(&state);

    uint16_t supported = man_supported_usb_caps();
    uint16_t enabled = state.usb_enabled & supported;
    file_t *ef_pin_policy = file_search_by_fid(EF_PIN_COMPLEXITY_POLICY, NULL, SPECIFY_EF);
    bool pin_complexity = file_has_data(ef_pin_policy);

    res_APDU_size = 0;
    res_APDU[res_APDU_size++] = 0; // Overall length. Filled later

    res_APDU[res_APDU_size++] = TAG_USB_SUPPORTED;
    res_APDU[res_APDU_size++] = 2;
    res_APDU[res_APDU_size++] = (uint8_t)(supported >> 8);
    res_APDU[res_APDU_size++] = (uint8_t)(supported & 0xFF);

    res_APDU[res_APDU_size++] = TAG_SERIAL;
    res_APDU[res_APDU_size++] = 4;
    memcpy(res_APDU + res_APDU_size, pico_serial.id, 4);
    res_APDU[res_APDU_size] &= ~0xFC; // Force 8-digit serial number
    res_APDU_size += 4;

    res_APDU[res_APDU_size++] = TAG_FORM_FACTOR;
    res_APDU[res_APDU_size++] = 1;
    res_APDU[res_APDU_size++] = 0x01;

    res_APDU[res_APDU_size++] = TAG_VERSION;
    res_APDU[res_APDU_size++] = 3;
    res_APDU[res_APDU_size++] = PICO_FIDO_VERSION_MAJOR;
    res_APDU[res_APDU_size++] = PICO_FIDO_VERSION_MINOR;
    res_APDU[res_APDU_size++] = 0;

    res_APDU[res_APDU_size++] = TAG_USB_ENABLED;
    res_APDU[res_APDU_size++] = 2;
    res_APDU[res_APDU_size++] = (uint8_t)(enabled >> 8);
    res_APDU[res_APDU_size++] = (uint8_t)(enabled & 0xFF);

    res_APDU[res_APDU_size++] = TAG_AUTO_EJECT_TIMEOUT;
    res_APDU[res_APDU_size++] = 2;
    res_APDU[res_APDU_size++] = (uint8_t)(state.auto_eject_timeout >> 8);
    res_APDU[res_APDU_size++] = (uint8_t)(state.auto_eject_timeout & 0xFF);

    res_APDU[res_APDU_size++] = TAG_CHALRESP_TIMEOUT;
    res_APDU[res_APDU_size++] = 1;
    res_APDU[res_APDU_size++] = state.chalresp_timeout;

    res_APDU[res_APDU_size++] = TAG_DEVICE_FLAGS;
    res_APDU[res_APDU_size++] = 1;
    res_APDU[res_APDU_size++] = state.device_flags;

    res_APDU[res_APDU_size++] = TAG_CONFIG_LOCK;
    res_APDU[res_APDU_size++] = 1;
    res_APDU[res_APDU_size++] = state.is_locked ? 0x01 : 0x00;

    res_APDU[res_APDU_size++] = TAG_PIN_COMPLEXITY;
    res_APDU[res_APDU_size++] = 1;
    res_APDU[res_APDU_size++] = pin_complexity ? 0x01 : 0x00;

    mbedtls_platform_zeroize(&state, sizeof(state));
    res_APDU[0] = (uint8_t)(res_APDU_size - 1);
    return PICOKEYS_OK;
}

static int cmd_read_config(void) {
    if (man_get_config() != PICOKEYS_OK) {
        return SW_EXEC_ERROR();
    }
    return SW_OK();
}

int man_write_config(const uint8_t *data, uint16_t len) {
    if (!data || len < 1) {
        return SW_WRONG_DATA();
    }
    uint8_t payload_len = data[0];
    if (len < (uint16_t)(1 + payload_len)) {
        return SW_WRONG_DATA();
    }

    man_config_state_t state;
    man_load_state(&state);
    uint16_t supported = man_supported_usb_caps();

    bool unlock_present = false;
    uint8_t unlock_code[MAN_LOCK_CODE_LEN] = { 0 };
    bool new_lock_present = false;
    uint8_t new_lock_code[MAN_LOCK_CODE_LEN] = { 0 };

    uint8_t *p = NULL;
    tlv_item_t item;
    tlv_ctx_t ctxi;
    tlv_ctx_init(BYTE_ARRAY((uint8_t *)(data + 1), payload_len), &ctxi);
    while (tlv_walk(&ctxi, &p, &item)) {
        switch (item.tag) {
            case TAG_USB_ENABLED:
                if (item.value.len == 1) {
                    uint16_t v = item.value.data[0];
                    state.usb_enabled = (uint16_t)((state.usb_enabled & ~supported) | (v & supported));
                }
                else if (item.value.len == 2) {
                    uint16_t v = get_uint16_be(item.value.data);
                    state.usb_enabled = (uint16_t)((state.usb_enabled & ~supported) | (v & supported));
                }
                else {
                    mbedtls_platform_zeroize(&state, sizeof(state));
                    return SW_WRONG_DATA();
                }
                break;
            case TAG_AUTO_EJECT_TIMEOUT:
                if (item.value.len == 1) {
                    state.auto_eject_timeout = item.value.data[0];
                }
                else if (item.value.len == 2) {
                    state.auto_eject_timeout = get_uint16_be(item.value.data);
                }
                else {
                    mbedtls_platform_zeroize(&state, sizeof(state));
                    return SW_WRONG_DATA();
                }
                break;
            case TAG_CHALRESP_TIMEOUT:
                if (item.value.len != 1) {
                    mbedtls_platform_zeroize(&state, sizeof(state));
                    return SW_WRONG_DATA();
                }
                state.chalresp_timeout = item.value.data[0];
                break;
            case TAG_DEVICE_FLAGS:
                if (item.value.len != 1) {
                    mbedtls_platform_zeroize(&state, sizeof(state));
                    return SW_WRONG_DATA();
                }
                state.device_flags = item.value.data[0];
                break;
            case TAG_UNLOCK:
                if (item.value.len != MAN_LOCK_CODE_LEN) {
                    mbedtls_platform_zeroize(&state, sizeof(state));
                    return SW_WRONG_DATA();
                }
                unlock_present = true;
                memcpy(unlock_code, item.value.data, MAN_LOCK_CODE_LEN);
                break;
            case TAG_CONFIG_LOCK:
                if (item.value.len != MAN_LOCK_CODE_LEN) {
                    mbedtls_platform_zeroize(&state, sizeof(state));
                    return SW_WRONG_DATA();
                }
                new_lock_present = true;
                memcpy(new_lock_code, item.value.data, MAN_LOCK_CODE_LEN);
                break;
            case TAG_NFC_ENABLED:
                if (item.value.len == 1) {
                    state.nfc_enabled = item.value.data[0];
                }
                else if (item.value.len == 2) {
                    state.nfc_enabled = get_uint16_be(item.value.data);
                }
                break;
            case TAG_NFC_RESTRICTED:
                if (item.value.len == 1) {
                    state.nfc_restricted = item.value.data[0];
                }
                break;
            case TAG_REBOOT:
                break;
            default:
                break;
        }
    }

    if (state.is_locked) {
        if (!unlock_present || mbedtls_ct_memcmp(state.lock_code, unlock_code, MAN_LOCK_CODE_LEN) != 0) {
            mbedtls_platform_zeroize(&state, sizeof(state));
            mbedtls_platform_zeroize(unlock_code, sizeof(unlock_code));
            mbedtls_platform_zeroize(new_lock_code, sizeof(new_lock_code));
            return SW_SECURITY_STATUS_NOT_SATISFIED();
        }
    }
    else if (unlock_present && man_lock_code_is_nonzero(unlock_code)) {
        mbedtls_platform_zeroize(&state, sizeof(state));
        mbedtls_platform_zeroize(unlock_code, sizeof(unlock_code));
        mbedtls_platform_zeroize(new_lock_code, sizeof(new_lock_code));
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }

    if ((state.usb_enabled & supported) == 0) {
        mbedtls_platform_zeroize(&state, sizeof(state));
        mbedtls_platform_zeroize(unlock_code, sizeof(unlock_code));
        mbedtls_platform_zeroize(new_lock_code, sizeof(new_lock_code));
        return SW_INCORRECT_PARAMS();
    }

    if (new_lock_present) {
        if (man_lock_code_is_nonzero(new_lock_code)) {
            state.is_locked = true;
            memcpy(state.lock_code, new_lock_code, MAN_LOCK_CODE_LEN);
        }
        else {
            state.is_locked = false;
            memset(state.lock_code, 0, MAN_LOCK_CODE_LEN);
        }
    }

    int save_ret = man_save_state(&state);
    mbedtls_platform_zeroize(&state, sizeof(state));
    mbedtls_platform_zeroize(unlock_code, sizeof(unlock_code));
    mbedtls_platform_zeroize(new_lock_code, sizeof(new_lock_code));
    if (save_ret != PICOKEYS_OK) {
        return SW_MEMORY_FAILURE();
    }
    return SW_OK();
}

static int cmd_write_config(void) {
    if (apdu.nc < 1 || apdu.data[0] != apdu.nc - 1) {
        return SW_WRONG_DATA();
    }
    return man_write_config(apdu.data, (uint16_t)apdu.nc);
}

int man_set_mode(const uint8_t *data, uint16_t len) {
    if (!data || len < 1) {
        return SW_WRONG_DATA();
    }
    man_config_state_t state;
    man_load_state(&state);
    if (state.is_locked) {
        mbedtls_platform_zeroize(&state, sizeof(state));
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }

    uint8_t mode_code = data[0] & 0x07;
    if (mode_code > 6) {
        mbedtls_platform_zeroize(&state, sizeof(state));
        return SW_INCORRECT_PARAMS();
    }
    // _MODES = [OTP(0), CCID(1), OTP|CCID(2), FIDO(3), OTP|FIDO(4), FIDO|CCID(5), OTP|FIDO|CCID(6)]
    bool mode_otp = (mode_code == 0 || mode_code == 2 || mode_code == 4 || mode_code == 6);
    bool mode_ccid = (mode_code == 1 || mode_code == 2 || mode_code == 5 || mode_code == 6);
    bool mode_fido = (mode_code == 3 || mode_code == 4 || mode_code == 5 || mode_code == 6);

    uint16_t new_usb = 0;
    if (mode_otp) {
        new_usb |= CAP_OTP;
    }
    if (mode_fido) {
        new_usb |= CAP_U2F | CAP_FIDO2;
    }
    if (mode_ccid) {
        new_usb |= CAP_OATH | CAP_PIV | CAP_OPENPGP | CAP_HSMAUTH;
    }

    uint16_t supported = man_supported_usb_caps();
    state.usb_enabled = (uint16_t)((state.usb_enabled & ~supported) | (new_usb & supported));
    if (data[0] & FLAG_EJECT) {
        state.device_flags |= FLAG_EJECT;
    }
    else {
        state.device_flags &= (uint8_t)~FLAG_EJECT;
    }
    if (len >= 2) {
        state.chalresp_timeout = data[1];
    }
    if (len >= 4) {
        state.auto_eject_timeout = get_uint16_le(data + 2);
    }

    int ret = man_save_state(&state);
    mbedtls_platform_zeroize(&state, sizeof(state));
    return ret == PICOKEYS_OK ? SW_OK() : SW_MEMORY_FAILURE();
}

static int cmd_set_mode(void) {
    if (P1(apdu) != 0x11) {
        return SW_INCORRECT_P1P2();
    }
    return man_set_mode(apdu.data, (uint16_t)apdu.nc);
}

extern int cbor_reset(void);
static int cmd_factory_reset(void) {
    cbor_reset();
    return SW_OK();
}

#define INS_SET_MODE                0x16
#define INS_WRITE_CONFIG            0x1C
#define INS_READ_CONFIG             0x1D
#define INS_RESET                   0x1E    // Reset device
#define INS_DEVICE_RESET            0x1F    // YubiKey device reset

static const cmd_t cmds[] = {
    { INS_SET_MODE, cmd_set_mode },
    { INS_READ_CONFIG, cmd_read_config },
    { INS_WRITE_CONFIG, cmd_write_config },
    { INS_RESET, cmd_factory_reset },
    { INS_DEVICE_RESET, cmd_factory_reset },
    { 0x00, 0x0 }
};

static int man_process_apdu(void) {
    if (CLA(apdu) != 0x00) {
        return SW_CLA_NOT_SUPPORTED();
    }
    for (const cmd_t *cmd = cmds; cmd->ins != 0x00; cmd++) {
        if (cmd->ins == INS(apdu)) {
            int r = cmd->cmd_handler();
            return r;
        }
    }
    return SW_INS_NOT_SUPPORTED();
}
