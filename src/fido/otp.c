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
#include "button.h"
#include "fido.h"
#include "apdu.h"
#include "files.h"
#include "random.h"
#include "version.h"
#include "hid/ctap_hid.h"
#include "usb.h"
#if defined(PICO_PLATFORM)
#include "bsp/board.h"
#endif
#include "tusb.h"
#include "mbedtls/aes.h"
#include "mbedtls/constant_time.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "crypto_utils.h"
#include "management.h"
#include "otp_container.h"
#include "otp_transport.h"
#include "applet_txn.h"

#define FIXED_SIZE          16
#define KEY_SIZE            16
#define UID_SIZE            6
#define KEY_SIZE_OATH       20
#define ACC_CODE_SIZE       6

#define CONFIG1_VALID       0x01
#define CONFIG2_VALID       0x02
#define CONFIG1_TOUCH       0x04
#define CONFIG2_TOUCH       0x08
#define CONFIG_LED_INV      0x10
#define CONFIG_STATUS_MASK  0x1f

#define CONFIG3_VALID       0x01
#define CONFIG4_VALID       0x02
#define CONFIG3_TOUCH       0x04
#define CONFIG4_TOUCH       0x08

/* EXT Flags */
#define SERIAL_BTN_VISIBLE  0x01    // Serial number visible at startup (button press)
#define SERIAL_USB_VISIBLE  0x02    // Serial number visible in USB iSerial field
#define SERIAL_API_VISIBLE  0x04    // Serial number visible via API call
#define USE_NUMERIC_KEYPAD  0x08    // Use numeric keypad for digits
#define FAST_TRIG           0x10    // Use fast trig if only cfg1 set
#define ALLOW_UPDATE        0x20    // Allow update of existing configuration (selected flags + access code)
#define DORMANT             0x40    // Dormant config (woken up, flag removed, requires update flag)
#define LED_INV             0x80    // LED idle state is off rather than on
#define EXTFLAG_UPDATE_MASK (SERIAL_BTN_VISIBLE | SERIAL_USB_VISIBLE | SERIAL_API_VISIBLE | \
                             USE_NUMERIC_KEYPAD | FAST_TRIG | ALLOW_UPDATE | DORMANT | LED_INV)

/* TKT Flags */
#define TAB_FIRST       0x01    // Send TAB before first part
#define APPEND_TAB1     0x02    // Send TAB after first part
#define APPEND_TAB2     0x04    // Send TAB after second part
#define APPEND_DELAY1   0x08    // Add 0.5s delay after first part
#define APPEND_DELAY2   0x10    // Add 0.5s delay after second part
#define APPEND_CR       0x20    // Append CR as final character
#define OATH_HOTP       0x40    // OATH HOTP mode
#define CHAL_RESP       0x40    // Challenge-response enabled (both must be set)
#define PROTECT_CFG2    0x80    // Block update of config 2 unless config 2 is configured and has this bit set
#define TKTFLAG_UPDATE_MASK (TAB_FIRST | APPEND_TAB1 | APPEND_TAB2 | APPEND_DELAY1 | APPEND_DELAY2 | \
                             APPEND_CR)

/* CFG Flags */
#define SEND_REF            0x01    // Send reference string (0..F) before data
#define PACING_10MS         0x04    // Add 10ms intra-key pacing
#define PACING_20MS         0x08    // Add 20ms intra-key pacing
#define STATIC_TICKET       0x20    // Static ticket generation
// Static
#define SHORT_TICKET        0x02    // Send truncated ticket (half length)
#define STRONG_PW1          0x10    // Strong password policy flag #1 (mixed case)
#define STRONG_PW2          0x40    // Strong password policy flag #2 (subtitute 0..7 to digits)
#define MAN_UPDATE          0x80    // Allow manual (local) update of static OTP
// Challenge (no keyboard)
#define HMAC_LT64           0x04    // Set when HMAC message is less than 64 bytes
#define CHAL_BTN_TRIG       0x08    // Challenge-response operation requires button press
#define CHAL_YUBICO         0x20    // Challenge-response enabled - Yubico OTP mode
#define CHAL_HMAC           0x22    // Challenge-response enabled - HMAC-SHA1
// OATH
#define OATH_HOTP8          0x02    // Generate 8 digits HOTP rather than 6 digits
#define OATH_FIXED_MODHEX1  0x10    // First byte in fixed part sent as modhex
#define OATH_FIXED_MODHEX2  0x40    // First two bytes in fixed part sent as modhex
#define OATH_FIXED_MODHEX   0x50    // Fixed part sent as modhex
#define OATH_FIXED_MASK     0x50    // Mask to get out fixed flags
#define CFGFLAG_UPDATE_MASK (PACING_10MS | PACING_20MS)

static uint8_t config_seq = { 1 };
static applet_txn_t otp_txn = APPLET_TXN_INITIALIZER(EF_OTP_TXN);

static int otp_storage_finish(int ret, bool own_transaction) {
    if (ret != PICOKEYS_OK) {
        applet_txn_fail(&otp_txn);
        return ret;
    }
    return !own_transaction || applet_txn_commit(&otp_txn) ? PICOKEYS_OK : PICOKEYS_ERR_MEMORY_FATAL;
}

PACK(
typedef struct otp_config {
    uint8_t fixed_data[FIXED_SIZE];
    uint8_t uid[UID_SIZE];
    uint8_t aes_key[KEY_SIZE];
    uint8_t acc_code[ACC_CODE_SIZE];
    uint8_t fixed_size;
    uint8_t ext_flags;
    uint8_t tkt_flags;
    uint8_t cfg_flags;
    uint8_t rfu[2];
    uint16_t crc;
}) otp_config_t;

#define otp_config_size sizeof(otp_config_t)
#define OTP_SLOT_FORMAT_V1 1
#define OTP_SLOT_PLAIN_MAX (otp_config_size + 8)
#define OTP_SLOT_SECURE_OVERHEAD (sizeof(otp_slot_magic) + 1 + 12 + 16)
#define OTP_BUMP_TRIES 3u
#define OTP_SLOT_METADATA_VERSION 1u
static uint16_t otp_status(bool is_otp);
static int otp_process_apdu(void);
static int otp_unload(void);
static const uint8_t otp_slot_magic[] = { 'P', 'K', 'O', 'T', 'P' };
static const uint8_t otp_slot_metadata_magic[] = { 'P', 'K', 'T', 'M' };

PACK(
typedef struct otp_slot_metadata {
    uint8_t magic[sizeof(otp_slot_metadata_magic)];
    uint8_t version;
    uint8_t fixed_size;
    uint8_t ext_flags;
    uint8_t tkt_flags;
    uint8_t cfg_flags;
}) otp_slot_metadata_t;

static bool otp_slot_is_secure(const uint8_t *data, size_t len) {
    return data != NULL && len >= OTP_SLOT_SECURE_OVERHEAD + otp_config_size &&
           memcmp(data, otp_slot_magic, sizeof(otp_slot_magic)) == 0 &&
           data[sizeof(otp_slot_magic)] == OTP_SLOT_FORMAT_V1;
}

static int otp_slot_derive_key(uint16_t fid, uint8_t key[32]) {
    const uint8_t info[] = {
        'O', 'T', 'P', '/', 'S', 'L', 'O', 'T',
        (uint8_t)(fid >> 8), (uint8_t)fid
    };
    uint8_t kbase[32];
    derive_kbase(kbase);
    int ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), pico_serial_hash, sizeof(pico_serial_hash), kbase, sizeof(kbase), info, sizeof(info), key, 32);
    mbedtls_platform_zeroize(kbase, sizeof(kbase));
    return ret == 0 ? PICOKEYS_OK : PICOKEYS_EXEC_ERROR;
}

static int otp_slot_has_data_status(uint16_t fid, bool *present) {
    if (!present) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    file_t *ef = file_search(fid);
    if (file_has_data(ef) && !otp_container_is_marker(ef)) {
        *present = true;
        return PICOKEYS_OK;
    }
    return otp_container_has_slot_status((uint8_t)(fid - EF_OTP_SLOT1), present);
}

static bool otp_slot_has_data(uint16_t fid) {
    bool present = false;
    return otp_slot_has_data_status(fid, &present) == PICOKEYS_OK && present;
}

static int otp_slot_load(uint16_t fid, uint8_t plain[OTP_SLOT_PLAIN_MAX], uint16_t *plain_len) {
    if (plain == NULL || plain_len == NULL) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    file_t *ef = file_search(fid);
    if (file_has_data(ef) && otp_container_is_marker(ef)) {
        byte_buffer_t output = BYTE_BUFFER(plain, OTP_SLOT_PLAIN_MAX);
        int ret = otp_container_read_slot((uint8_t)(fid - EF_OTP_SLOT1), &output);
        if (ret != PICOKEYS_OK || output.len > UINT16_MAX) {
            return ret;
        }
        *plain_len = (uint16_t)output.len;
        return PICOKEYS_OK;
    }
    if (!file_has_data(ef)) {
        bool present = false;
        int ret = otp_container_has_slot_status((uint8_t)(fid - EF_OTP_SLOT1), &present);
        if (ret != PICOKEYS_OK) {
            return ret;
        }
        if (present) {
            byte_buffer_t output = BYTE_BUFFER(plain, OTP_SLOT_PLAIN_MAX);
            ret = otp_container_read_slot((uint8_t)(fid - EF_OTP_SLOT1), &output);
            if (ret != PICOKEYS_OK || output.len > UINT16_MAX) {
                return ret;
            }
            *plain_len = (uint16_t)output.len;
            return PICOKEYS_OK;
        }
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }

    const uint8_t *stored = file_get_data(ef);
    size_t stored_len = file_get_size(ef);
    if (!otp_slot_is_secure(stored, stored_len)) {
        if (stored_len != otp_config_size && stored_len != OTP_SLOT_PLAIN_MAX) {
            return PICOKEYS_WRONG_DATA;
        }
        memcpy(plain, stored, stored_len);
        *plain_len = (uint16_t)stored_len;
        return PICOKEYS_OK;
    }

    size_t decrypted_len = stored_len - OTP_SLOT_SECURE_OVERHEAD;
    if (decrypted_len != otp_config_size && decrypted_len != OTP_SLOT_PLAIN_MAX) {
        return PICOKEYS_WRONG_DATA;
    }
    uint8_t key[32];
    int ret = otp_slot_derive_key(fid, key);
    if (ret == PICOKEYS_OK) {
        ret = decrypt_with_aad(key, CONST_BYTE_ARRAY(stored + sizeof(otp_slot_magic) + 1, stored_len - sizeof(otp_slot_magic) - 1), PIN_KDF_V2, plain);
    }
    mbedtls_platform_zeroize(key, sizeof(key));
    if (ret != PICOKEYS_OK) {
        mbedtls_platform_zeroize(plain, OTP_SLOT_PLAIN_MAX);
        return PICOKEYS_EXEC_ERROR;
    }
    *plain_len = (uint16_t)decrypted_len;
    return PICOKEYS_OK;
}

static int otp_slot_store_legacy(uint16_t fid, const uint8_t *plain, uint16_t plain_len) {
    file_t *ef = file_search(fid);
    if (!ef) {
        ef = file_new(fid);
    }
    if (ef == NULL || plain == NULL || (plain_len != otp_config_size && plain_len != OTP_SLOT_PLAIN_MAX)) {
        return PICOKEYS_WRONG_DATA;
    }

    uint8_t stored[OTP_SLOT_SECURE_OVERHEAD + OTP_SLOT_PLAIN_MAX] = { 0 };
    memcpy(stored, otp_slot_magic, sizeof(otp_slot_magic));
    stored[sizeof(otp_slot_magic)] = OTP_SLOT_FORMAT_V1;
    uint8_t key[32];
    int ret = otp_slot_derive_key(fid, key);
    if (ret == PICOKEYS_OK) {
        ret = encrypt_with_aad(key, CONST_BYTE_ARRAY(plain, plain_len), PIN_KDF_V2, stored + sizeof(otp_slot_magic) + 1);
    }
    mbedtls_platform_zeroize(key, sizeof(key));
    if (ret == PICOKEYS_OK) {
        ret = file_put_data(ef, CONST_BYTE_ARRAY(stored, OTP_SLOT_SECURE_OVERHEAD + plain_len));
    }
    mbedtls_platform_zeroize(stored, sizeof(stored));
    return ret;
}

static void otp_slot_metadata_build(const uint8_t *plain, otp_slot_metadata_t *metadata) {
    const otp_config_t *config = (const otp_config_t *)plain;
    memcpy(metadata->magic, otp_slot_metadata_magic, sizeof(metadata->magic));
    metadata->version = OTP_SLOT_METADATA_VERSION;
    metadata->fixed_size = config->fixed_size;
    metadata->ext_flags = config->ext_flags;
    metadata->tkt_flags = config->tkt_flags;
    metadata->cfg_flags = config->cfg_flags;
}

static int otp_slot_store_uncommitted(uint16_t fid, const uint8_t *plain, uint16_t plain_len) {
    if (plain == NULL || (plain_len != otp_config_size && plain_len != OTP_SLOT_PLAIN_MAX)) {
        return PICOKEYS_WRONG_DATA;
    }
    file_t *ef = file_search(fid);
    if (file_has_data(ef) && !otp_container_is_marker(ef)) {
        return otp_slot_store_legacy(fid, plain, plain_len);
    }
    otp_slot_metadata_t metadata = { 0 };
    otp_slot_metadata_build(plain, &metadata);
    int ret = otp_container_write_slot((uint8_t)(fid - EF_OTP_SLOT1), plain, plain_len, (const uint8_t *)&metadata, sizeof(metadata));
    mbedtls_platform_zeroize(&metadata, sizeof(metadata));
    return ret;
}

static int otp_slot_store(uint16_t fid, const uint8_t *plain, uint16_t size) {
    if (!applet_txn_ready(&otp_txn)) return PICOKEYS_ERR_MEMORY_FATAL;
    bool own = !otp_txn.active;
    if (own && !applet_txn_begin(&otp_txn)) return PICOKEYS_ERR_MEMORY_FATAL;
    return otp_storage_finish(otp_slot_store_uncommitted(fid, plain, size), own);
}

static int otp_slot_delete(uint16_t fid) {
    bool present = false;
    int ret = otp_slot_has_data_status(fid, &present);
    if (ret != PICOKEYS_OK) {
        return ret;
    }
    if (!applet_txn_ready(&otp_txn)) return PICOKEYS_ERR_MEMORY_FATAL;
    bool own = !otp_txn.active;
    if (own && !applet_txn_begin(&otp_txn)) return PICOKEYS_ERR_MEMORY_FATAL;
    file_t *ef = file_search(fid);
    ret = present && otp_container_is_marker(ef) ? otp_container_delete_slot((uint8_t)(fid - EF_OTP_SLOT1)) :
          (ef ? file_delete(ef) : PICOKEYS_OK);
    return otp_storage_finish(ret, own);
}

static int otp_migrate_slots(void) {
    bool changed = false;
    for (uint8_t i = 0; i < 4; i++) {
        file_t *ef = file_search(EF_OTP_SLOT1 + i);
        if (!file_has_data(ef) || otp_container_is_marker(ef)) {
            continue;
        }
        bool secure = otp_slot_is_secure(file_get_data(ef), file_get_size(ef));
        uint8_t plain[OTP_SLOT_PLAIN_MAX] = { 0 };
        uint16_t plain_len = 0;
        int ret = otp_slot_load((uint16_t)(EF_OTP_SLOT1 + i), plain, &plain_len);
        if (ret == PICOKEYS_OK && !secure) {
            ret = otp_slot_store_legacy((uint16_t)(EF_OTP_SLOT1 + i), plain, plain_len);
            changed |= ret == PICOKEYS_OK;
        }
        mbedtls_platform_zeroize(plain, sizeof(plain));
        if (ret != PICOKEYS_OK) {
            return ret;
        }
    }
    if (changed) {
        flash_commit();
    }
    return PICOKEYS_OK;
}

extern int (*hid_set_report_cb)(uint8_t, uint8_t, hid_report_type_t, uint8_t const *, uint16_t);
extern uint16_t (*hid_get_report_cb)(uint8_t, uint8_t, hid_report_type_t, uint8_t *, uint16_t);

const uint8_t otp_aid[] = {
    7,
    0xa0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01
};

static int otp_select(app_t *a, uint8_t force) {
    (void) force;
    if (cap_supported(CAP_OTP)) {
#if defined(PICO_PLATFORM)
        if (get_core_num() != 1) {
            /* A USB-side SELECT must not scan, migrate or commit Flash. */
            const uint8_t status[7] = { PICO_FIDO_VERSION_MAJOR, PICO_FIDO_VERSION_MINOR,
                                       PICO_FIDO_VERSION_PATCH, 0, 0, 0, 0x20 };
            a->process_apdu = otp_process_apdu;
            a->unload = otp_unload;
            memcpy(res_APDU, status, sizeof(status));
            res_APDU_size = sizeof(status);
            apdu.ne = res_APDU_size;
            return PICOKEYS_OK;
        }
#endif
        a->process_apdu = otp_process_apdu;
        a->unload = otp_unload;
        init_otp();
        if (!applet_txn_ready(&otp_txn)) return PICOKEYS_ERR_MEMORY_FATAL;
        if (otp_slot_has_data(EF_OTP_SLOT1) || otp_slot_has_data(EF_OTP_SLOT2)) {
            if (config_seq == 0) {
                config_seq = 1;
            }
        }
        else {
            config_seq = 0;
        }
        return otp_status(false) == SW_OK() ? PICOKEYS_OK : PICOKEYS_ERR_MEMORY_FATAL;
    }
    return PICOKEYS_ERR_FILE_NOT_FOUND;
}

uint8_t modhex_tab[] =
{ 'c', 'b', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'n', 'r', 't', 'u', 'v' };
static int encode_modhex(const uint8_t *in, size_t len, uint8_t *out) {
    for (size_t l = 0; l < len; l++) {
        *out++ = modhex_tab[in[l] >> 4];
        *out++ = modhex_tab[in[l] & 0xf];
    }
    return 0;
}
static bool scanned = false;

void init_otp(void) {
#if defined(PICO_PLATFORM)
    /* HID INIT/USB callbacks run on core 0. Only the card worker can wait for
     * Flash persistence without deadlocking the USB/Flash service loop. */
    if (get_core_num() != 1) return;
#endif
    if (scanned || !applet_txn_ready(&otp_txn)) return;
    scan_all();
    if (!applet_txn_begin(&otp_txn)) return;
    if (otp_migrate_slots() != PICOKEYS_OK) {
        applet_txn_fail(&otp_txn);
        return;
    }
    for (uint8_t i = 0; i < FIDO_OTP_SLOT_COUNT; i++) {
        uint8_t data[OTP_SLOT_PLAIN_MAX] = { 0 };
        uint16_t size = 0;
        int ret = otp_slot_load((uint16_t)(EF_OTP_SLOT1 + i), data, &size);
        if (ret == PICOKEYS_ERR_FILE_NOT_FOUND) continue;
        if (ret != PICOKEYS_OK) {
            mbedtls_platform_zeroize(data, sizeof(data));
            applet_txn_fail(&otp_txn);
            return;
        }
        otp_config_t *config = (otp_config_t *)data;
        if (size == OTP_SLOT_PLAIN_MAX && !(config->tkt_flags & OATH_HOTP) &&
            !(config->cfg_flags & (SHORT_TICKET | STATIC_TICKET))) {
            uint16_t counter = get_uint16_be(data + otp_config_size);
            if (counter >= 0x7fff) ret = PICOKEYS_WRONG_DATA;
            else {
                put_uint16_be(counter + 1u, data + otp_config_size);
                ret = otp_slot_store((uint16_t)(EF_OTP_SLOT1 + i), data, size);
            }
        }
        mbedtls_platform_zeroize(data, sizeof(data));
        if (ret != PICOKEYS_OK) {
            applet_txn_fail(&otp_txn);
            return;
        }
    }
    if (otp_storage_finish(PICOKEYS_OK, true) != PICOKEYS_OK) return;
    config_seq = otp_slot_has_data(EF_OTP_SLOT1) || otp_slot_has_data(EF_OTP_SLOT2) ? 1 : 0;
    scanned = true;
}
static uint16_t calculate_crc(const uint8_t *data, size_t data_len) {
    uint16_t crc = 0xFFFF;
    for (size_t idx = 0; idx < data_len; idx++) {
        crc ^= data[idx];
        for (uint8_t i = 0; i < 8; i++) {
            uint16_t j = crc & 0x1;
            crc >>= 1;
            if (j == 1) {
                crc ^= 0x8408;
            }
        }
    }
    return crc & 0xFFFF;
}

static uint8_t session_counter[FIDO_OTP_SLOT_COUNT] = { 0 };
static int otp_button_pressed_impl(uint8_t slot) {
    init_otp();
    if (!scanned || !applet_txn_ready(&otp_txn)) return 1;
    if (!cap_supported(CAP_OTP)) {
        return 3;
    }
    if (slot < 1 || slot > FIDO_OTP_SLOT_COUNT) {
        return 1;
    }
    uint16_t slot_ef = EF_OTP_SLOT1 + slot - 1;
    bool present = false;
    if (otp_slot_has_data_status(slot_ef, &present) != PICOKEYS_OK || !present) {
        return 1;
    }
    uint8_t data[OTP_SLOT_PLAIN_MAX] = { 0 };
    uint16_t data_len = 0;
    if (otp_slot_load(slot_ef, data, &data_len) != PICOKEYS_OK) {
        return 1;
    }
    otp_config_t *otp_config = (otp_config_t *) data;
    if (otp_config->cfg_flags & CHAL_YUBICO && otp_config->tkt_flags & CHAL_RESP) {
        mbedtls_platform_zeroize(data, sizeof(data));
        return 2;
    }
#ifdef ENABLE_OATH_APP
    if (otp_config->tkt_flags & OATH_HOTP) {
        uint8_t tmp_key[KEY_SIZE_OATH + 2];
        tmp_key[0] = 0x01;
        tmp_key[1] = (otp_config->cfg_flags & OATH_HOTP8) ? 8 : 6;
        memcpy(tmp_key + 2, otp_config->aes_key, KEY_SIZE);
        memcpy(tmp_key + 2 + KEY_SIZE, otp_config->uid, KEY_SIZE_OATH - KEY_SIZE);
        uint64_t imf = 0;
        if (data_len == OTP_SLOT_PLAIN_MAX) {
            imf = get_uint64_be(data + otp_config_size);
        }
        if (imf == 0) {
            imf = (uint64_t)get_uint16_be(otp_config->uid + 4) * 16u;
        }
        if (imf == UINT64_MAX) {
            mbedtls_platform_zeroize(tmp_key, sizeof(tmp_key));
            mbedtls_platform_zeroize(data, sizeof(data));
            return 1;
        }
        uint8_t chal[8];
        put_uint64_be(imf, chal);
        res_APDU_size = 0;
        int ret = calculate_oath(1, tmp_key, sizeof(tmp_key), chal, sizeof(chal));
        mbedtls_platform_zeroize(tmp_key, sizeof(tmp_key));
        if (ret == PICOKEYS_OK) {
            uint32_t base = otp_config->cfg_flags & OATH_HOTP8 ? 100000000u : 1000000u;
            uint32_t number = get_uint32_be(res_APDU + 2);
            number %= base;
            char out_str[2 * FIXED_SIZE + 9];
            size_t out_len = 0;
            uint8_t fsize = otp_config->fixed_size <= FIXED_SIZE ? otp_config->fixed_size : 0;
            if (fsize > 0) {
                encode_modhex(otp_config->fixed_data, fsize, (uint8_t *)out_str);
                out_len = (size_t)fsize * 2u;
            }
            if (otp_config->cfg_flags & OATH_HOTP8) {
                snprintf(out_str + out_len, sizeof(out_str) - out_len, "%08lu", (long unsigned int) number);
                out_len += 8;
            }
            else {
                snprintf(out_str + out_len, sizeof(out_str) - out_len, "%06lu", (long unsigned int) number);
                out_len += 6;
            }
            imf++;
            uint8_t new_chal[8];
            put_uint64_be(imf, new_chal);
            uint8_t new_otp_config[otp_config_size + sizeof(new_chal)];
            memcpy(new_otp_config, otp_config, otp_config_size);
            memcpy(new_otp_config + otp_config_size, new_chal, sizeof(new_chal));
            int stored = otp_slot_store(slot_ef, new_otp_config, sizeof(new_otp_config));
            mbedtls_platform_zeroize(new_otp_config, sizeof(new_otp_config));
            if (stored != PICOKEYS_OK) {
                mbedtls_platform_zeroize(out_str, sizeof(out_str));
                mbedtls_platform_zeroize(data, sizeof(data));
                res_APDU_size = 0;
                return 1;
            }
            add_keyboard_buffer(CONST_BYTE_ARRAY((const uint8_t *)out_str, out_len), true);
            mbedtls_platform_zeroize(out_str, sizeof(out_str));
        }
        else {
            mbedtls_platform_zeroize(data, sizeof(data));
            return 1;
        }
        if (otp_config->tkt_flags & APPEND_CR) {
            append_keyboard_buffer(CONST_BYTE_ARRAY((const uint8_t *)"\r", 1));
        }
    }
#endif
    else if (otp_config->cfg_flags & SHORT_TICKET || otp_config->cfg_flags & STATIC_TICKET) {
        uint8_t max_size = FIXED_SIZE + UID_SIZE + KEY_SIZE;
        if (otp_config->fixed_size > 0 && otp_config->fixed_size < max_size) {
            max_size = otp_config->fixed_size;
        }
        uint8_t scancode_len = 0;
        while (scancode_len < max_size && otp_config->fixed_data[scancode_len] != 0) {
            scancode_len++;
        }
        add_keyboard_buffer(CONST_BYTE_ARRAY(otp_config->fixed_data, scancode_len), false);
        if (otp_config->tkt_flags & APPEND_CR) {
            append_keyboard_buffer(CONST_BYTE_ARRAY((const uint8_t *)"\x28", 1));
        }
    }
    else {
        uint8_t fsize = otp_config->fixed_size <= FIXED_SIZE ? otp_config->fixed_size : 6;
        uint8_t otpk[FIXED_SIZE + 16];
        uint8_t *po = otpk;
        bool update_counter = false;
        uint16_t counter = data_len == OTP_SLOT_PLAIN_MAX ? get_uint16_be(data + otp_config_size) : 0;
        uint16_t crc = 0;
        uint32_t ts = board_millis() / 1000;
        if (counter > 0x7fff || (counter == 0x7fff && session_counter[slot - 1] == UINT8_MAX)) {
            mbedtls_platform_zeroize(data, sizeof(data));
            return 1;
        }
        if (counter == 0) {
            update_counter = true;
            counter = 1;
        }
        if (fsize > 0) {
            memcpy(po, otp_config->fixed_data, fsize);
            po += fsize;
        }
        uint8_t *enc_block = po;
        memcpy(po, otp_config->uid, UID_SIZE);
        po += UID_SIZE;
        po += put_uint16_le(counter, po);
        ts >>= 1;
        *po++ = (uint8_t)(ts & 0xffu);
        *po++ = (uint8_t)(ts >> 8);
        *po++ = (uint8_t)(ts >> 16);
        *po++ = session_counter[slot - 1];
        random_fill_buffer(BYTE_ARRAY(po, 2));
        po += 2;
        crc = calculate_crc(enc_block, 14);
        po += put_uint16_le(~crc, po);
        mbedtls_aes_context ctx;
        mbedtls_aes_init(&ctx);
        mbedtls_aes_setkey_enc(&ctx, otp_config->aes_key, 128);
        mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, enc_block, enc_block);
        mbedtls_aes_free(&ctx);
        uint8_t otp_out[2 * (FIXED_SIZE + 16)];
        size_t total_raw = (size_t)fsize + 16u;
        encode_modhex(otpk, total_raw, otp_out);
        mbedtls_platform_zeroize(otpk, sizeof(otpk));
        uint8_t next_session_counter = (uint8_t)(session_counter[slot - 1] + 1);
        if (next_session_counter == 0) {
            if (++counter <= 0x7fff) {
                update_counter = true;
            }
        }
        if (update_counter == true) {
            uint8_t new_data[OTP_SLOT_PLAIN_MAX] = { 0 };
            memcpy(new_data, data, data_len);
            put_uint16_be(counter, new_data + otp_config_size);
            if (otp_slot_store(slot_ef, new_data, sizeof(new_data)) != PICOKEYS_OK) {
                mbedtls_platform_zeroize(new_data, sizeof(new_data));
                mbedtls_platform_zeroize(otp_out, sizeof(otp_out));
                mbedtls_platform_zeroize(data, sizeof(data));
                return 1;
            }
            mbedtls_platform_zeroize(new_data, sizeof(new_data));
        }
        session_counter[slot - 1] = next_session_counter;
        add_keyboard_buffer(CONST_BYTE_ARRAY((const uint8_t *)otp_out, total_raw * 2u), true);
        if (otp_config->tkt_flags & APPEND_CR) {
            append_keyboard_buffer(CONST_BYTE_ARRAY((const uint8_t *)"\r", 1));
        }
    }

    mbedtls_platform_zeroize(data, sizeof(data));
    return 0;
}

static int otp_button_pressed(uint8_t slot) {
#ifndef ENABLE_EMULATION
    if (slot == 1 && button_pressed_duration >= 1500) slot = 2;
#endif
    return otp_hid_queue_button(slot);
}

int otp_hid_button(uint8_t slot) {
    uint8_t response[64] = {0};
    apdu = (struct apdu){.rdata=response, .ne=sizeof(response)};
    int result = otp_button_pressed_impl(slot);
    apdu = (struct apdu){0};
    return result;
}

INITIALIZER( otp_ctor ) {
    register_app(otp_select, otp_aid);
    button_pressed_cb = otp_button_pressed;
    hid_set_report_cb = otp_hid_set_report_cb;
    hid_get_report_cb = otp_hid_get_report_cb;
}

static int otp_unload(void) {
    return PICOKEYS_OK;
}

uint8_t status_byte = 0x0;
static uint16_t otp_status_ext(void) {
    for (uint8_t i = 0; i < 4; i++) {
        uint16_t fid = (uint16_t)(EF_OTP_SLOT1 + i);
        if (otp_slot_has_data(fid)) {
            uint8_t data[OTP_SLOT_PLAIN_MAX] = { 0 };
            uint16_t data_len = 0;
            if (otp_slot_load(fid, data, &data_len) != PICOKEYS_OK) {
                continue;
            }
            res_APDU[res_APDU_size++] = (uint8_t)(0xB0u + i);
            res_APDU[res_APDU_size++] = 0; // Filled later
            uint8_t *p = res_APDU + res_APDU_size;
            otp_config_t *otp_config = (otp_config_t *)data;
            *p++ = 0xA0;
            *p++ = 2;
            *p++ = otp_config->tkt_flags;
            *p++ = otp_config->cfg_flags;
            if (otp_config->cfg_flags & CHAL_YUBICO && otp_config->tkt_flags & CHAL_RESP) {

            }
            else if (otp_config->tkt_flags & OATH_HOTP) {
            }
            else if (otp_config->cfg_flags & SHORT_TICKET || otp_config->cfg_flags & STATIC_TICKET) {
            }
            else {
                *p++ = 0xC0;
                *p++ = 6;
                memcpy(p, otp_config->fixed_data, 6);
                p += 6;
            }
            size_t response_len = (size_t)(p - (res_APDU + res_APDU_size));
            uint8_t len = (uint8_t)response_len;
            res_APDU[res_APDU_size - 1] = len;
            res_APDU_size += len;
            mbedtls_platform_zeroize(data, sizeof(data));
        }
    }
    return SW_OK();
}

void otp_hid_refresh_status(void) {
    uint8_t snapshot[8] = {0};
    uint16_t used = 1;
    snapshot[1] = PICO_FIDO_VERSION_MAJOR;
    snapshot[2] = PICO_FIDO_VERSION_MINOR;
    snapshot[3] = PICO_FIDO_VERSION_PATCH;
#if defined(PICO_PLATFORM)
    if (get_core_num() != 1) {
        snapshot[7] = 0x20;
        otp_hid_update_status(snapshot);
        return;
    }
#endif
    init_otp();
    if (!scanned || !applet_txn_ready(&otp_txn)) {
        snapshot[7] = 0x10;
        otp_hid_update_status(snapshot);
        return;
    }
    snapshot[used++] = PICO_FIDO_VERSION_MAJOR;
    snapshot[used++] = PICO_FIDO_VERSION_MINOR;
    snapshot[used++] = PICO_FIDO_VERSION_PATCH;
    snapshot[used++] = config_seq;
    uint8_t opts = 0;
    if (otp_slot_has_data(EF_OTP_SLOT1)) {
        uint8_t data[OTP_SLOT_PLAIN_MAX] = { 0 };
        uint16_t data_len = 0;
        if (otp_slot_load(EF_OTP_SLOT1, data, &data_len) == PICOKEYS_OK) {
            opts |= CONFIG1_VALID;
            otp_config_t *otp_config = (otp_config_t *)data;
            if (!((otp_config->tkt_flags & CHAL_RESP) && (otp_config->cfg_flags & CHAL_YUBICO)) || (otp_config->cfg_flags & CHAL_BTN_TRIG)) {
                opts |= CONFIG1_TOUCH;
            }
        }
        mbedtls_platform_zeroize(data, sizeof(data));
    }
    if (otp_slot_has_data(EF_OTP_SLOT2)) {
        uint8_t data[OTP_SLOT_PLAIN_MAX] = { 0 };
        uint16_t data_len = 0;
        if (otp_slot_load(EF_OTP_SLOT2, data, &data_len) == PICOKEYS_OK) {
            opts |= CONFIG2_VALID;
            otp_config_t *otp_config = (otp_config_t *)data;
            if (!((otp_config->tkt_flags & CHAL_RESP) && (otp_config->cfg_flags & CHAL_YUBICO)) || (otp_config->cfg_flags & CHAL_BTN_TRIG)) {
                opts |= CONFIG2_TOUCH;
            }
        }
        mbedtls_platform_zeroize(data, sizeof(data));
    }
    snapshot[used++] = opts;
    snapshot[used++] = 0;
    snapshot[used++] = status_byte;
    otp_hid_update_status(snapshot);
}

static uint16_t otp_status(bool is_otp) {
    if (!scanned || !applet_txn_ready(&otp_txn)) return SW_MEMORY_FAILURE();
    /* Build the snapshot without borrowing the active request's APDU pointers. */
    otp_hid_refresh_status();
    uint8_t snapshot[8];
    /* Worker-owned refresh publishes a snapshot; the getter is USB-only. */
    otp_hid_copy_status(snapshot);
    memcpy(res_APDU, snapshot + (is_otp ? 0 : 1), is_otp ? 8 : 7);
    res_APDU_size = is_otp ? 0 : 7;
    if (!is_otp) apdu.ne = res_APDU_size;
    return SW_OK();
}

static bool check_crc(const otp_config_t *data) {
    uint16_t crc = calculate_crc((const uint8_t *) data, otp_config_size);
    return crc == 0xF0B8;
}

static bool otp_slot_offset_valid(uint8_t p1, uint8_t p2) {
    if (p1 == 0x01 || p1 == 0x04 || p1 == 0x20 || p1 == 0x30) {
        return p2 <= 3;
    }
    return p2 == 0;
}

bool _is_otp = false;
static int cmd_otp(void) {
    uint8_t p1 = P1(apdu), p2 = P2(apdu);
    if (p1 == 0x01 || p1 == 0x03) { // Configure slot
        if (apdu.nc < otp_config_size) {
            return SW_WRONG_LENGTH();
        }
        otp_config_t *odata = (otp_config_t *) apdu.data;
        if (!otp_slot_offset_valid(p1, p2)) {
            return SW_INCORRECT_P1P2();
        }
        uint16_t slot = (p1 == 0x01 ? EF_OTP_SLOT1 : EF_OTP_SLOT2) + p2;
        bool present = false;
        int ret = otp_slot_has_data_status(slot, &present);
        if (ret != PICOKEYS_OK) {
            return SW_MEMORY_FAILURE();
        }
        if (present) {
            if (apdu.nc < otp_config_size + ACC_CODE_SIZE) {
                return SW_WRONG_LENGTH();
            }
            uint8_t current[OTP_SLOT_PLAIN_MAX] = { 0 };
            uint16_t current_len = 0;
            if (otp_slot_load(slot, current, &current_len) != PICOKEYS_OK) {
                return SW_MEMORY_FAILURE();
            }
            otp_config_t *otpc = (otp_config_t *)current;
            if (mbedtls_ct_memcmp(otpc->acc_code, apdu.data + otp_config_size, ACC_CODE_SIZE) != 0) {
                mbedtls_platform_zeroize(current, sizeof(current));
                return SW_SECURITY_STATUS_NOT_SATISFIED();
            }
            mbedtls_platform_zeroize(current, sizeof(current));
        }
        for (size_t c = 0; c < otp_config_size; c++) {
            if (apdu.data[c] != 0) {
                if (odata->rfu[0] != 0 || odata->rfu[1] != 0 || check_crc(odata) == false) {
                    return SW_WRONG_DATA();
                }
                uint8_t configured[OTP_SLOT_PLAIN_MAX] = { 0 };
                memcpy(configured, apdu.data, otp_config_size);
                int stored = otp_slot_store(slot, configured, sizeof(configured));
                mbedtls_platform_zeroize(configured, sizeof(configured));
                if (stored != PICOKEYS_OK) {
                    return SW_MEMORY_FAILURE();
                }
                session_counter[slot - EF_OTP_SLOT1] = 0;
                config_seq++;
                return otp_status(_is_otp);
            }
        }
        // Delete slot
        if (otp_slot_delete(slot) != PICOKEYS_OK) {
            return SW_MEMORY_FAILURE();
        }
        if (!otp_slot_has_data(EF_OTP_SLOT1) && !otp_slot_has_data(EF_OTP_SLOT2)) {
            config_seq = 0;
        }
        else {
            config_seq++;
        }
        return otp_status(_is_otp);
    }
    else if (p1 == 0x04 || p1 == 0x05) { // Update slot
        if (apdu.nc < otp_config_size) {
            return SW_WRONG_LENGTH();
        }
        otp_config_t *odata = (otp_config_t *) apdu.data;
        if (!otp_slot_offset_valid(p1, p2)) {
            return SW_INCORRECT_P1P2();
        }
        uint16_t slot = (p1 == 0x04 ? EF_OTP_SLOT1 : EF_OTP_SLOT2) + p2;
        if (odata->rfu[0] != 0 || odata->rfu[1] != 0 || check_crc(odata) == false) {
            return SW_WRONG_DATA();
        }
        bool present = false;
        int ret = otp_slot_has_data_status(slot, &present);
        if (ret != PICOKEYS_OK) {
            return SW_MEMORY_FAILURE();
        }
        if (present) {
            if (apdu.nc < otp_config_size + ACC_CODE_SIZE) {
                return SW_WRONG_LENGTH();
            }
            uint8_t current[OTP_SLOT_PLAIN_MAX] = { 0 };
            uint16_t current_len = 0;
            if (otp_slot_load(slot, current, &current_len) != PICOKEYS_OK) {
                return SW_MEMORY_FAILURE();
            }
            otp_config_t *otpc = (otp_config_t *)current;
            if (mbedtls_ct_memcmp(otpc->acc_code, apdu.data + otp_config_size, ACC_CODE_SIZE) != 0) {
                mbedtls_platform_zeroize(current, sizeof(current));
                return SW_SECURITY_STATUS_NOT_SATISFIED();
            }
            memcpy(apdu.data, current, FIXED_SIZE + UID_SIZE + KEY_SIZE);
            odata->fixed_size = otpc->fixed_size;
            odata->ext_flags = (otpc->ext_flags & ~EXTFLAG_UPDATE_MASK) |
                               (odata->ext_flags & EXTFLAG_UPDATE_MASK);
            odata->tkt_flags = (otpc->tkt_flags & ~TKTFLAG_UPDATE_MASK) |
                               (odata->tkt_flags & TKTFLAG_UPDATE_MASK);
            if (!((otpc->tkt_flags & CHAL_RESP) && (otpc->cfg_flags & CHAL_YUBICO))) {
                odata->cfg_flags = (otpc->cfg_flags & ~CFGFLAG_UPDATE_MASK) |
                                   (odata->cfg_flags & CFGFLAG_UPDATE_MASK);
            }
            else {
                odata->cfg_flags = otpc->cfg_flags;
            }
            uint16_t new_crc = calculate_crc((const uint8_t *)odata, otp_config_size - sizeof(uint16_t));
            odata->crc = (uint16_t)~new_crc;
            memcpy(current, apdu.data, otp_config_size);
            if (otp_slot_store(slot, current, current_len) != PICOKEYS_OK) {
                mbedtls_platform_zeroize(current, sizeof(current));
                return SW_MEMORY_FAILURE();
            }
            mbedtls_platform_zeroize(current, sizeof(current));
            config_seq++;
        }
        return otp_status(_is_otp);
    }
    else if (p1 == 0x06) { // Swap slots
        uint8_t data1[OTP_SLOT_PLAIN_MAX] = { 0 };
        uint8_t data2[OTP_SLOT_PLAIN_MAX] = { 0 };
        uint16_t len1 = 0, len2 = 0;
        bool ef1_data = false, ef2_data = false;
        uint16_t slot1 = EF_OTP_SLOT1, slot2 = EF_OTP_SLOT2;
        uint8_t access_code[ACC_CODE_SIZE] = { 0 };
        if (_is_otp) {
            if (apdu.nc != 64) {
                return SW_WRONG_LENGTH();
            }
            for (size_t i = 2 + ACC_CODE_SIZE; i < apdu.nc; i++) {
                if (apdu.data[i] != 0) {
                    return SW_WRONG_DATA();
                }
            }
            slot1 += apdu.data[0];
            slot2 += apdu.data[1];
            memcpy(access_code, apdu.data + 2, sizeof(access_code));
        }
        else if (apdu.nc != 0) {
            if (apdu.nc == ACC_CODE_SIZE) {
                memcpy(access_code, apdu.data, sizeof(access_code));
            }
            else if (apdu.nc == otp_config_size + ACC_CODE_SIZE) {
                memcpy(access_code, apdu.data + otp_config_size, sizeof(access_code));
            }
            else if (apdu.nc == 2 || apdu.nc == 2 + ACC_CODE_SIZE) {
                slot1 += apdu.data[0];
                slot2 += apdu.data[1];
                if (apdu.nc == 2 + ACC_CODE_SIZE) {
                    memcpy(access_code, apdu.data + 2, sizeof(access_code));
                }
            }
            else {
                return SW_WRONG_LENGTH();
            }
        }
        if (slot1 > EF_OTP_SLOT1 + 3 || slot2 > EF_OTP_SLOT1 + 3 || slot1 == slot2) {
            mbedtls_platform_zeroize(access_code, sizeof(access_code));
            return SW_INCORRECT_P1P2();
        }
        file_t *ef1 = file_search(slot1);
        file_t *ef2 = file_search(slot2);
        int ret = otp_slot_has_data_status(slot1, &ef1_data);
        if (ret != PICOKEYS_OK) {
            mbedtls_platform_zeroize(data1, sizeof(data1));
            mbedtls_platform_zeroize(data2, sizeof(data2));
            mbedtls_platform_zeroize(access_code, sizeof(access_code));
            return SW_MEMORY_FAILURE();
        }
        if (ef1_data) {
            if (otp_slot_load(slot1, data1, &len1) != PICOKEYS_OK) {
                mbedtls_platform_zeroize(data1, sizeof(data1));
                mbedtls_platform_zeroize(access_code, sizeof(access_code));
                return SW_MEMORY_FAILURE();
            }
            if (mbedtls_ct_memcmp(((otp_config_t *)data1)->acc_code, access_code, sizeof(access_code)) != 0) {
                mbedtls_platform_zeroize(data1, sizeof(data1));
                mbedtls_platform_zeroize(access_code, sizeof(access_code));
                return SW_SECURITY_STATUS_NOT_SATISFIED();
            }
        }
        ret = otp_slot_has_data_status(slot2, &ef2_data);
        if (ret != PICOKEYS_OK) {
            mbedtls_platform_zeroize(data1, sizeof(data1));
            mbedtls_platform_zeroize(data2, sizeof(data2));
            mbedtls_platform_zeroize(access_code, sizeof(access_code));
            return SW_MEMORY_FAILURE();
        }
        if (ef2_data) {
            if (otp_slot_load(slot2, data2, &len2) != PICOKEYS_OK) {
                mbedtls_platform_zeroize(data1, sizeof(data1));
                mbedtls_platform_zeroize(access_code, sizeof(access_code));
                return SW_MEMORY_FAILURE();
            }
            if (mbedtls_ct_memcmp(((otp_config_t *)data2)->acc_code, access_code, sizeof(access_code)) != 0) {
                mbedtls_platform_zeroize(data1, sizeof(data1));
                mbedtls_platform_zeroize(data2, sizeof(data2));
                mbedtls_platform_zeroize(access_code, sizeof(access_code));
                return SW_SECURITY_STATUS_NOT_SATISFIED();
            }
        }
        if (!applet_txn_begin(&otp_txn)) {
            mbedtls_platform_zeroize(data1, sizeof(data1));
            mbedtls_platform_zeroize(data2, sizeof(data2));
            mbedtls_platform_zeroize(access_code, sizeof(access_code));
            return SW_MEMORY_FAILURE();
        }
        bool legacy1 = file_has_data(ef1) && !otp_container_is_marker(ef1);
        bool legacy2 = file_has_data(ef2) && !otp_container_is_marker(ef2);
        if (!legacy1 && !legacy2 && (ef1_data || ef2_data)) {
            otp_slot_metadata_t metadata1 = { 0 };
            otp_slot_metadata_t metadata2 = { 0 };
            if (ef1_data) {
                otp_slot_metadata_build(data1, &metadata1);
            }
            if (ef2_data) {
                otp_slot_metadata_build(data2, &metadata2);
            }
            ret = otp_container_swap_slots((uint8_t)(slot1 - EF_OTP_SLOT1), ef1_data, data1, len1, (const uint8_t *)&metadata1, sizeof(metadata1), (uint8_t)(slot2 - EF_OTP_SLOT1), ef2_data, data2, len2, (const uint8_t *)&metadata2, sizeof(metadata2));
            mbedtls_platform_zeroize(&metadata1, sizeof(metadata1));
            mbedtls_platform_zeroize(&metadata2, sizeof(metadata2));
            mbedtls_platform_zeroize(data1, sizeof(data1));
            mbedtls_platform_zeroize(data2, sizeof(data2));
            mbedtls_platform_zeroize(access_code, sizeof(access_code));
            if (otp_storage_finish(ret, true) != PICOKEYS_OK) return SW_MEMORY_FAILURE();
            uint8_t session = session_counter[slot1 - EF_OTP_SLOT1];
            session_counter[slot1 - EF_OTP_SLOT1] = session_counter[slot2 - EF_OTP_SLOT1];
            session_counter[slot2 - EF_OTP_SLOT1] = session;
            config_seq++;
            return otp_status(_is_otp);
        }
        if (ef2_data) {
            if (otp_slot_store(slot1, data2, len2) != PICOKEYS_OK) {
                mbedtls_platform_zeroize(data1, sizeof(data1));
                mbedtls_platform_zeroize(data2, sizeof(data2));
                mbedtls_platform_zeroize(access_code, sizeof(access_code));
                return SW_MEMORY_FAILURE();
            }
        }
        else {
            if (otp_slot_delete(slot1) != PICOKEYS_OK) {
                mbedtls_platform_zeroize(data1, sizeof(data1));
                mbedtls_platform_zeroize(data2, sizeof(data2));
                mbedtls_platform_zeroize(access_code, sizeof(access_code));
                return SW_MEMORY_FAILURE();
            }
        }
        if (ef1_data) {
            if (otp_slot_store(slot2, data1, len1) != PICOKEYS_OK) {
                mbedtls_platform_zeroize(data1, sizeof(data1));
                mbedtls_platform_zeroize(data2, sizeof(data2));
                mbedtls_platform_zeroize(access_code, sizeof(access_code));
                return SW_MEMORY_FAILURE();
            }
        }
        else if (ef2_data) {
            if (otp_slot_delete(slot2) != PICOKEYS_OK) {
                mbedtls_platform_zeroize(data1, sizeof(data1));
                mbedtls_platform_zeroize(data2, sizeof(data2));
                mbedtls_platform_zeroize(access_code, sizeof(access_code));
                return SW_MEMORY_FAILURE();
            }
        }
        mbedtls_platform_zeroize(data1, sizeof(data1));
        mbedtls_platform_zeroize(data2, sizeof(data2));
        mbedtls_platform_zeroize(access_code, sizeof(access_code));
        if (otp_storage_finish(PICOKEYS_OK, true) != PICOKEYS_OK) return SW_MEMORY_FAILURE();
        uint8_t session = session_counter[slot1 - EF_OTP_SLOT1];
        session_counter[slot1 - EF_OTP_SLOT1] = session_counter[slot2 - EF_OTP_SLOT1];
        session_counter[slot2 - EF_OTP_SLOT1] = session;
        config_seq++;
        return otp_status(_is_otp);
    }
    else if (p1 == 0x08 || p1 == 0x09) { // Configure NDEF (Slot 1 / Slot 2)
        uint16_t slot = (p1 == 0x08) ? EF_OTP_SLOT1 : EF_OTP_SLOT2;
        bool present = false;
        if (otp_slot_has_data_status(slot, &present) != PICOKEYS_OK) {
            return SW_MEMORY_FAILURE();
        }
        if (present) {
            if (apdu.nc >= 54 + ACC_CODE_SIZE) {
                uint8_t current[OTP_SLOT_PLAIN_MAX] = { 0 };
                uint16_t current_len = 0;
                if (otp_slot_load(slot, current, &current_len) != PICOKEYS_OK) {
                    return SW_MEMORY_FAILURE();
                }
                otp_config_t *otpc = (otp_config_t *)current;
                if (mbedtls_ct_memcmp(otpc->acc_code, apdu.data + 54, ACC_CODE_SIZE) != 0) {
                    mbedtls_platform_zeroize(current, sizeof(current));
                    return SW_SECURITY_STATUS_NOT_SATISFIED();
                }
                mbedtls_platform_zeroize(current, sizeof(current));
            }
            config_seq++;
        }
        return otp_status(_is_otp);
    }
    else if (p1 == 0x12) { // Update scan map
        config_seq++;
        return otp_status(_is_otp);
    }
    else if (p1 == 0x10) {
        memcpy(res_APDU, pico_serial.id, 4);
        res_APDU[0] &= ~0xFC; // Force 8-digit serial number
        res_APDU_size = 4;
    }
    else if (p1 == 0x11) { // Set device mode
        int ret = man_set_mode(apdu.data, (uint16_t)apdu.nc);
        if (ret != 0x9000) {
            return (uint16_t)ret;
        }
        return otp_status(_is_otp);
    }
    else if (p1 == 0x13) { // Get config
        man_get_config();
    }
    else if (p1 == 0x15) { // Write config
        int ret = man_write_config(apdu.data, (uint16_t)apdu.nc);
        if (ret != 0x9000) {
            return (uint16_t)ret;
        }
        return otp_status(_is_otp);
    }
    else if (p1 == 0x14) {
        otp_status_ext();
    }
    else if (p1 == 0x30 || p1 == 0x38 || p1 == 0x20 || p1 == 0x28) { // Calculate OTP
        if (!otp_slot_offset_valid(p1, p2)) {
            return SW_INCORRECT_P1P2();
        }
        uint16_t slot = (p1 == 0x30 || p1 == 0x20 ? EF_OTP_SLOT1 : EF_OTP_SLOT2) + p2;
        bool present = false;
        if (otp_slot_has_data_status(slot, &present) != PICOKEYS_OK) {
            return SW_MEMORY_FAILURE();
        }
        if (present) {
            uint8_t data[OTP_SLOT_PLAIN_MAX] = { 0 };
            uint16_t data_len = 0;
            if (otp_slot_load(slot, data, &data_len) != PICOKEYS_OK) {
                return SW_MEMORY_FAILURE();
            }
            otp_config_t *otp_config = (otp_config_t *)data;
            if (!(otp_config->tkt_flags & CHAL_RESP)) {
                mbedtls_platform_zeroize(data, sizeof(data));
                return SW_WRONG_DATA();
            }
            int ret = 0;
            uint8_t *rdata_bk = apdu.rdata;
            if (otp_config->cfg_flags & CHAL_BTN_TRIG) {
                status_byte = 0x20;
                otp_status(_is_otp);
#ifndef ENABLE_EMULATION
                if (wait_button_pressed()) {
                    status_byte = 0x00;
                    otp_status(_is_otp);
                    mbedtls_platform_zeroize(data, sizeof(data));
                    return SW_CONDITIONS_NOT_SATISFIED();
                }
#endif
                status_byte = 0x10;
                apdu.rdata = rdata_bk;
            }
            if (p1 == 0x30 || p1 == 0x38) {
                if (apdu.nc < 64) {
                    mbedtls_platform_zeroize(data, sizeof(data));
                    return SW_WRONG_LENGTH();
                }
                if (!(otp_config->cfg_flags & CHAL_HMAC)) {
                    mbedtls_platform_zeroize(data, sizeof(data));
                    return SW_WRONG_DATA();
                }
                uint8_t aes_key[KEY_SIZE + UID_SIZE];
                memcpy(aes_key, otp_config->aes_key, KEY_SIZE);
                memcpy(aes_key + KEY_SIZE, otp_config->uid, UID_SIZE);
                uint8_t chal_len = 64;
                if (otp_config->cfg_flags & HMAC_LT64) {
                    while (chal_len > 0 && apdu.data[63] == apdu.data[chal_len - 1]) {
                        chal_len--;
                    }
                }
                mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), aes_key, sizeof(aes_key), apdu.data, chal_len, res_APDU);
                mbedtls_platform_zeroize(aes_key, sizeof(aes_key));
                if (ret == 0) {
                    res_APDU_size = 20;
                }
            }
            else if (p1 == 0x20 || p1 == 0x28) {
                if (apdu.nc < 6) {
                    mbedtls_platform_zeroize(data, sizeof(data));
                    return SW_WRONG_LENGTH();
                }
                if (!(otp_config->cfg_flags & CHAL_YUBICO)) {
                    mbedtls_platform_zeroize(data, sizeof(data));
                    return SW_WRONG_DATA();
                }
                uint8_t challenge[16];
                memcpy(challenge, apdu.data, 6);
                memcpy(challenge + 6, pico_serial_str, 10);
                mbedtls_aes_context ctx;
                mbedtls_aes_init(&ctx);
                mbedtls_aes_setkey_enc(&ctx, otp_config->aes_key, 128);
                ret = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, challenge, res_APDU);
                mbedtls_aes_free(&ctx);
                if (ret == 0) {
                    res_APDU_size = 16;
                }
            }
            if (ret == 0) {
                status_byte = 0x00;
            }
            mbedtls_platform_zeroize(data, sizeof(data));
        }
    }
    return SW_OK();
}

static int cmd_otp_status(void) {
    return otp_status(false);
}

#define INS_OTP             0x01
#define INS_YK2_STATUS      0x03

static const cmd_t cmds[] = {
    { INS_OTP, cmd_otp },
    { INS_YK2_STATUS, cmd_otp_status },
    { 0x00, 0x0 }
};

static int otp_process_apdu(void) {
    bool ready = applet_txn_ready(&otp_txn);
    if (!ready && CLA(apdu) == 0 && INS(apdu) == 0x04 && P1(apdu) == 0xde && P2(apdu) == 0xad && apdu.nc == 0) {
        bool prior_force = force_button_wait;
        force_button_wait = true;
        bool touched = wait_button_pressed_timeout(15) == 0;
        force_button_wait = prior_force;
        if (!touched) return SW_SECURITY_STATUS_NOT_SATISFIED();
        if (!applet_txn_recover_begin(&otp_txn)) return SW_MEMORY_FAILURE();
        if (otp_storage_finish(otp_container_purge(), true) != PICOKEYS_OK) return SW_MEMORY_FAILURE();
        memset(session_counter, 0, sizeof(session_counter));
        config_seq = 0;
        scanned = true;
        return SW_OK();
    }
    if (!ready) return SW_MEMORY_FAILURE();
    init_otp();
    if (!scanned || !applet_txn_ready(&otp_txn)) return SW_MEMORY_FAILURE();
    if (CLA(apdu) != 0x00) {
        return SW_CLA_NOT_SUPPORTED();
    }
    if (cap_supported(CAP_OTP)) {
        for (const cmd_t *cmd = cmds; cmd->ins != 0x00; cmd++) {
            if (cmd->ins == INS(apdu)) {
                int r = cmd->cmd_handler();
                return r;
            }
        }
    }
    return SW_INS_NOT_SUPPORTED();
}

int otp_hid_command(uint8_t command, const uint8_t request[64], uint8_t response[70], size_t *response_len) {
    uint8_t header[4] = {0, INS_OTP, command, 0};
    apdu = (struct apdu){.header=header, .data=(uint8_t *)request, .nc=64, .rdata=response, .ne=68};
    _is_otp = true;
    int result = otp_process_apdu();
    _is_otp = false;
    *response_len = apdu.rlen;
    /* Do not retain the address of a stack-local header or response buffer. */
    apdu = (struct apdu){0};
    return result;
}
