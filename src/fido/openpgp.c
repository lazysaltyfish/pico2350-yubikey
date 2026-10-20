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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "picokeys.h"
#include "apdu.h"
#include "files.h"
#include "applet_storage.h"
#include "applet_txn.h"
#include "random.h"
#include "serial.h"
#include "crypto_utils.h"
#include "management.h"
#include "fido.h"
#include "button.h"
#include "pico_time.h"
#include "otp.h"
#if !defined(ENABLE_EMULATION) && !defined(ESP_PLATFORM)
#include "pico/unique_id.h"
#endif
#include "mbedtls/rsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecdh.h"
#ifdef MBEDTLS_EDDSA_C
#include "mbedtls/eddsa.h"
#endif
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "mbedtls/gcm.h"
#include "mbedtls/constant_time.h"
#include "mbedtls/platform_util.h"

/* OpenPGP INS codes */
#define OPGP_INS_VERIFY                0x20
#define OPGP_INS_CHANGE_PIN            0x24
#define OPGP_INS_RESET_RETRY_COUNTER   0x2C
#define OPGP_INS_PSO                   0x2A
#define OPGP_INS_ACTIVATE              0x44
#define OPGP_INS_GENERATE_ASYM         0x47
#define OPGP_INS_GET_CHALLENGE         0x84
#define OPGP_INS_INTERNAL_AUTHENTICATE 0x88
#define OPGP_INS_SELECT_DATA           0xA5
#define OPGP_INS_GET_DATA              0xCA
#define OPGP_INS_PUT_DATA              0xDA
#define OPGP_INS_PUT_DATA_ODD          0xDB
#define OPGP_INS_TERMINATE             0xE6
#define OPGP_INS_GET_VERSION           0xF1
#define OPGP_INS_SET_PIN_RETRIES       0xF2
#define OPGP_INS_GET_ATTESTATION       0xFB

/* Key Slots (0=SIG, 1=DEC, 2=AUT, 3=ATT) */
#define OPGP_SLOT_SIG 0
#define OPGP_SLOT_DEC 1
#define OPGP_SLOT_AUT 2
#define OPGP_SLOT_ATT 3
#define OPGP_NUM_SLOTS 4

/* Algorithm IDs */
#define OPGP_ALG_RSA   0x01
#define OPGP_ALG_ECDH  0x12
#define OPGP_ALG_ECDSA 0x13
#define OPGP_ALG_EDDSA 0x16

/* Key Status */
#define OPGP_KEY_STATUS_NONE      0x00
#define OPGP_KEY_STATUS_GENERATED 0x01
#define OPGP_KEY_STATUS_IMPORTED  0x02

/* UIF (Touch Policy) */
#define OPGP_UIF_OFF          0x00
#define OPGP_UIF_ON           0x01
#define OPGP_UIF_FIXED        0x02
#define OPGP_UIF_CACHED       0x03
#define OPGP_UIF_CACHED_FIXED 0x04

#define OPGP_STATE_MAGIC 0x4F504731UL

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint8_t terminated;
    uint8_t pw1_hash[32];
    uint8_t pw1_len;
    uint8_t pw1_max_retries;
    uint8_t pw1_retries;
    uint8_t pw1_policy; /* 0 = ALWAYS, 1 = ONCE */
    uint8_t rc_hash[32];
    uint8_t rc_len;
    uint8_t rc_max_retries;
    uint8_t rc_retries;
    uint8_t pw3_hash[32];
    uint8_t pw3_len;
    uint8_t pw3_max_retries;
    uint8_t pw3_retries;
    uint32_t sig_counter;
    uint8_t alg_attr[OPGP_NUM_SLOTS][16];
    uint8_t alg_attr_len[OPGP_NUM_SLOTS];
    uint8_t uif[OPGP_NUM_SLOTS][2];
    uint8_t fp[OPGP_NUM_SLOTS][20];
    uint8_t ca_fp[OPGP_NUM_SLOTS][20];
    uint32_t gen_time[OPGP_NUM_SLOTS];
    uint8_t key_status[OPGP_NUM_SLOTS];
    uint8_t name[40];
    uint8_t name_len;
    uint8_t lang[8];
    uint8_t lang_len;
    uint8_t sex;
    uint8_t login[64];
    uint8_t login_len;
    uint8_t url[128];
    uint8_t url_len;
    uint8_t kdf_data[128];
    uint8_t kdf_len;
} opgp_state_t;

typedef struct __attribute__((packed)) {
    uint8_t alg_id;
    uint8_t grp_id;
    uint16_t bits;
    uint16_t pub_len;
    uint16_t priv_len;
    uint8_t iv[12];
    uint8_t tag[16];
} opgp_key_hdr_t;

static bool pw1_81_verified = false;
static bool pw1_82_verified = false;
static bool pw3_verified = false;
static uint8_t selected_cert_occurrence = 0; /* 0=AUT, 1=DEC, 2=SIG, 3=ATT */
static uint32_t opgp_last_touch_ms = 0;

/* Curve OID table */
typedef struct {
    mbedtls_ecp_group_id grp_id;
    uint8_t oid_len;
    uint8_t oid[12];
    uint8_t coord_len;
} opgp_curve_info_t;

static const opgp_curve_info_t opgp_curves[] = {
    { MBEDTLS_ECP_DP_SECP256R1, 8,  { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 }, 32 },
    { MBEDTLS_ECP_DP_SECP256K1, 5,  { 0x2B, 0x81, 0x04, 0x00, 0x0A }, 32 },
    { MBEDTLS_ECP_DP_SECP384R1, 5,  { 0x2B, 0x81, 0x04, 0x00, 0x22 }, 48 },
    { MBEDTLS_ECP_DP_SECP521R1, 5,  { 0x2B, 0x81, 0x04, 0x00, 0x23 }, 66 },
    { MBEDTLS_ECP_DP_BP256R1,   9,  { 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07 }, 32 },
    { MBEDTLS_ECP_DP_BP384R1,   9,  { 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B }, 48 },
    { MBEDTLS_ECP_DP_BP512R1,   9,  { 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D }, 64 },
    { MBEDTLS_ECP_DP_CURVE25519, 10, { 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01 }, 32 },
#if defined(MBEDTLS_EDDSA_C)
    { MBEDTLS_ECP_DP_ED25519,   9,  { 0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01 }, 32 },
#endif
};

static const opgp_curve_info_t *opgp_find_curve_by_oid(const uint8_t *oid, size_t oid_len) {
    /* Strip optional 0xFF (EC_IMPORT_FORMAT.STANDARD_W_PUBKEY) */
    if (oid_len > 1 && oid[oid_len - 1] == 0xFF) {
        oid_len--;
    }
    for (size_t i = 0; i < sizeof(opgp_curves) / sizeof(opgp_curves[0]); i++) {
        if (opgp_curves[i].oid_len == oid_len && memcmp(opgp_curves[i].oid, oid, oid_len) == 0) {
            return &opgp_curves[i];
        }
    }
    return NULL;
}

static const opgp_curve_info_t *opgp_find_curve_by_grp(mbedtls_ecp_group_id grp_id) {
    for (size_t i = 0; i < sizeof(opgp_curves) / sizeof(opgp_curves[0]); i++) {
        if (opgp_curves[i].grp_id == grp_id) {
            return &opgp_curves[i];
        }
    }
    return NULL;
}

static int opgp_rng(void *ctx, unsigned char *buf, size_t len) {
    (void)ctx;
    random_fill_buffer(BYTE_ARRAY(buf, len));
    return 0;
}

static void opgp_sha256(const uint8_t *in, size_t in_len, uint8_t out[32]) {
    mbedtls_sha256(in, in_len, out, 0);
}

static uint32_t opgp_get_serial_u32(void) {
    uint32_t b0 = (uint32_t)(pico_serial.id[0] & (uint8_t)~0xFCu);
    return (b0 << 24) | ((uint32_t)pico_serial.id[1] << 16) |
           ((uint32_t)pico_serial.id[2] << 8) | (uint32_t)pico_serial.id[3];
}
static uint8_t to_bcd(uint8_t v) {
    return (uint8_t)(((v / 10) << 4) | (v % 10));
}

static void opgp_build_aid(uint8_t aid[16]) {
    /* D2 76 00 01 24 01 03 04 00 06 <4B BCD serial> 00 00 */
    aid[0] = 0xD2; aid[1] = 0x76; aid[2] = 0x00;
    aid[3] = 0x01; aid[4] = 0x24; aid[5] = 0x01;
    aid[6] = 0x03; aid[7] = 0x04; /* v3.4 */
    aid[8] = 0x00; aid[9] = 0x06; /* Yubico manufacturer 0x0006 */
    uint32_t s = opgp_get_serial_u32() % 100000000UL;
    aid[10] = to_bcd((uint8_t)((s / 1000000UL) % 100));
    aid[11] = to_bcd((uint8_t)((s / 10000UL) % 100));
    aid[12] = to_bcd((uint8_t)((s / 100UL) % 100));
    aid[13] = to_bcd((uint8_t)(s % 100));
    aid[14] = 0x00; aid[15] = 0x00;
}

static void opgp_default_state(opgp_state_t *st) {
    memset(st, 0, sizeof(*st));
    st->magic = OPGP_STATE_MAGIC;
    st->terminated = 0;

    static const uint8_t def_pw1[] = "123456";
    opgp_sha256(def_pw1, 6, st->pw1_hash);
    st->pw1_len = 6;
    st->pw1_max_retries = 3;
    st->pw1_retries = 3;
    st->pw1_policy = 0; /* PIN_POLICY.ALWAYS */

    st->rc_len = 0;
    st->rc_max_retries = 3;
    st->rc_retries = 0;

    static const uint8_t def_pw3[] = "12345678";
    opgp_sha256(def_pw3, 8, st->pw3_hash);
    st->pw3_len = 8;
    st->pw3_max_retries = 3;
    st->pw3_retries = 3;

    st->sig_counter = 0;

    /* Default algorithm attributes: RSA 2048, e=17 bits, STANDARD (01 08 00 00 11 00) */
    static const uint8_t def_rsa2048[6] = { 0x01, 0x08, 0x00, 0x00, 0x11, 0x00 };
    for (int i = 0; i < OPGP_NUM_SLOTS; i++) {
        memcpy(st->alg_attr[i], def_rsa2048, 6);
        st->alg_attr_len[i] = 6;
        st->uif[i][0] = OPGP_UIF_OFF;
        st->uif[i][1] = 0x20; /* BUTTON */
        st->key_status[i] = OPGP_KEY_STATUS_NONE;
    }

    st->lang[0] = 'e';
    st->lang[1] = 'n';
    st->lang_len = 2;
    st->sex = 0x39; /* '9' Not applicable */

    /* Default KDF: KdfNone (81 01 00) */
    st->kdf_data[0] = 0x81;
    st->kdf_data[1] = 0x01;
    st->kdf_data[2] = 0x00;
    st->kdf_len = 3;
}

static applet_txn_t opgp_txn = APPLET_TXN_INITIALIZER(EF_OPENPGP_TXN);

static bool opgp_record_save(uint16_t fid, const void *data, size_t len) {
    bool ok = applet_txn_ready(&opgp_txn) && applet_storage_save(fid, data, len) && flash_commit_sync(5000);
    if (!ok) applet_txn_fail(&opgp_txn);
    return ok;
}

static bool opgp_record_delete(file_t *ef) {
    bool ok = file_delete_no_commit(ef) == PICOKEYS_OK && flash_commit_sync(5000);
    if (!ok) applet_txn_fail(&opgp_txn);
    return ok;
}

static bool opgp_save_state(const opgp_state_t *st) {
    return opgp_record_save(EF_OPENPGP_STATE, st, sizeof(*st));
}

static bool opgp_load_state(opgp_state_t *st) {
    memset(st, 0, sizeof(*st));
    if (!applet_txn_ready(&opgp_txn)) return false;
    file_t *ef = file_search(EF_OPENPGP_STATE);
    if (ef && file_has_data(ef)) {
        bool valid = applet_storage_load(EF_OPENPGP_STATE, st, sizeof(*st)) &&
                     st->magic == OPGP_STATE_MAGIC &&
                     st->name_len <= sizeof(st->name) && st->lang_len <= sizeof(st->lang) &&
                     st->login_len <= sizeof(st->login) && st->url_len <= sizeof(st->url) &&
                     st->kdf_len <= sizeof(st->kdf_data) && st->pw1_retries <= st->pw1_max_retries &&
                     st->pw3_retries <= st->pw3_max_retries && st->rc_retries <= st->rc_max_retries;
        for (size_t i = 0; valid && i < OPGP_NUM_SLOTS; i++) {
            valid = st->alg_attr_len[i] <= sizeof(st->alg_attr[i]) && st->uif[i][0] <= OPGP_UIF_CACHED_FIXED;
        }
        if (!valid) mbedtls_platform_zeroize(st, sizeof(*st));
        return valid;
    }
    /* Defaults are safe only for a completely empty applet. */
    for (uint16_t i = 0; i < OPGP_NUM_SLOTS; i++) {
        if (file_has_data(file_search((uint16_t)(EF_OPENPGP_KEY_BASE + i))) ||
            file_has_data(file_search((uint16_t)(EF_OPENPGP_CERT_BASE + i))) ||
            file_has_data(file_search((uint16_t)(EF_OPENPGP_PRIV_DO_BASE + i)))) return false;
    }
    opgp_default_state(st);
    return opgp_save_state(st);
}

static uint8_t opgp_kdf_alg(const opgp_state_t *st) {
    if (st->kdf_len >= 3 && st->kdf_data[0] == 0x81 && st->kdf_data[1] == 0x01) {
        return st->kdf_data[2];
    }
    return 0x00;
}

static bool opgp_check_touch(uint8_t uif_mode) {
    if (uif_mode == OPGP_UIF_OFF) {
        return true;
    }
#ifdef ENABLE_EMULATION
    (void)opgp_last_touch_ms;
    return check_user_presence();
#else
    uint32_t now = board_millis();
    if ((uif_mode == OPGP_UIF_CACHED || uif_mode == OPGP_UIF_CACHED_FIXED) &&
        opgp_last_touch_ms != 0 && (now - opgp_last_touch_ms) < 15000u) {
        return true;
    }
    uint32_t timeout_s = button_timeout_seconds();
    if (timeout_s == 0) {
        timeout_s = 15;
    }
    if (wait_button_pressed_timeout(timeout_s) != 0) {
        return false;
    }
    opgp_last_touch_ms = board_millis();
    if (opgp_last_touch_ms == 0) {
        opgp_last_touch_ms = 1;
    }
    return true;
#endif
}

static size_t put_tlv(uint8_t *out, uint16_t tag, const uint8_t *val, size_t len) {
    size_t off = 0;
    if (tag > 0xFF) {
        out[off++] = (uint8_t)(tag >> 8);
        out[off++] = (uint8_t)(tag & 0xFF);
    }
    else {
        out[off++] = (uint8_t)tag;
    }
    if (len < 0x80) {
        out[off++] = (uint8_t)len;
    }
    else if (len <= 0xFF) {
        out[off++] = 0x81;
        out[off++] = (uint8_t)len;
    }
    else {
        out[off++] = 0x82;
        out[off++] = (uint8_t)(len >> 8);
        out[off++] = (uint8_t)(len & 0xFF);
    }
    if (len > 0 && val != NULL && out + off != val) {
        memcpy(out + off, val, len);
    }
    return off + len;
}

static bool parse_tlv(const uint8_t *buf, size_t buf_len, size_t *pos, uint16_t *tag, const uint8_t **val, size_t *len) {
    if (*pos >= buf_len) {
        return false;
    }
    size_t p = *pos;
    uint16_t t = buf[p++];
    if ((t & 0x1F) == 0x1F) {
        if (p >= buf_len) {
            return false;
        }
        t = (uint16_t)((t << 8) | buf[p++]);
    }
    if (p >= buf_len) {
        return false;
    }
    size_t l = buf[p++];
    if (l == 0x81) {
        if (p >= buf_len) {
            return false;
        }
        l = buf[p++];
    }
    else if (l == 0x82) {
        if (p + 1 >= buf_len) {
            return false;
        }
        l = ((size_t)buf[p] << 8) | buf[p + 1];
        p += 2;
    }
    else if (l == 0x83) {
        if (p + 2 >= buf_len) {
            return false;
        }
        l = ((size_t)buf[p] << 16) | ((size_t)buf[p + 1] << 8) | buf[p + 2];
        p += 3;
    }
    else if (l > 0x83) {
        return false;
    }
    if (p + l > buf_len) {
        return false;
    }
    *tag = t;
    *val = buf + p;
    *len = l;
    *pos = p + l;
    return true;
}

/* Authenticate the complete key record, including public material and lengths,
 * even when a caller requests only its header or public key. */
static int opgp_store_key_record(uint8_t slot, uint8_t alg_id, uint8_t grp_id, uint16_t bits,
                                 const uint8_t *pub, uint16_t pub_len,
                                 const uint8_t *priv, uint16_t priv_len) {
    if (slot >= OPGP_NUM_SLOTS || pub_len > 600 || priv_len > 1400 ||
        (!pub && pub_len) || (!priv && priv_len)) return -1;
    static uint8_t record[sizeof(opgp_key_hdr_t) + 600 + 1400];
    memset(record, 0, sizeof(record));
    opgp_key_hdr_t hdr = { .alg_id = alg_id, .grp_id = grp_id, .bits = bits,
                           .pub_len = pub_len, .priv_len = priv_len };
    memcpy(record, &hdr, sizeof(hdr));
    if (pub_len) memcpy(record + sizeof(hdr), pub, pub_len);
    if (priv_len) memcpy(record + sizeof(hdr) + pub_len, priv, priv_len);
    bool ok = opgp_record_save((uint16_t)(EF_OPENPGP_KEY_BASE + slot), record,
                                  sizeof(hdr) + pub_len + priv_len);
    mbedtls_platform_zeroize(record, sizeof(record));
    return ok ? 0 : -1;
}

static int opgp_load_key_record(uint8_t slot, opgp_key_hdr_t *hdr_out,
                                uint8_t *pub_out, uint16_t pub_max,
                                uint8_t *priv_out, uint16_t priv_max) {
    if (slot >= OPGP_NUM_SLOTS) return -1;
    static uint8_t record[sizeof(opgp_key_hdr_t) + 600 + 1400];
    size_t len;
    if (!applet_storage_load_variable((uint16_t)(EF_OPENPGP_KEY_BASE + slot), record, sizeof(record), &len)) return -1;
    opgp_key_hdr_t hdr;
    int ret = -1;
    if (len < sizeof(hdr)) goto done;
    memcpy(&hdr, record, sizeof(hdr));
    if (hdr.pub_len > 600 || hdr.priv_len > 1400 ||
        sizeof(hdr) + hdr.pub_len + hdr.priv_len != len ||
        (pub_out && hdr.pub_len > pub_max) || (priv_out && hdr.priv_len > priv_max)) goto done;
    if (pub_out) memcpy(pub_out, record + sizeof(hdr), hdr.pub_len);
    if (priv_out) memcpy(priv_out, record + sizeof(hdr) + hdr.pub_len, hdr.priv_len);
    if (hdr_out) *hdr_out = hdr;
    ret = 0;
done:
    mbedtls_platform_zeroize(record, sizeof(record));
    return ret;
}

static int opgp_get_stored_data(uint16_t fid, size_t limit) {
    static uint8_t data[2048];
    file_t *ef = file_search(fid);
    if (!ef || !file_has_data(ef)) return SW_OK();
    size_t len;
    if (limit > sizeof(data) || !applet_storage_load_variable(fid, data, limit, &len)) return SW_EXEC_ERROR();
    apdu_set_response_buffer(data, (uint16_t)len);
    return SW_OK();
}

static bool opgp_delete_slot_key(opgp_state_t *st, uint8_t slot) {
    if (slot >= OPGP_NUM_SLOTS) {
        return false;
    }
    uint16_t fid = (uint16_t)(EF_OPENPGP_KEY_BASE + slot);
    file_t *ef = file_search(fid);
    if (ef && file_has_data(ef)) {
        if (!opgp_record_delete(ef)) return false;
    }
    st->key_status[slot] = OPGP_KEY_STATUS_NONE;
    memset(st->fp[slot], 0, 20);
    st->gen_time[slot] = 0;
    if (slot == OPGP_SLOT_SIG) {
        st->sig_counter = 0;
    }
    return true;
}

static bool opgp_factory_reset(void) {
    for (uint8_t s = 0; s < OPGP_NUM_SLOTS; s++) {
        file_t *ef = file_search((uint16_t)(EF_OPENPGP_KEY_BASE + s));
        if (ef && file_has_data(ef)) {
            if (!opgp_record_delete(ef)) return false;
        }
        ef = file_search((uint16_t)(EF_OPENPGP_CERT_BASE + s));
        if (ef && file_has_data(ef)) {
            if (!opgp_record_delete(ef)) return false;
        }
        ef = file_search((uint16_t)(EF_OPENPGP_PRIV_DO_BASE + s));
        if (ef && file_has_data(ef)) {
            if (!opgp_record_delete(ef)) return false;
        }
    }
    static opgp_state_t st;
    opgp_default_state(&st);
    if (!opgp_save_state(&st)) return false;
    pw1_81_verified = false;
    pw1_82_verified = false;
    pw3_verified = false;
    selected_cert_occurrence = 0;
    return true;
}

static bool opgp_validate_alg_attr(uint8_t slot, const uint8_t *attr, size_t len) {
    if (len < 2 || len > 16) {
        return false;
    }
    uint8_t alg_id = attr[0];
    if (alg_id == OPGP_ALG_RSA) {
        if (len != 6) {
            return false;
        }
        uint16_t n_bits = (uint16_t)((attr[1] << 8) | attr[2]);
        if (n_bits != 2048 && n_bits != 3072 && n_bits != 4096) {
            return false;
        }
        return true;
    }
    if (alg_id == OPGP_ALG_ECDH || alg_id == OPGP_ALG_ECDSA || alg_id == OPGP_ALG_EDDSA) {
        const opgp_curve_info_t *ci = opgp_find_curve_by_oid(attr + 1, len - 1);
        if (!ci) {
            return false;
        }
        if (slot == OPGP_SLOT_DEC) {
#if defined(MBEDTLS_EDDSA_C)
            if (ci->grp_id == MBEDTLS_ECP_DP_ED25519) {
                return false;
            }
#endif
        }
        else {
            if (ci->grp_id == MBEDTLS_ECP_DP_CURVE25519) {
                return false;
            }
        }
        return true;
    }
    return false;
}

static size_t opgp_build_discretionary(const opgp_state_t *st, uint8_t *out) {
    size_t off = 0;
    /* C0: Extended Capabilities (10B) */
    static const uint8_t ext_cap[10] = {
        0x7F, /* KDF(1)|AES(2)|ALG_CHANGE(4)|PRIV_USE(8)|PW_STATUS(16)|KEY_IMPORT(32)|GET_CHALLENGE(64) */
        0x00, /* SM alg */
        0x00, 0xFF, /* max challenge = 255 */
        0x08, 0x00, /* max cert = 2048 */
        0x00, 0xFF, /* max special DO = 255 */
        0x00, /* pin block 2 format */
        0x00  /* MSE command */
    };
    off += put_tlv(out + off, 0x00C0, ext_cap, sizeof(ext_cap));
    /* C1, C2, C3, DA: Algorithm Attributes */
    off += put_tlv(out + off, 0x00C1, st->alg_attr[OPGP_SLOT_SIG], st->alg_attr_len[OPGP_SLOT_SIG]);
    off += put_tlv(out + off, 0x00C2, st->alg_attr[OPGP_SLOT_DEC], st->alg_attr_len[OPGP_SLOT_DEC]);
    off += put_tlv(out + off, 0x00C3, st->alg_attr[OPGP_SLOT_AUT], st->alg_attr_len[OPGP_SLOT_AUT]);
    off += put_tlv(out + off, 0x00DA, st->alg_attr[OPGP_SLOT_ATT], st->alg_attr_len[OPGP_SLOT_ATT]);
    /* C4: PW Status Bytes (7B) */
    uint8_t c4[7] = {
        st->pw1_policy,
        127, 127, 127,
        st->pw1_retries,
        st->rc_retries,
        st->pw3_retries
    };
    off += put_tlv(out + off, 0x00C4, c4, sizeof(c4));
    /* C5: Fingerprints (80B: SIG, DEC, AUT, ATT) */
    uint8_t fps[80];
    for (int i = 0; i < OPGP_NUM_SLOTS; i++) {
        memcpy(fps + i * 20, st->fp[i], 20);
    }
    off += put_tlv(out + off, 0x00C5, fps, sizeof(fps));
    /* C6: CA Fingerprints (80B) */
    uint8_t ca_fps[80];
    for (int i = 0; i < OPGP_NUM_SLOTS; i++) {
        memcpy(ca_fps + i * 20, st->ca_fp[i], 20);
    }
    off += put_tlv(out + off, 0x00C6, ca_fps, sizeof(ca_fps));
    /* CD: Generation Timestamps (16B) */
    uint8_t times[16];
    for (int i = 0; i < OPGP_NUM_SLOTS; i++) {
        uint32_t t = st->gen_time[i];
        times[i * 4 + 0] = (uint8_t)(t >> 24);
        times[i * 4 + 1] = (uint8_t)(t >> 16);
        times[i * 4 + 2] = (uint8_t)(t >> 8);
        times[i * 4 + 3] = (uint8_t)(t & 0xFF);
    }
    off += put_tlv(out + off, 0x00CD, times, sizeof(times));
    /* DE: Key Information (8B) */
    uint8_t key_info[8] = {
        0x01, st->key_status[OPGP_SLOT_SIG],
        0x02, st->key_status[OPGP_SLOT_DEC],
        0x03, st->key_status[OPGP_SLOT_AUT],
        0x81, st->key_status[OPGP_SLOT_ATT]
    };
    off += put_tlv(out + off, 0x00DE, key_info, sizeof(key_info));
    /* D6..D9: UIF */
    off += put_tlv(out + off, 0x00D6, st->uif[OPGP_SLOT_SIG], 2);
    off += put_tlv(out + off, 0x00D7, st->uif[OPGP_SLOT_DEC], 2);
    off += put_tlv(out + off, 0x00D8, st->uif[OPGP_SLOT_AUT], 2);
    off += put_tlv(out + off, 0x00D9, st->uif[OPGP_SLOT_ATT], 2);
    return off;
}

static size_t opgp_build_algorithm_info(uint8_t *out) {
    static const uint16_t slot_tags[4] = { 0x00C1, 0x00C2, 0x00C3, 0x00DA };
    static const uint16_t rsa_sizes[3] = { 2048, 3072, 4096 };
    static const uint8_t rsa_fmts[2] = { 0x00, 0x03 };
    static const uint8_t ec_fmts[2] = { 0x00, 0xFF };

    static uint8_t inner[1024];
    size_t off = 0;
    for (int s = 0; s < 4; s++) {
        uint16_t tag = slot_tags[s];
        for (int r = 0; r < 3; r++) {
            for (int f = 0; f < 2; f++) {
                uint8_t attr[6] = {
                    OPGP_ALG_RSA,
                    (uint8_t)(rsa_sizes[r] >> 8),
                    (uint8_t)(rsa_sizes[r] & 0xFF),
                    0x00, 0x11,
                    rsa_fmts[f]
                };
                off += put_tlv(inner + off, tag, attr, sizeof(attr));
            }
        }
        for (size_t c = 0; c < sizeof(opgp_curves) / sizeof(opgp_curves[0]); c++) {
            const opgp_curve_info_t *ci = &opgp_curves[c];
#if defined(MBEDTLS_EDDSA_C)
            if (s == OPGP_SLOT_DEC && ci->grp_id == MBEDTLS_ECP_DP_ED25519) {
                continue;
            }
#endif
            if (s != OPGP_SLOT_DEC && ci->grp_id == MBEDTLS_ECP_DP_CURVE25519) {
                continue;
            }
            uint8_t alg_id = (s == OPGP_SLOT_DEC) ? OPGP_ALG_ECDH : OPGP_ALG_ECDSA;
#if defined(MBEDTLS_EDDSA_C)
            if (ci->grp_id == MBEDTLS_ECP_DP_ED25519) {
                alg_id = OPGP_ALG_EDDSA;
            }
#endif
            for (int f = 0; f < 2; f++) {
                uint8_t attr[16];
                attr[0] = alg_id;
                memcpy(attr + 1, ci->oid, ci->oid_len);
                size_t alen = (size_t)(1 + ci->oid_len);
                if (ec_fmts[f] == 0xFF) {
                    attr[alen++] = 0xFF;
                }
                off += put_tlv(inner + off, tag, attr, alen);
            }
        }
    }
    return put_tlv(out, 0x00FA, inner, off);
}

static int cmd_opgp_select_data(void) {
    uint8_t p1 = P1(apdu);
    uint8_t p2 = P2(apdu);
    if (p2 != 0x04 || p1 > 3 || apdu.nc < 4) {
        return SW_INCORRECT_P1P2();
    }
    /* Expect 60 04 5C 02 7F 21 */
    selected_cert_occurrence = p1;
    return SW_OK();
}

static int cmd_opgp_get_data(void) {
    static opgp_state_t st;
    if (!opgp_load_state(&st)) return SW_EXEC_ERROR();
    uint16_t tag = (uint16_t)((P1(apdu) << 8) | P2(apdu));

    switch (tag) {
        case 0x004F: {
            uint8_t aid[16];
            opgp_build_aid(aid);
            memcpy(res_APDU, aid, 16);
            res_APDU_size = 16;
            return SW_OK();
        }
        case 0x005E: {
            if (st.login_len > 0) {
                memcpy(res_APDU, st.login, st.login_len);
                res_APDU_size = st.login_len;
            }
            return SW_OK();
        }
        case 0x5F50: {
            if (st.url_len > 0) {
                memcpy(res_APDU, st.url, st.url_len);
                res_APDU_size = st.url_len;
            }
            return SW_OK();
        }
        case 0x5F52: {
            uint8_t hist[8] = { 0x00, 0x73, 0x00, 0x00, 0xE0, st.terminated ? 0x03 : 0x05, 0x90, 0x00 };
            memcpy(res_APDU, hist, 8);
            res_APDU_size = 8;
            return SW_OK();
        }
        case 0x7F66: {
            static const uint8_t ext_len[8] = { 0x02, 0x02, 0x08, 0x00, 0x02, 0x02, 0x08, 0x00 };
            res_APDU_size = (uint16_t)put_tlv(res_APDU, 0x7F66, ext_len, sizeof(ext_len));
            return SW_OK();
        }
        case 0x7F74: {
            static const uint8_t gfm[3] = { 0x81, 0x01, 0x20 };
            res_APDU_size = (uint16_t)put_tlv(res_APDU, 0x7F74, gfm, sizeof(gfm));
            return SW_OK();
        }
        case 0x0065: {
            uint8_t inner[64];
            size_t off = 0;
            off += put_tlv(inner + off, 0x005B, st.name, st.name_len);
            off += put_tlv(inner + off, 0x5F2D, st.lang, st.lang_len);
            off += put_tlv(inner + off, 0x5F35, &st.sex, 1);
            res_APDU_size = (uint16_t)put_tlv(res_APDU, 0x0065, inner, off);
            return SW_OK();
        }
        case 0x0073: {
            static uint8_t disc[384];
            size_t dlen = opgp_build_discretionary(&st, disc);
            res_APDU_size = (uint16_t)put_tlv(res_APDU, 0x0073, disc, dlen);
            return SW_OK();
        }
        case 0x006E: {
            static uint8_t inner[512];
            size_t off = 0;
            uint8_t aid[16];
            opgp_build_aid(aid);
            off += put_tlv(inner + off, 0x004F, aid, 16);
            uint8_t hist[8] = { 0x00, 0x73, 0x00, 0x00, 0xE0, st.terminated ? 0x03 : 0x05, 0x90, 0x00 };
            off += put_tlv(inner + off, 0x5F52, hist, 8);
            static const uint8_t ext_len[8] = { 0x02, 0x02, 0x08, 0x00, 0x02, 0x02, 0x08, 0x00 };
            off += put_tlv(inner + off, 0x7F66, ext_len, sizeof(ext_len));
            static const uint8_t gfm[3] = { 0x81, 0x01, 0x20 };
            off += put_tlv(inner + off, 0x7F74, gfm, sizeof(gfm));
            static uint8_t disc[384];
            size_t dlen = opgp_build_discretionary(&st, disc);
            off += put_tlv(inner + off, 0x0073, disc, dlen);
            res_APDU_size = (uint16_t)put_tlv(res_APDU, 0x006E, inner, off);
            return SW_OK();
        }
        case 0x007A: {
            uint8_t cnt[3] = {
                (uint8_t)((st.sig_counter >> 16) & 0xFF),
                (uint8_t)((st.sig_counter >> 8) & 0xFF),
                (uint8_t)(st.sig_counter & 0xFF)
            };
            uint8_t inner[8];
            size_t off = put_tlv(inner, 0x0093, cnt, 3);
            res_APDU_size = (uint16_t)put_tlv(res_APDU, 0x007A, inner, off);
            return SW_OK();
        }
        case 0x0093: {
            res_APDU[0] = (uint8_t)((st.sig_counter >> 16) & 0xFF);
            res_APDU[1] = (uint8_t)((st.sig_counter >> 8) & 0xFF);
            res_APDU[2] = (uint8_t)(st.sig_counter & 0xFF);
            res_APDU_size = 3;
            return SW_OK();
        }
        case 0x00C4: {
            res_APDU[0] = st.pw1_policy;
            res_APDU[1] = 127;
            res_APDU[2] = 127;
            res_APDU[3] = 127;
            res_APDU[4] = st.pw1_retries;
            res_APDU[5] = st.rc_retries;
            res_APDU[6] = st.pw3_retries;
            res_APDU_size = 7;
            return SW_OK();
        }
        case 0x00C1:
        case 0x00C2:
        case 0x00C3:
        case 0x00DA: {
            uint8_t s = (tag == 0x00DA) ? OPGP_SLOT_ATT : (uint8_t)(tag - 0x00C1);
            memcpy(res_APDU, st.alg_attr[s], st.alg_attr_len[s]);
            res_APDU_size = st.alg_attr_len[s];
            return SW_OK();
        }
        case 0x00D6:
        case 0x00D7:
        case 0x00D8:
        case 0x00D9: {
            uint8_t s = (uint8_t)(tag - 0x00D6);
            memcpy(res_APDU, st.uif[s], 2);
            res_APDU_size = 2;
            return SW_OK();
        }
        case 0x00DE: {
            uint8_t key_info[8] = {
                0x01, st.key_status[OPGP_SLOT_SIG],
                0x02, st.key_status[OPGP_SLOT_DEC],
                0x03, st.key_status[OPGP_SLOT_AUT],
                0x81, st.key_status[OPGP_SLOT_ATT]
            };
            memcpy(res_APDU, key_info, 8);
            res_APDU_size = 8;
            return SW_OK();
        }
        case 0x00F9: {
            memcpy(res_APDU, st.kdf_data, st.kdf_len);
            res_APDU_size = st.kdf_len;
            return SW_OK();
        }
        case 0x00FA: {
            res_APDU_size = (uint16_t)opgp_build_algorithm_info(res_APDU);
            return SW_OK();
        }
        case 0x7F21:
        case 0x00FC: {
            /* Occurrence mapping: 0=AUT(slot 2), 1=DEC(slot 1), 2=SIG(slot 0), 3/0xFC=ATT(slot 3) */
            uint8_t cert_idx = 3;
            if (tag == 0x7F21) {
                if (selected_cert_occurrence == 0) cert_idx = OPGP_SLOT_AUT;
                else if (selected_cert_occurrence == 1) cert_idx = OPGP_SLOT_DEC;
                else if (selected_cert_occurrence == 2) cert_idx = OPGP_SLOT_SIG;
                else cert_idx = OPGP_SLOT_ATT;
            }
            return opgp_get_stored_data((uint16_t)(EF_OPENPGP_CERT_BASE + cert_idx), 2048);
        }
        case 0x0101:
        case 0x0102:
        case 0x0103:
        case 0x0104: {
            if (tag == 0x0103 && !pw1_82_verified && !pw3_verified) {
                return SW_SECURITY_STATUS_NOT_SATISFIED();
            }
            if (tag == 0x0104 && !pw3_verified) {
                return SW_SECURITY_STATUS_NOT_SATISFIED();
            }
            uint8_t idx = (uint8_t)(tag - 0x0101);
            return opgp_get_stored_data((uint16_t)(EF_OPENPGP_PRIV_DO_BASE + idx), 255);
        }
        default:
            return SW_REFERENCE_NOT_FOUND();
    }
}

static int cmd_opgp_put_data(void) {
    static opgp_state_t st;
    if (!opgp_load_state(&st)) return SW_EXEC_ERROR();
    uint16_t tag = (uint16_t)((P1(apdu) << 8) | P2(apdu));

    /* Check access control: 0x0101 and 0x0103 require PW1(82), all others require PW3 */
    if (tag == 0x0101 || tag == 0x0103) {
        if (!pw1_82_verified) {
            return SW_SECURITY_STATUS_NOT_SATISFIED();
        }
    }
    else {
        if (!pw3_verified) {
            return SW_SECURITY_STATUS_NOT_SATISFIED();
        }
    }

    switch (tag) {
        case 0x005B:
            if (apdu.nc > 39) return SW_WRONG_LENGTH();
            memcpy(st.name, apdu.data, apdu.nc);
            st.name_len = (uint8_t)apdu.nc;
            if (!opgp_save_state(&st)) return SW_MEMORY_FAILURE();
            return SW_OK();
        case 0x5F2D:
            if (apdu.nc > 8) return SW_WRONG_LENGTH();
            memcpy(st.lang, apdu.data, apdu.nc);
            st.lang_len = (uint8_t)apdu.nc;
            if (!opgp_save_state(&st)) return SW_MEMORY_FAILURE();
            return SW_OK();
        case 0x5F35:
            if (apdu.nc != 1) return SW_WRONG_LENGTH();
            st.sex = apdu.data[0];
            if (!opgp_save_state(&st)) return SW_MEMORY_FAILURE();
            return SW_OK();
        case 0x005E:
            if (apdu.nc > sizeof(st.login)) return SW_WRONG_LENGTH();
            memcpy(st.login, apdu.data, apdu.nc);
            st.login_len = (uint8_t)apdu.nc;
            if (!opgp_save_state(&st)) return SW_MEMORY_FAILURE();
            return SW_OK();
        case 0x5F50:
            if (apdu.nc > sizeof(st.url)) return SW_WRONG_LENGTH();
            memcpy(st.url, apdu.data, apdu.nc);
            st.url_len = (uint8_t)apdu.nc;
            if (!opgp_save_state(&st)) return SW_MEMORY_FAILURE();
            return SW_OK();
        case 0x00C4:
            if (apdu.nc != 1 && apdu.nc != 7) return SW_WRONG_LENGTH();
            if (apdu.data[0] > 1) return SW_WRONG_DATA();
            st.pw1_policy = apdu.data[0];
            if (!opgp_save_state(&st)) return SW_MEMORY_FAILURE();
            return SW_OK();
        case 0x00C1:
        case 0x00C2:
        case 0x00C3:
        case 0x00DA: {
            uint8_t s = (tag == 0x00DA) ? OPGP_SLOT_ATT : (uint8_t)(tag - 0x00C1);
            if (!opgp_validate_alg_attr(s, apdu.data, apdu.nc)) {
                return SW_WRONG_DATA();
            }
            if (!opgp_txn.active && !applet_txn_begin(&opgp_txn)) return SW_MEMORY_FAILURE();
            if (!opgp_delete_slot_key(&st, s)) return SW_MEMORY_FAILURE();
            memcpy(st.alg_attr[s], apdu.data, apdu.nc);
            st.alg_attr_len[s] = (uint8_t)apdu.nc;
            if (!opgp_save_state(&st)) return SW_MEMORY_FAILURE();
            return SW_OK();
        }
        case 0x00C7:
        case 0x00C8:
        case 0x00C9:
        case 0x00DB: {
            if (apdu.nc != 20 && apdu.nc != 0) return SW_WRONG_LENGTH();
            uint8_t s = (tag == 0x00DB) ? OPGP_SLOT_ATT : (uint8_t)(tag - 0x00C7);
            if (apdu.nc == 20) memcpy(st.fp[s], apdu.data, 20);
            else memset(st.fp[s], 0, 20);
            if (!opgp_save_state(&st)) return SW_MEMORY_FAILURE();
            return SW_OK();
        }
        case 0x00CA:
        case 0x00CB:
        case 0x00CC:
        case 0x00DC: {
            if (apdu.nc != 20 && apdu.nc != 0) return SW_WRONG_LENGTH();
            uint8_t s = (tag == 0x00DC) ? OPGP_SLOT_ATT : (uint8_t)(tag - 0x00CA);
            if (apdu.nc == 20) memcpy(st.ca_fp[s], apdu.data, 20);
            else memset(st.ca_fp[s], 0, 20);
            if (!opgp_save_state(&st)) return SW_MEMORY_FAILURE();
            return SW_OK();
        }
        case 0x00CE:
        case 0x00CF:
        case 0x00D0:
        case 0x00DD: {
            if (apdu.nc != 4 && apdu.nc != 0) return SW_WRONG_LENGTH();
            uint8_t s = (tag == 0x00DD) ? OPGP_SLOT_ATT : (uint8_t)(tag - 0x00CE);
            if (apdu.nc == 4) {
                st.gen_time[s] = ((uint32_t)apdu.data[0] << 24) | ((uint32_t)apdu.data[1] << 16) |
                                 ((uint32_t)apdu.data[2] << 8) | apdu.data[3];
            }
            else {
                st.gen_time[s] = 0;
            }
            if (!opgp_save_state(&st)) return SW_MEMORY_FAILURE();
            return SW_OK();
        }
        case 0x00D3: {
            if (apdu.nc == 0) {
                st.rc_len = 0;
                st.rc_retries = 0;
            }
            else {
                uint8_t min_len = (opgp_kdf_alg(&st) == 0x03) ? 32 : 8;
                if (apdu.nc < min_len || apdu.nc > 127) {
                    return SW_WRONG_LENGTH();
                }
                opgp_sha256(apdu.data, apdu.nc, st.rc_hash);
                st.rc_len = (uint8_t)apdu.nc;
                st.rc_retries = st.rc_max_retries;
            }
            if (!opgp_save_state(&st)) return SW_MEMORY_FAILURE();
            return SW_OK();
        }
        case 0x00D6:
        case 0x00D7:
        case 0x00D8:
        case 0x00D9: {
            if (apdu.nc != 2) return SW_WRONG_LENGTH();
            uint8_t s = (uint8_t)(tag - 0x00D6);
            uint8_t cur = st.uif[s][0];
            if (cur == OPGP_UIF_FIXED || cur == OPGP_UIF_CACHED_FIXED) {
                return SW_CONDITIONS_NOT_SATISFIED();
            }
            if (apdu.data[0] > OPGP_UIF_CACHED_FIXED) {
                return SW_WRONG_DATA();
            }
            st.uif[s][0] = apdu.data[0];
            st.uif[s][1] = 0x20;
            if (!opgp_save_state(&st)) return SW_MEMORY_FAILURE();
            return SW_OK();
        }
        case 0x00F9: {
            if (apdu.nc < 3 || apdu.nc > sizeof(st.kdf_data)) {
                return SW_WRONG_LENGTH();
            }
            /* Parse KDF TLVs; extract 0x81 (alg), 0x87 (init_hash_user), 0x88 (init_hash_admin) */
            size_t pos = 0;
            uint16_t t = 0;
            const uint8_t *v = NULL;
            size_t l = 0;
            uint8_t alg = 0xFF;
            const uint8_t *init_u = NULL;
            const uint8_t *init_a = NULL;
            while (parse_tlv(apdu.data, apdu.nc, &pos, &t, &v, &l)) {
                if (t == 0x81 && l == 1) alg = v[0];
                else if (t == 0x87 && l == 32) init_u = v;
                else if (t == 0x88 && l == 32) init_a = v;
            }
            if (alg != 0x00 && (alg != 0x03 || !init_u || !init_a)) {
                return SW_WRONG_DATA();
            }
            memcpy(st.kdf_data, apdu.data, apdu.nc);
            st.kdf_len = (uint8_t)apdu.nc;
            if (alg == 0x00) {
                static const uint8_t def_pw1[] = "123456";
                static const uint8_t def_pw3[] = "12345678";
                opgp_sha256(def_pw1, 6, st.pw1_hash);
                st.pw1_len = 6;
                opgp_sha256(def_pw3, 8, st.pw3_hash);
                st.pw3_len = 8;
            }
            else {
                opgp_sha256(init_u, 32, st.pw1_hash);
                st.pw1_len = 32;
                opgp_sha256(init_a, 32, st.pw3_hash);
                st.pw3_len = 32;
            }
            st.pw1_retries = st.pw1_max_retries;
            st.pw3_retries = st.pw3_max_retries;
            st.rc_len = 0;
            st.rc_retries = 0;
            if (!opgp_save_state(&st)) return SW_MEMORY_FAILURE();
            return SW_OK();
        }
        case 0x7F21:
        case 0x00FC: {
            if (apdu.nc > 2048) return SW_WRONG_LENGTH();
            uint8_t cert_idx = 3;
            if (tag == 0x7F21) {
                if (selected_cert_occurrence == 0) cert_idx = OPGP_SLOT_AUT;
                else if (selected_cert_occurrence == 1) cert_idx = OPGP_SLOT_DEC;
                else if (selected_cert_occurrence == 2) cert_idx = OPGP_SLOT_SIG;
                else cert_idx = OPGP_SLOT_ATT;
            }
            uint16_t fid = (uint16_t)(EF_OPENPGP_CERT_BASE + cert_idx);
            file_t *ef = file_search(fid);
            if (apdu.nc == 0) {
                if (ef && file_has_data(ef)) {
                    if (!opgp_record_delete(ef)) return SW_MEMORY_FAILURE();
                }
            }
            else {
                if (!opgp_record_save(fid, apdu.data, apdu.nc)) return SW_MEMORY_FAILURE();
            }
            return SW_OK();
        }
        case 0x0101:
        case 0x0102:
        case 0x0103:
        case 0x0104: {
            if (apdu.nc > 255) return SW_WRONG_LENGTH();
            uint8_t idx = (uint8_t)(tag - 0x0101);
            uint16_t fid = (uint16_t)(EF_OPENPGP_PRIV_DO_BASE + idx);
            file_t *ef = file_search(fid);
            if (apdu.nc == 0) {
                if (ef && file_has_data(ef)) {
                    if (!opgp_record_delete(ef)) return SW_MEMORY_FAILURE();
                }
            }
            else {
                if (!opgp_record_save(fid, apdu.data, apdu.nc)) return SW_MEMORY_FAILURE();
            }
            return SW_OK();
        }
        default:
            return SW_REFERENCE_NOT_FOUND();
    }
}

static int cmd_opgp_verify(void) {
    static opgp_state_t st;
    if (!opgp_load_state(&st)) return SW_EXEC_ERROR();
    uint8_t p1 = P1(apdu);
    uint8_t p2 = P2(apdu);

    if (p2 != 0x81 && p2 != 0x82 && p2 != 0x83) {
        return SW_INCORRECT_P1P2();
    }
    if (p1 == 0xFF) {
        if (p2 == 0x81) pw1_81_verified = false;
        else if (p2 == 0x82) pw1_82_verified = false;
        else pw3_verified = false;
        return SW_OK();
    }
    if (p1 != 0x00) {
        return SW_INCORRECT_P1P2();
    }
    if (apdu.nc == 0) {
        if (p2 == 0x81 && pw1_81_verified) return SW_OK();
        if (p2 == 0x82 && pw1_82_verified) return SW_OK();
        if (p2 == 0x83 && pw3_verified) return SW_OK();
        uint8_t rem = (p2 == 0x83) ? st.pw3_retries : st.pw1_retries;
        return set_res_sw(0x63, (uint8_t)(0xC0 | (rem & 0x0F)));
    }

    uint8_t h[32];
    opgp_sha256(apdu.data, apdu.nc, h);

    if (p2 == 0x81 || p2 == 0x82) {
        if (st.pw1_retries == 0) {
            return SW_PIN_BLOCKED();
        }
        st.pw1_retries--;
        if (!opgp_save_state(&st)) return SW_MEMORY_FAILURE();
        if (apdu.nc == st.pw1_len && mbedtls_ct_memcmp(h, st.pw1_hash, 32) == 0) {
            if (st.pw1_retries != st.pw1_max_retries) {
                st.pw1_retries = st.pw1_max_retries;
                if (!opgp_save_state(&st)) return SW_MEMORY_FAILURE();
            }
            if (p2 == 0x81) pw1_81_verified = true;
            else pw1_82_verified = true;
            return SW_OK();
        }
        pw1_81_verified = false;
        pw1_82_verified = false;
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    else {
        if (st.pw3_retries == 0) {
            return SW_PIN_BLOCKED();
        }
        st.pw3_retries--;
        if (!opgp_save_state(&st)) return SW_MEMORY_FAILURE();
        if (apdu.nc == st.pw3_len && mbedtls_ct_memcmp(h, st.pw3_hash, 32) == 0) {
            if (st.pw3_retries != st.pw3_max_retries) {
                st.pw3_retries = st.pw3_max_retries;
                if (!opgp_save_state(&st)) return SW_MEMORY_FAILURE();
            }
            pw3_verified = true;
            return SW_OK();
        }
        pw3_verified = false;
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
}

static int cmd_opgp_change_pin(void) {
    static opgp_state_t st;
    if (!opgp_load_state(&st)) return SW_EXEC_ERROR();
    uint8_t p1 = P1(apdu);
    uint8_t p2 = P2(apdu);
    if (p1 != 0x00 || (p2 != 0x81 && p2 != 0x83)) {
        return SW_INCORRECT_P1P2();
    }

    uint8_t old_len = (p2 == 0x81) ? st.pw1_len : st.pw3_len;
    uint8_t min_new = (opgp_kdf_alg(&st) == 0x03) ? 32 : ((p2 == 0x81) ? 6 : 8);
    if (apdu.nc < (size_t)(old_len + min_new) || (apdu.nc - old_len) > 127) {
        return SW_WRONG_LENGTH();
    }

    uint8_t h_old[32];
    opgp_sha256(apdu.data, old_len, h_old);

    if (p2 == 0x81) {
        if (st.pw1_retries == 0) return SW_PIN_BLOCKED();
        st.pw1_retries--;
        if (!opgp_save_state(&st)) return SW_MEMORY_FAILURE();
        if (mbedtls_ct_memcmp(h_old, st.pw1_hash, 32) != 0) {
            pw1_81_verified = false;
            pw1_82_verified = false;
            return SW_SECURITY_STATUS_NOT_SATISFIED();
        }
        opgp_sha256(apdu.data + old_len, apdu.nc - old_len, st.pw1_hash);
        st.pw1_len = (uint8_t)(apdu.nc - old_len);
        st.pw1_retries = st.pw1_max_retries;
        if (!opgp_save_state(&st)) return SW_MEMORY_FAILURE();
        return SW_OK();
    }
    else {
        if (st.pw3_retries == 0) return SW_PIN_BLOCKED();
        st.pw3_retries--;
        if (!opgp_save_state(&st)) return SW_MEMORY_FAILURE();
        if (mbedtls_ct_memcmp(h_old, st.pw3_hash, 32) != 0) {
            pw3_verified = false;
            return SW_SECURITY_STATUS_NOT_SATISFIED();
        }
        opgp_sha256(apdu.data + old_len, apdu.nc - old_len, st.pw3_hash);
        st.pw3_len = (uint8_t)(apdu.nc - old_len);
        st.pw3_retries = st.pw3_max_retries;
        if (!opgp_save_state(&st)) return SW_MEMORY_FAILURE();
        return SW_OK();
    }
}

static int cmd_opgp_reset_retry_counter(void) {
    static opgp_state_t st;
    if (!opgp_load_state(&st)) return SW_EXEC_ERROR();
    uint8_t p1 = P1(apdu);
    uint8_t p2 = P2(apdu);
    if (p2 != 0x81 || (p1 != 0x00 && p1 != 0x02)) {
        return SW_INCORRECT_P1P2();
    }
    uint8_t min_new = (opgp_kdf_alg(&st) == 0x03) ? 32 : 6;
    if (p1 == 0x02) {
        if (!pw3_verified) {
            return SW_SECURITY_STATUS_NOT_SATISFIED();
        }
        if (apdu.nc < min_new || apdu.nc > 127) {
            return SW_WRONG_LENGTH();
        }
        opgp_sha256(apdu.data, apdu.nc, st.pw1_hash);
        st.pw1_len = (uint8_t)apdu.nc;
        st.pw1_retries = st.pw1_max_retries;
        if (!opgp_save_state(&st)) return SW_MEMORY_FAILURE();
        return SW_OK();
    }
    else {
        if (st.rc_len == 0 || st.rc_retries == 0) {
            return SW_PIN_BLOCKED();
        }
        if (apdu.nc < (size_t)(st.rc_len + min_new) || (apdu.nc - st.rc_len) > 127) {
            return SW_WRONG_LENGTH();
        }
        uint8_t h_rc[32];
        opgp_sha256(apdu.data, st.rc_len, h_rc);
        st.rc_retries--;
        if (!opgp_save_state(&st)) return SW_MEMORY_FAILURE();
        if (mbedtls_ct_memcmp(h_rc, st.rc_hash, 32) != 0) {
            return SW_SECURITY_STATUS_NOT_SATISFIED();
        }
        st.rc_retries = st.rc_max_retries;
        opgp_sha256(apdu.data + st.rc_len, apdu.nc - st.rc_len, st.pw1_hash);
        st.pw1_len = (uint8_t)(apdu.nc - st.rc_len);
        st.pw1_retries = st.pw1_max_retries;
        if (!opgp_save_state(&st)) return SW_MEMORY_FAILURE();
        return SW_OK();
    }
}

static int cmd_opgp_set_pin_retries(void) {
    if (!pw3_verified) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (P1(apdu) != 0x00 || P2(apdu) != 0x00) {
        return SW_INCORRECT_P1P2();
    }
    if (apdu.nc != 3) {
        return SW_WRONG_LENGTH();
    }
    if (apdu.data[0] < 1 || apdu.data[1] < 1 || apdu.data[2] < 1) {
        return SW_WRONG_DATA();
    }
    static opgp_state_t st;
    if (!opgp_load_state(&st)) return SW_EXEC_ERROR();
    st.pw1_max_retries = apdu.data[0];
    st.pw1_retries = apdu.data[0];
    st.rc_max_retries = apdu.data[1];
    st.rc_retries = (st.rc_len > 0) ? apdu.data[1] : 0;
    st.pw3_max_retries = apdu.data[2];
    st.pw3_retries = apdu.data[2];
    if (!opgp_save_state(&st)) return SW_MEMORY_FAILURE();
    return SW_OK();
}

/* Parse CRT (B6 00 -> SIG, B8 00 -> DEC, A4 00 -> AUT, B6 03 84 01 81 -> ATT) */
static int opgp_parse_crt(const uint8_t *buf, size_t len) {
    if (len < 2) return -1;
    if (buf[0] == 0xB6) {
        if (len >= 5 && buf[1] == 0x03 && buf[2] == 0x84 && buf[3] == 0x01 && buf[4] == 0x81) {
            return OPGP_SLOT_ATT;
        }
        return OPGP_SLOT_SIG;
    }
    if (buf[0] == 0xB8) return OPGP_SLOT_DEC;
    if (buf[0] == 0xA4) return OPGP_SLOT_AUT;
    return -1;
}

static size_t opgp_encode_pubkey_7f49(const opgp_key_hdr_t *hdr, const uint8_t *pub, uint8_t *out) {
    static uint8_t inner[600];
    size_t off = 0;
    if (hdr->alg_id == OPGP_ALG_RSA) {
        off += put_tlv(inner + off, 0x0081, pub, hdr->pub_len);
        static const uint8_t exp[3] = { 0x01, 0x00, 0x01 };
        off += put_tlv(inner + off, 0x0082, exp, 3);
    }
    else {
        off += put_tlv(inner + off, 0x0086, pub, hdr->pub_len);
    }
    return put_tlv(out, 0x7F49, inner, off);
}

static int opgp_generate_slot_key(opgp_state_t *st, uint8_t slot, opgp_key_hdr_t *hdr_out, uint8_t *pub_out) {
    const uint8_t *attr = st->alg_attr[slot];
    size_t attr_len = st->alg_attr_len[slot];
    if (attr_len < 2) return -1;

    uint8_t alg_id = attr[0];
    static uint8_t pub_buf[600];
    static uint8_t priv_buf[1400];
    uint16_t pub_len = 0;
    uint16_t priv_len = 0;
    uint8_t grp_id = 0;
    uint16_t bits = 0;

    if (alg_id == OPGP_ALG_RSA) {
        bits = (uint16_t)((attr[1] << 8) | attr[2]);
        if (bits != 2048 && bits != 3072 && bits != 4096) return -1;
        uint16_t p_len = (uint16_t)(bits / 16);
        uint16_t n_len = (uint16_t)(bits / 8);
        mbedtls_rsa_context rsa;
        mbedtls_rsa_init(&rsa);
        int ret = mbedtls_rsa_gen_key(&rsa, opgp_rng, NULL, bits, 65537);
        if (ret == 0) {
            ret = mbedtls_mpi_write_binary(&rsa.N, pub_buf, n_len);
        }
        if (ret == 0) {
            ret = mbedtls_mpi_write_binary(&rsa.P, priv_buf, p_len);
        }
        if (ret == 0) {
            ret = mbedtls_mpi_write_binary(&rsa.Q, priv_buf + p_len, p_len);
        }
        mbedtls_rsa_free(&rsa);
        if (ret != 0) return -1;
        pub_len = n_len;
        priv_len = (uint16_t)(2 * p_len);
    }
    else {
        const opgp_curve_info_t *ci = opgp_find_curve_by_oid(attr + 1, attr_len - 1);
        if (!ci) return -1;
        grp_id = (uint8_t)ci->grp_id;
        bits = (uint16_t)(ci->coord_len * 8);
        mbedtls_ecp_keypair kp;
        mbedtls_ecp_keypair_init(&kp);
        int ret = -1;
        if (mbedtls_ecp_get_type(&kp.grp) == MBEDTLS_ECP_TYPE_NONE &&
            (ci->grp_id == MBEDTLS_ECP_DP_CURVE25519
#if defined(MBEDTLS_EDDSA_C)
             || ci->grp_id == MBEDTLS_ECP_DP_ED25519
#endif
            )) {
            random_fill_buffer(BYTE_ARRAY(priv_buf, 32));
            if (priv_buf[31] == 0) priv_buf[31] = 0x01;
            ret = mbedtls_ecp_group_load(&kp.grp, ci->grp_id);
            if (ret == 0) ret = mbedtls_ecp_read_key(ci->grp_id, &kp, priv_buf, 32);
            if (ret == 0) ret = mbedtls_ecp_keypair_calc_public(&kp, opgp_rng, NULL);
            if (ret == 0) {
                size_t olen = 0;
                ret = mbedtls_ecp_point_write_binary(&kp.grp, &kp.Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                                     &olen, pub_buf, sizeof(pub_buf));
                pub_len = (uint16_t)olen;
                priv_len = 32;
            }
        }
        else {
            ret = mbedtls_ecp_gen_key(ci->grp_id, &kp, opgp_rng, NULL);
            if (ret == 0) {
                priv_len = ci->coord_len;
                ret = mbedtls_mpi_write_binary(&kp.d, priv_buf, priv_len);
            }
            if (ret == 0) {
                size_t olen = 0;
                ret = mbedtls_ecp_point_write_binary(&kp.grp, &kp.Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                                     &olen, pub_buf, sizeof(pub_buf));
                pub_len = (uint16_t)olen;
            }
        }
        mbedtls_ecp_keypair_free(&kp);
        if (ret != 0) return -1;
    }

    if ((!opgp_txn.active && !applet_txn_begin(&opgp_txn)) ||
        opgp_store_key_record(slot, alg_id, grp_id, bits, pub_buf, pub_len, priv_buf, priv_len) != 0) {
        mbedtls_platform_zeroize(priv_buf, sizeof(priv_buf));
        return -1;
    }
    mbedtls_platform_zeroize(priv_buf, sizeof(priv_buf));

    st->key_status[slot] = OPGP_KEY_STATUS_GENERATED;
    if (slot == OPGP_SLOT_SIG) {
        st->sig_counter = 0;
    }
    if (!opgp_save_state(st)) return -1;

    if (hdr_out) {
        hdr_out->alg_id = alg_id;
        hdr_out->grp_id = grp_id;
        hdr_out->bits = bits;
        hdr_out->pub_len = pub_len;
        hdr_out->priv_len = priv_len;
    }
    if (pub_out) {
        memcpy(pub_out, pub_buf, pub_len);
    }
    return 0;
}

static bool opgp_ensure_att_key(opgp_state_t *st) {
    opgp_key_hdr_t hdr;
    if (file_has_data(file_search(EF_OPENPGP_KEY_BASE + OPGP_SLOT_ATT))) {
        return opgp_load_key_record(OPGP_SLOT_ATT, &hdr, NULL, 0, NULL, 0) == 0;
    }
    /* Provision default P-256 Attestation Key (fast & compact) */
    static const uint8_t att_p256_attr[9] = { 0x13, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
    memcpy(st->alg_attr[OPGP_SLOT_ATT], att_p256_attr, sizeof(att_p256_attr));
    st->alg_attr_len[OPGP_SLOT_ATT] = sizeof(att_p256_attr);
    return opgp_generate_slot_key(st, OPGP_SLOT_ATT, NULL, NULL) == 0;
}

static int cmd_opgp_generate_asym(void) {
    uint8_t p1 = P1(apdu);
    uint8_t p2 = P2(apdu);
    if (p2 != 0x00 || (p1 != 0x80 && p1 != 0x81)) {
        return SW_INCORRECT_P1P2();
    }
    int slot = opgp_parse_crt(apdu.data, apdu.nc);
    if (slot < 0) {
        return SW_WRONG_DATA();
    }

    static opgp_state_t st;
    if (!opgp_load_state(&st)) return SW_EXEC_ERROR();

    if (p1 == 0x80) {
        if (!pw3_verified) {
            return SW_SECURITY_STATUS_NOT_SATISFIED();
        }
        opgp_key_hdr_t hdr;
        static uint8_t pub[600];
        if (opgp_generate_slot_key(&st, (uint8_t)slot, &hdr, pub) != 0) {
            return opgp_txn.faulted ? SW_MEMORY_FAILURE() : SW_EXEC_ERROR();
        }
        res_APDU_size = (uint16_t)opgp_encode_pubkey_7f49(&hdr, pub, res_APDU);
        return SW_OK();
    }
    else {
        if (slot == OPGP_SLOT_ATT) {
            if (!opgp_ensure_att_key(&st)) return opgp_txn.faulted ? SW_MEMORY_FAILURE() : SW_EXEC_ERROR();
        }
        opgp_key_hdr_t hdr;
        static uint8_t pub[600];
        if (opgp_load_key_record((uint8_t)slot, &hdr, pub, sizeof(pub), NULL, 0) != 0) {
            return SW_REFERENCE_NOT_FOUND();
        }
        res_APDU_size = (uint16_t)opgp_encode_pubkey_7f49(&hdr, pub, res_APDU);
        return SW_OK();
    }
}

static int cmd_opgp_put_data_odd(void) {
    if (!pw3_verified) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (P1(apdu) != 0x3F || P2(apdu) != 0xFF) {
        return SW_INCORRECT_P1P2();
    }
    /* Parse outer 0x4D Extended Header List */
    size_t pos = 0;
    uint16_t outer_tag = 0;
    const uint8_t *outer_val = NULL;
    size_t outer_len = 0;
    if (!parse_tlv(apdu.data, apdu.nc, &pos, &outer_tag, &outer_val, &outer_len) || outer_tag != 0x004D) {
        return SW_WRONG_DATA();
    }

    int slot = -1;
    const uint8_t *tlist = NULL;
    size_t tlist_len = 0;
    const uint8_t *concat_data = NULL;
    size_t concat_len = 0;

    size_t ipos = 0;
    uint16_t t = 0;
    const uint8_t *v = NULL;
    size_t l = 0;
    while (parse_tlv(outer_val, outer_len, &ipos, &t, &v, &l)) {
        if (t == 0x00B6) {
            if (l == 3 && v[0] == 0x84 && v[1] == 0x01 && v[2] == 0x81) slot = OPGP_SLOT_ATT;
            else slot = OPGP_SLOT_SIG;
        }
        else if (t == 0x00B8) slot = OPGP_SLOT_DEC;
        else if (t == 0x00A4) slot = OPGP_SLOT_AUT;
        else if (t == 0x7F48) { tlist = v; tlist_len = l; }
        else if (t == 0x5F48) { concat_data = v; concat_len = l; }
    }
    if (slot < 0 || !tlist || !concat_data) {
        return SW_WRONG_DATA();
    }

    /* Parse 7F48 header list to locate 0x91 (e), 0x92 (p or d), 0x93 (q), 0x99 (pub) */
    const uint8_t *val_91 = NULL; size_t len_91 = 0;
    const uint8_t *val_92 = NULL; size_t len_92 = 0;
    const uint8_t *val_93 = NULL; size_t len_93 = 0;
    size_t hpos = 0;
    size_t dpos = 0;
    uint16_t htag = 0;
    const uint8_t * dummy_v = NULL;
    size_t hlen = 0;
    /* Note: 7F48 contains tag+length pairs without value bytes! */
    while (hpos < tlist_len) {
        htag = tlist[hpos++];
        if ((htag & 0x1F) == 0x1F) {
            if (hpos >= tlist_len) return SW_WRONG_DATA();
            htag = (uint16_t)((htag << 8) | tlist[hpos++]);
        }
        if (hpos >= tlist_len) return SW_WRONG_DATA();
        hlen = tlist[hpos++];
        if (hlen == 0x81) {
            if (hpos >= tlist_len) return SW_WRONG_DATA();
            hlen = tlist[hpos++];
        }
        else if (hlen == 0x82) {
            if (hpos + 1 >= tlist_len) return SW_WRONG_DATA();
            hlen = ((size_t)tlist[hpos] << 8) | tlist[hpos + 1];
            hpos += 2;
        }
        if (dpos + hlen > concat_len) return SW_WRONG_DATA();
        if (htag == 0x0091) { val_91 = concat_data + dpos; len_91 = hlen; }
        else if (htag == 0x0092) { val_92 = concat_data + dpos; len_92 = hlen; }
        else if (htag == 0x0093) { val_93 = concat_data + dpos; len_93 = hlen; }
        dpos += hlen;
    }
    (void)dummy_v;
    (void)val_91;
    (void)len_91;

    static opgp_state_t st;
    if (!opgp_load_state(&st)) return SW_EXEC_ERROR();
    const uint8_t *attr = st.alg_attr[slot];
    size_t attr_len = st.alg_attr_len[slot];
    uint8_t alg_id = attr[0];

    static uint8_t pub_buf[600];
    static uint8_t priv_buf[1400];
    uint16_t pub_len = 0;
    uint16_t priv_len = 0;
    uint8_t grp_id = 0;
    uint16_t bits = 0;

    if (alg_id == OPGP_ALG_RSA) {
        if (!val_92 || !val_93 || len_92 == 0 || len_92 != len_93 || len_92 > 256) {
            return SW_WRONG_DATA();
        }
        bits = (uint16_t)(len_92 * 16);
        pub_len = (uint16_t)(len_92 * 2);
        priv_len = (uint16_t)(len_92 * 2);
        memcpy(priv_buf, val_92, len_92);
        memcpy(priv_buf + len_92, val_93, len_93);

        mbedtls_mpi P, Q, N;
        mbedtls_mpi_init(&P); mbedtls_mpi_init(&Q); mbedtls_mpi_init(&N);
        int ret = mbedtls_mpi_read_binary(&P, val_92, len_92);
        if (ret == 0) ret = mbedtls_mpi_read_binary(&Q, val_93, len_93);
        if (ret == 0) ret = mbedtls_mpi_mul_mpi(&N, &P, &Q);
        if (ret == 0) ret = mbedtls_mpi_write_binary(&N, pub_buf, pub_len);
        mbedtls_mpi_free(&P); mbedtls_mpi_free(&Q); mbedtls_mpi_free(&N);
        if (ret != 0) return SW_WRONG_DATA();
    }
    else {
        const opgp_curve_info_t *ci = opgp_find_curve_by_oid(attr + 1, attr_len - 1);
        if (!ci || !val_92 || len_92 == 0 || len_92 > ci->coord_len) {
            return SW_WRONG_DATA();
        }
        grp_id = (uint8_t)ci->grp_id;
        bits = (uint16_t)(ci->coord_len * 8);
        priv_len = ci->coord_len;
        memset(priv_buf, 0, priv_len);
        if (ci->grp_id == MBEDTLS_ECP_DP_CURVE25519) {
            /* OpenPGP imports X25519 scalar in reversed (big-endian) byte order */
            if (len_92 != 32) return SW_WRONG_DATA();
            for (int i = 0; i < 32; i++) {
                priv_buf[i] = val_92[31 - i];
            }
        }
        else {
            memcpy(priv_buf + (priv_len - len_92), val_92, len_92);
        }
        mbedtls_ecp_keypair kp;
        mbedtls_ecp_keypair_init(&kp);
        int ret = mbedtls_ecp_group_load(&kp.grp, ci->grp_id);
        if (ret == 0) ret = mbedtls_ecp_read_key(ci->grp_id, &kp, priv_buf, priv_len);
        if (ret == 0) ret = mbedtls_ecp_keypair_calc_public(&kp, opgp_rng, NULL);
        if (ret == 0) {
            size_t olen = 0;
            ret = mbedtls_ecp_point_write_binary(&kp.grp, &kp.Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                                 &olen, pub_buf, sizeof(pub_buf));
            pub_len = (uint16_t)olen;
        }
        mbedtls_ecp_keypair_free(&kp);
        if (ret != 0) {
            mbedtls_platform_zeroize(priv_buf, sizeof(priv_buf));
            return SW_WRONG_DATA();
        }
    }

    if ((!opgp_txn.active && !applet_txn_begin(&opgp_txn)) ||
        opgp_store_key_record((uint8_t)slot, alg_id, grp_id, bits, pub_buf, pub_len, priv_buf, priv_len) != 0) {
        mbedtls_platform_zeroize(priv_buf, sizeof(priv_buf));
        return SW_MEMORY_FAILURE();
    }
    mbedtls_platform_zeroize(priv_buf, sizeof(priv_buf));
    st.key_status[slot] = OPGP_KEY_STATUS_IMPORTED;
    if (slot == OPGP_SLOT_SIG) {
        st.sig_counter = 0;
    }
    if (!opgp_save_state(&st)) return SW_MEMORY_FAILURE();
    return SW_OK();
}

static int opgp_sign_with_slot(opgp_state_t *st, uint8_t slot) {
    if (!opgp_check_touch(st->uif[slot][0])) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    opgp_key_hdr_t hdr;
    static uint8_t pub[600];
    static uint8_t priv[1400];
    if (opgp_load_key_record(slot, &hdr, pub, sizeof(pub), priv, sizeof(priv)) != 0) {
        return SW_REFERENCE_NOT_FOUND();
    }

    int rc = SW_EXEC_ERROR();
    if (hdr.alg_id == OPGP_ALG_RSA) {
        uint16_t n_len = hdr.pub_len;
        uint16_t p_len = (uint16_t)(hdr.priv_len / 2);
        if (apdu.nc > (size_t)(n_len - 11)) {
            mbedtls_platform_zeroize(priv, sizeof(priv));
            return SW_WRONG_LENGTH();
        }
        /* Build PKCS#1 v1.5 Type 1 block: 00 01 FF..FF 00 || apdu.data */
        static uint8_t em[512];
        em[0] = 0x00;
        em[1] = 0x01;
        size_t ps_len = n_len - 3 - apdu.nc;
        memset(em + 2, 0xFF, ps_len);
        em[2 + ps_len] = 0x00;
        memcpy(em + 3 + ps_len, apdu.data, apdu.nc);

        mbedtls_rsa_context rsa;
        mbedtls_rsa_init(&rsa);
        uint8_t exp[3] = { 0x01, 0x00, 0x01 };
        int ret = mbedtls_rsa_import_raw(&rsa, pub, n_len, priv, p_len, priv + p_len, p_len, NULL, 0, exp, 3);
        if (ret == 0) ret = mbedtls_rsa_complete(&rsa);
        if (ret == 0) ret = mbedtls_rsa_private(&rsa, opgp_rng, NULL, em, res_APDU);
        mbedtls_rsa_free(&rsa);
        if (ret == 0) {
            res_APDU_size = n_len;
            rc = SW_OK();
        }
    }
#if defined(MBEDTLS_EDDSA_C)
    else if (hdr.alg_id == OPGP_ALG_EDDSA || hdr.grp_id == MBEDTLS_ECP_DP_ED25519) {
        mbedtls_ecp_keypair kp;
        mbedtls_ecp_keypair_init(&kp);
        size_t sig_len = 0;
        int ret = mbedtls_ecp_group_load(&kp.grp, MBEDTLS_ECP_DP_ED25519);
        if (ret == 0) ret = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_ED25519, &kp, priv, hdr.priv_len);
        if (ret == 0) {
            ret = mbedtls_eddsa_write_signature(&kp, apdu.data, apdu.nc,
                                                res_APDU, 128, &sig_len,
                                                MBEDTLS_EDDSA_PURE, NULL, 0,
                                                opgp_rng, NULL);
        }
        mbedtls_ecp_keypair_free(&kp);
        if (ret == 0) {
            res_APDU_size = (uint16_t)sig_len;
            rc = SW_OK();
        }
    }
#endif
    else if (hdr.alg_id == OPGP_ALG_ECDSA) {
        const opgp_curve_info_t *ci = opgp_find_curve_by_grp((mbedtls_ecp_group_id)hdr.grp_id);
        if (ci) {
            mbedtls_ecp_group grp;
            mbedtls_mpi d, r, s;
            mbedtls_ecp_group_init(&grp);
            mbedtls_mpi_init(&d); mbedtls_mpi_init(&r); mbedtls_mpi_init(&s);
            int ret = mbedtls_ecp_group_load(&grp, ci->grp_id);
            if (ret == 0) ret = mbedtls_mpi_read_binary(&d, priv, hdr.priv_len);
            if (ret == 0) {
                ret = mbedtls_ecdsa_sign(&grp, &r, &s, &d, apdu.data, apdu.nc, opgp_rng, NULL);
            }
            if (ret == 0) {
                memset(res_APDU, 0, (size_t)(2 * ci->coord_len));
                ret = mbedtls_mpi_write_binary(&r, res_APDU, ci->coord_len);
                if (ret == 0) {
                    ret = mbedtls_mpi_write_binary(&s, res_APDU + ci->coord_len, ci->coord_len);
                }
            }
            mbedtls_ecp_group_free(&grp);
            mbedtls_mpi_free(&d); mbedtls_mpi_free(&r); mbedtls_mpi_free(&s);
            if (ret == 0) {
                res_APDU_size = (uint16_t)(2 * ci->coord_len);
                rc = SW_OK();
            }
        }
    }

    mbedtls_platform_zeroize(priv, sizeof(priv));
    if (rc == SW_OK() && slot == OPGP_SLOT_SIG) {
        if (st->sig_counter == UINT32_MAX) {
            mbedtls_platform_zeroize(res_APDU, res_APDU_size);
            return SW_CONDITIONS_NOT_SATISFIED();
        }
        st->sig_counter++;
        if (!opgp_save_state(st)) {
            mbedtls_platform_zeroize(res_APDU, res_APDU_size);
            pw1_81_verified = false;
            return SW_MEMORY_FAILURE();
        }
        if (st->pw1_policy == 0) {
            pw1_81_verified = false;
        }
    }
    return rc;
}

static int cmd_opgp_pso(void) {
    uint16_t p1p2 = (uint16_t)((P1(apdu) << 8) | P2(apdu));
    static opgp_state_t st;
    if (!opgp_load_state(&st)) return SW_EXEC_ERROR();

    if (p1p2 == 0x9E9A) {
        /* Compute Digital Signature */
        if (!pw1_81_verified) {
            return SW_SECURITY_STATUS_NOT_SATISFIED();
        }
        return opgp_sign_with_slot(&st, OPGP_SLOT_SIG);
    }
    else if (p1p2 == 0x8086) {
        /* Decipher */
        if (!pw1_82_verified) {
            return SW_SECURITY_STATUS_NOT_SATISFIED();
        }
        if (!opgp_check_touch(st.uif[OPGP_SLOT_DEC][0])) {
            return SW_SECURITY_STATUS_NOT_SATISFIED();
        }
        opgp_key_hdr_t hdr;
        static uint8_t pub[600];
        static uint8_t priv[1400];
        if (opgp_load_key_record(OPGP_SLOT_DEC, &hdr, pub, sizeof(pub), priv, sizeof(priv)) != 0) {
            return SW_REFERENCE_NOT_FOUND();
        }
        int rc = SW_EXEC_ERROR();
        if (hdr.alg_id == OPGP_ALG_RSA) {
            uint16_t n_len = hdr.pub_len;
            uint16_t p_len = (uint16_t)(hdr.priv_len / 2);
            /* Expect padding indicator 0x00 || ciphertext */
            const uint8_t *ct = apdu.data;
            size_t ct_len = apdu.nc;
            if (ct_len == (size_t)(n_len + 1) && ct[0] == 0x00) {
                ct++;
                ct_len--;
            }
            if (ct_len != n_len) {
                mbedtls_platform_zeroize(priv, sizeof(priv));
                return SW_WRONG_LENGTH();
            }
            static uint8_t block[512];
            mbedtls_rsa_context rsa;
            mbedtls_rsa_init(&rsa);
            uint8_t exp[3] = { 0x01, 0x00, 0x01 };
            int ret = mbedtls_rsa_import_raw(&rsa, pub, n_len, priv, p_len, priv + p_len, p_len, NULL, 0, exp, 3);
            if (ret == 0) ret = mbedtls_rsa_complete(&rsa);
            if (ret == 0) ret = mbedtls_rsa_private(&rsa, opgp_rng, NULL, ct, block);
            mbedtls_rsa_free(&rsa);
            if (ret == 0 && block[0] == 0x00 && block[1] == 0x02) {
                size_t idx = 2;
                while (idx < n_len && block[idx] != 0x00) {
                    idx++;
                }
                if (idx >= 10 && idx < n_len && block[idx] == 0x00) {
                    idx++;
                    res_APDU_size = (uint16_t)(n_len - idx);
                    memcpy(res_APDU, block + idx, res_APDU_size);
                    rc = SW_OK();
                }
            }
            mbedtls_platform_zeroize(block, sizeof(block));
        }
        else {
            /* ECDH: parse A6 -> 7F49 -> 86 <peer_pub> */
            size_t pos = 0, p2_pos = 0, p3_pos = 0;
            uint16_t t1 = 0, t2 = 0, t3 = 0;
            const uint8_t *v1 = NULL, *v2 = NULL, *peer_pub = NULL;
            size_t l1 = 0, l2 = 0, peer_len = 0;
            if (!parse_tlv(apdu.data, apdu.nc, &pos, &t1, &v1, &l1) || t1 != 0x00A6 ||
                !parse_tlv(v1, l1, &p2_pos, &t2, &v2, &l2) || t2 != 0x7F49 ||
                !parse_tlv(v2, l2, &p3_pos, &t3, &peer_pub, &peer_len) || t3 != 0x0086) {
                mbedtls_platform_zeroize(priv, sizeof(priv));
                return SW_WRONG_DATA();
            }
            mbedtls_ecp_group grp;
            mbedtls_ecp_point Qp;
            mbedtls_mpi d, z;
            mbedtls_ecp_group_init(&grp);
            mbedtls_ecp_point_init(&Qp);
            mbedtls_mpi_init(&d);
            mbedtls_mpi_init(&z);
            int ret = mbedtls_ecp_group_load(&grp, (mbedtls_ecp_group_id)hdr.grp_id);
            if (ret == 0) {
                if (hdr.grp_id == MBEDTLS_ECP_DP_CURVE25519) {
                    mbedtls_ecp_keypair kp;
                    mbedtls_ecp_keypair_init(&kp);
                    ret = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_CURVE25519, &kp, priv, hdr.priv_len);
                    if (ret == 0) ret = mbedtls_mpi_copy(&d, &kp.d);
                    mbedtls_ecp_keypair_free(&kp);
                }
                else {
                    ret = mbedtls_mpi_read_binary(&d, priv, hdr.priv_len);
                }
            }
            if (ret == 0) ret = mbedtls_ecp_point_read_binary(&grp, &Qp, peer_pub, peer_len);
            if (ret == 0) ret = mbedtls_ecdh_compute_shared(&grp, &z, &Qp, &d, opgp_rng, NULL);
            if (ret == 0) {
                size_t plen = (grp.pbits + 7) / 8;
                if (hdr.grp_id == MBEDTLS_ECP_DP_CURVE25519) {
                    ret = mbedtls_mpi_write_binary_le(&z, res_APDU, plen);
                }
                else {
                    ret = mbedtls_mpi_write_binary(&z, res_APDU, plen);
                }
                if (ret == 0) {
                    res_APDU_size = (uint16_t)plen;
                    rc = SW_OK();
                }
            }
            mbedtls_ecp_group_free(&grp);
            mbedtls_ecp_point_free(&Qp);
            mbedtls_mpi_free(&d);
            mbedtls_mpi_free(&z);
        }
        mbedtls_platform_zeroize(priv, sizeof(priv));
        return rc;
    }
    return SW_INCORRECT_P1P2();
}

static int cmd_opgp_internal_authenticate(void) {
    if (P1(apdu) != 0x00 || P2(apdu) != 0x00) {
        return SW_INCORRECT_P1P2();
    }
    if (!pw1_82_verified) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    static opgp_state_t st;
    if (!opgp_load_state(&st)) return SW_EXEC_ERROR();
    return opgp_sign_with_slot(&st, OPGP_SLOT_AUT);
}

static int cmd_opgp_get_challenge(void) {
    if (P1(apdu) != 0x00 || P2(apdu) != 0x00) {
        return SW_INCORRECT_P1P2();
    }
    uint16_t le = (apdu.ne == 0 || apdu.ne > 255) ? 255 : (uint16_t)apdu.ne;
    random_fill_buffer(BYTE_ARRAY(res_APDU, le));
    res_APDU_size = le;
    return SW_OK();
}

static int cmd_opgp_get_version(void) {
    if (P1(apdu) != 0x00 || P2(apdu) != 0x00) {
        return SW_INCORRECT_P1P2();
    }
    res_APDU[0] = 0x05;
    res_APDU[1] = 0x07;
    res_APDU[2] = 0x02;
    res_APDU_size = 3;
    return SW_OK();
}

static int cmd_opgp_terminate(void) {
    if (P1(apdu) != 0x00 || P2(apdu) != 0x00) {
        return SW_INCORRECT_P1P2();
    }
    static opgp_state_t st;
    if (!opgp_load_state(&st)) return SW_EXEC_ERROR();
    if (!pw3_verified && !(st.pw1_retries == 0 && st.pw3_retries == 0)) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    st.terminated = 1;
    if (!opgp_save_state(&st)) return SW_MEMORY_FAILURE();
    return SW_OK();
}

static int cmd_opgp_activate(void) {
    if (P1(apdu) != 0x00 || P2(apdu) != 0x00) {
        return SW_INCORRECT_P1P2();
    }
    static opgp_state_t st;
    if (!opgp_load_state(&st)) return SW_EXEC_ERROR();
    if (st.terminated) {
        if ((!opgp_txn.active && !applet_txn_begin(&opgp_txn)) || !opgp_factory_reset()) return SW_MEMORY_FAILURE();
    }
    return SW_OK();
}

/* Minimal DER builder for OpenPGP INS_GET_ATTESTATION (0xFB) */
static size_t der_wrap(uint8_t *out, uint8_t tag, const uint8_t *val, size_t len) {
    return put_tlv(out, tag, val, len);
}

static int cmd_opgp_get_attestation(void) {
    uint8_t key_ref = P1(apdu);
    if (P2(apdu) != 0x00 || (key_ref != 0x01 && key_ref != 0x02 && key_ref != 0x03)) {
        return SW_INCORRECT_P1P2();
    }
    if (!pw1_81_verified && !pw1_82_verified) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    uint8_t slot = (uint8_t)(key_ref - 1);
    static opgp_state_t st;
    if (!opgp_load_state(&st)) return SW_EXEC_ERROR();
    if (!opgp_check_touch(st.uif[OPGP_SLOT_ATT][0])) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (!opgp_ensure_att_key(&st)) return opgp_txn.faulted ? SW_MEMORY_FAILURE() : SW_EXEC_ERROR();

    opgp_key_hdr_t subj_hdr, att_hdr;
    static uint8_t subj_pub[600], att_pub[600], att_priv[1400];
    if (opgp_load_key_record(slot, &subj_hdr, subj_pub, sizeof(subj_pub), NULL, 0) != 0) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (opgp_load_key_record(OPGP_SLOT_ATT, &att_hdr, att_pub, sizeof(att_pub), att_priv, sizeof(att_priv)) != 0) {
        return SW_REFERENCE_NOT_FOUND();
    }

    /* Build SubjectPublicKeyInfo for subj_hdr */
    static uint8_t spki[660];
    size_t spki_len = 0;
    if (subj_hdr.alg_id == OPGP_ALG_RSA) {
        static const uint8_t rsa_alg_id[] = { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };
        static uint8_t mod_int[520], rsapub[540], bitstr[548];
        mod_int[0] = 0x00;
        memcpy(mod_int + 1, subj_pub, subj_hdr.pub_len);
        size_t m_off = der_wrap(rsapub, 0x02, mod_int, (size_t)(subj_hdr.pub_len + 1));
        static const uint8_t e_der[] = { 0x02, 0x03, 0x01, 0x00, 0x01 };
        memcpy(rsapub + m_off, e_der, sizeof(e_der));
        size_t seq_len = der_wrap(bitstr + 1, 0x30, rsapub, m_off + sizeof(e_der));
        bitstr[0] = 0x00;
        static uint8_t spki_inner[580];
        memcpy(spki_inner, rsa_alg_id, sizeof(rsa_alg_id));
        size_t bs_len = der_wrap(spki_inner + sizeof(rsa_alg_id), 0x03, bitstr, seq_len + 1);
        spki_len = der_wrap(spki, 0x30, spki_inner, sizeof(rsa_alg_id) + bs_len);
    }
#if defined(MBEDTLS_EDDSA_C)
    else if (subj_hdr.grp_id == MBEDTLS_ECP_DP_ED25519) {
        static const uint8_t ed_hdr[] = { 0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00 };
        memcpy(spki, ed_hdr, sizeof(ed_hdr));
        memcpy(spki + sizeof(ed_hdr), subj_pub, 32);
        spki_len = sizeof(ed_hdr) + 32;
    }
#endif
    else if (subj_hdr.grp_id == MBEDTLS_ECP_DP_CURVE25519) {
        static const uint8_t x_hdr[] = { 0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x6E, 0x03, 0x21, 0x00 };
        memcpy(spki, x_hdr, sizeof(x_hdr));
        memcpy(spki + sizeof(x_hdr), subj_pub, 32);
        spki_len = sizeof(x_hdr) + 32;
    }
    else {
        const opgp_curve_info_t *ci = opgp_find_curve_by_grp((mbedtls_ecp_group_id)subj_hdr.grp_id);
        if (!ci) {
            mbedtls_platform_zeroize(att_priv, sizeof(att_priv));
            return SW_EXEC_ERROR();
        }
        uint8_t alg_inner[32], alg_seq[36], bitstr[140], spki_inner[180];
        static const uint8_t id_ecpub[] = { 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
        memcpy(alg_inner, id_ecpub, sizeof(id_ecpub));
        size_t oid_l = der_wrap(alg_inner + sizeof(id_ecpub), 0x06, ci->oid, ci->oid_len);
        size_t alg_l = der_wrap(alg_seq, 0x30, alg_inner, sizeof(id_ecpub) + oid_l);
        bitstr[0] = 0x00;
        memcpy(bitstr + 1, subj_pub, subj_hdr.pub_len);
        memcpy(spki_inner, alg_seq, alg_l);
        size_t bs_l = der_wrap(spki_inner + alg_l, 0x03, bitstr, (size_t)(subj_hdr.pub_len + 1));
        spki_len = der_wrap(spki, 0x30, spki_inner, alg_l + bs_l);
    }

    /* Build TBSCertificate signed with ECDSA-with-SHA256 (or RSA-with-SHA256) */
    static const uint8_t tbs_prefix_ecdsa[] = {
        0xA0, 0x03, 0x02, 0x01, 0x02, /* v3 */
        0x02, 0x08, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, /* serial */
        0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, /* ecdsa-with-SHA256 */
        /* Issuer: CN=Yubico OpenPGP Attestation */
        0x30, 0x25, 0x31, 0x23, 0x30, 0x21, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x1A,
        'Y','u','b','i','c','o',' ','O','p','e','n','P','G','P',' ','A','t','t','e','s','t','a','t','i','o','n',
        /* Validity: 2025-01-01 to 2055-01-01 */
        0x30, 0x22, 0x18, 0x0F, '2','0','2','5','0','1','0','1','0','0','0','0','0','0','Z',
        0x18, 0x0F, '2','0','5','5','0','1','0','1','0','0','0','0','0','0','Z',
        /* Subject: CN=YubiKey OpenPGP Key */
        0x30, 0x1E, 0x31, 0x1C, 0x30, 0x1A, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x13,
        'Y','u','b','i','K','e','y',' ','O','p','e','n','P','G','P',' ','K','e','y'
    };
    static uint8_t tbs_inner[900], tbs[910];
    memcpy(tbs_inner, tbs_prefix_ecdsa, sizeof(tbs_prefix_ecdsa));
    memcpy(tbs_inner + sizeof(tbs_prefix_ecdsa), spki, spki_len);
    size_t tbs_len = der_wrap(tbs, 0x30, tbs_inner, sizeof(tbs_prefix_ecdsa) + spki_len);

    uint8_t digest[32];
    opgp_sha256(tbs, tbs_len, digest);

    uint8_t sig_der[160];
    size_t sig_der_len = 0;
    int ret = -1;
    if (att_hdr.alg_id == OPGP_ALG_ECDSA) {
        const opgp_curve_info_t *ci = opgp_find_curve_by_grp((mbedtls_ecp_group_id)att_hdr.grp_id);
        if (ci) {
            mbedtls_ecp_keypair kp;
            mbedtls_ecp_keypair_init(&kp);
            ret = mbedtls_ecp_group_load(&kp.grp, ci->grp_id);
            if (ret == 0) ret = mbedtls_ecp_read_key(ci->grp_id, &kp, att_priv, att_hdr.priv_len);
            if (ret == 0) {
                ret = mbedtls_ecdsa_write_signature(&kp, MBEDTLS_MD_SHA256, digest, 32,
                                                    sig_der, sizeof(sig_der), &sig_der_len,
                                                    opgp_rng, NULL);
            }
            mbedtls_ecp_keypair_free(&kp);
        }
    }
    mbedtls_platform_zeroize(att_priv, sizeof(att_priv));
    if (ret != 0) {
        return SW_EXEC_ERROR();
    }

    static const uint8_t sig_alg_ecdsa[] = { 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };
    static uint8_t sig_bs[168], cert_inner[1150];
    sig_bs[0] = 0x00;
    memcpy(sig_bs + 1, sig_der, sig_der_len);
    memcpy(cert_inner, tbs, tbs_len);
    memcpy(cert_inner + tbs_len, sig_alg_ecdsa, sizeof(sig_alg_ecdsa));
    size_t sbs_l = der_wrap(cert_inner + tbs_len + sizeof(sig_alg_ecdsa), 0x03, sig_bs, sig_der_len + 1);
    size_t cert_len = der_wrap(res_APDU, 0x30, cert_inner, tbs_len + sizeof(sig_alg_ecdsa) + sbs_l);

    /* Store into certificate slot for key_ref */
    uint16_t fid = (uint16_t)(EF_OPENPGP_CERT_BASE + slot);
    if ((!opgp_txn.active && !applet_txn_begin(&opgp_txn)) || !opgp_record_save(fid, res_APDU, cert_len)) {
        mbedtls_platform_zeroize(res_APDU, cert_len);
        return SW_MEMORY_FAILURE();
    }
    res_APDU_size = (uint16_t)cert_len;
    return SW_OK();
}

static int openpgp_unload(void) {
    apdu_clear_response_buffer();
    pw1_81_verified = false;
    pw1_82_verified = false;
    pw3_verified = false;
    selected_cert_occurrence = 0;
    return PICOKEYS_OK;
}

static int openpgp_dispatch(uint8_t ins) {
    switch (ins) {
        case OPGP_INS_VERIFY:
            return cmd_opgp_verify();
        case OPGP_INS_CHANGE_PIN:
            return cmd_opgp_change_pin();
        case OPGP_INS_RESET_RETRY_COUNTER:
            return cmd_opgp_reset_retry_counter();
        case OPGP_INS_SET_PIN_RETRIES:
            return cmd_opgp_set_pin_retries();
        case OPGP_INS_SELECT_DATA:
            return cmd_opgp_select_data();
        case OPGP_INS_GET_DATA:
            return cmd_opgp_get_data();
        case OPGP_INS_PUT_DATA:
            return cmd_opgp_put_data();
        case OPGP_INS_PUT_DATA_ODD:
            return cmd_opgp_put_data_odd();
        case OPGP_INS_GENERATE_ASYM:
            return cmd_opgp_generate_asym();
        case OPGP_INS_PSO:
            return cmd_opgp_pso();
        case OPGP_INS_INTERNAL_AUTHENTICATE:
            return cmd_opgp_internal_authenticate();
        case OPGP_INS_GET_CHALLENGE:
            return cmd_opgp_get_challenge();
        case OPGP_INS_GET_VERSION:
            return cmd_opgp_get_version();
        case OPGP_INS_GET_ATTESTATION:
            return cmd_opgp_get_attestation();
        case OPGP_INS_TERMINATE:
            return cmd_opgp_terminate();
        case OPGP_INS_ACTIVATE:
            return cmd_opgp_activate();
        default:
            return SW_INS_NOT_SUPPORTED();
    }
}

static int openpgp_process_apdu(void) {
    if (!cap_supported(CAP_OPENPGP)) return SW_INS_NOT_SUPPORTED();
    uint8_t ins = INS(apdu);
    static opgp_state_t st;
    if (!opgp_load_state(&st)) {
        openpgp_unload();
        if (ins == OPGP_INS_ACTIVATE && ((P1(apdu) == 0xDE && P2(apdu) == 0xAD) || (P1(apdu) == 0x00 && P2(apdu) == 0x00)) && apdu.nc == 0) {
#ifdef ENABLE_EMULATION
            if (!check_user_presence()) return SW_SECURITY_STATUS_NOT_SATISFIED();
#endif
            if (!applet_txn_recover_begin(&opgp_txn) || !opgp_factory_reset() ||
                !applet_txn_commit(&opgp_txn)) return SW_MEMORY_FAILURE();
            return SW_OK();
        }
        return SW_EXEC_ERROR();
    }
    if (st.terminated && ins != OPGP_INS_ACTIVATE && ins != OPGP_INS_GET_DATA && ins != OPGP_INS_GET_VERSION)
        return SW_CONDITIONS_NOT_SATISFIED();
    int ret = openpgp_dispatch(ins);
    if ((opgp_txn.active && !applet_txn_commit(&opgp_txn)) || opgp_txn.faulted) {
        mbedtls_platform_zeroize(res_APDU, res_APDU_size);
        openpgp_unload();
        return SW_MEMORY_FAILURE();
    }
    return ret;
}

static const uint8_t openpgp_aid[] = {
    6,
    0xD2, 0x76, 0x00, 0x01, 0x24, 0x01
};

static int openpgp_select_aid(app_t *a, uint8_t force) {
    (void)force;
    if (!cap_supported(CAP_OPENPGP)) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    a->process_apdu = openpgp_process_apdu;
    a->unload = openpgp_unload;
    pw1_81_verified = false;
    pw1_82_verified = false;
    pw3_verified = false;
    selected_cert_occurrence = 0;
    return PICOKEYS_OK;
}

INITIALIZER(openpgp_ctor) {
    register_app(openpgp_select_aid, openpgp_aid);
}
