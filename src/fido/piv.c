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
#include "random.h"
#include "serial.h"
#include "tlv.h"
#include "crypto_utils.h"
#include "management.h"
#include "fido.h"
#include "button.h"
#include "pico_time.h"
#include "mbedtls/aes.h"
#include "mbedtls/des.h"
#include "mbedtls/rsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecdh.h"
#ifdef MBEDTLS_EDDSA_C
#include "mbedtls/eddsa.h"
#endif
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/constant_time.h"
#include "mbedtls/platform_util.h"

#define PIV_VERSION_MAJOR 5
#define PIV_VERSION_MINOR 7
#define PIV_VERSION_PATCH 2

#define INS_VERIFY                  0x20
#define INS_CHANGE_REFERENCE        0x24
#define INS_RESET_RETRY             0x2C
#define INS_GENERATE_ASYMMETRIC     0x47
#define INS_AUTHENTICATE            0x87
#define INS_GET_DATA                0xCB
#define INS_PUT_DATA                0xDB
#define INS_MOVE_KEY                0xF6
#define INS_GET_METADATA            0xF7
#define INS_GET_SERIAL              0xF8
#define INS_ATTEST                  0xF9
#define INS_SET_PIN_RETRIES         0xFA
#define INS_RESET                   0xFB
#define INS_GET_VERSION             0xFD
#define INS_IMPORT_KEY              0xFE
#define INS_SET_MGMKEY              0xFF

#define PIV_ALG_3DES                0x03
#define PIV_ALG_RSA3072             0x05
#define PIV_ALG_RSA1024             0x06
#define PIV_ALG_RSA2048             0x07
#define PIV_ALG_AES128              0x08
#define PIV_ALG_AES192              0x0A
#define PIV_ALG_AES256              0x0C
#define PIV_ALG_ECCP256             0x11
#define PIV_ALG_ECCP384             0x14
#define PIV_ALG_RSA4096             0x16
#define PIV_ALG_ED25519             0xE0
#define PIV_ALG_X25519              0xE1

#define PIV_SLOT_AUTH               0x9A
#define PIV_SLOT_CARD_MGM           0x9B
#define PIV_SLOT_SIGNATURE          0x9C
#define PIV_SLOT_KEY_MGM            0x9D
#define PIV_SLOT_CARD_AUTH          0x9E
#define PIV_SLOT_RETIRED_FIRST      0x82
#define PIV_SLOT_RETIRED_LAST       0x95
#define PIV_SLOT_OCC_AUTH           0x96
#define PIV_SLOT_ATTESTATION        0xF9

#define PIV_PIN_P2                  0x80
#define PIV_PUK_P2                  0x81

#define PIV_PIN_POLICY_DEFAULT      0x00
#define PIV_PIN_POLICY_NEVER        0x01
#define PIV_PIN_POLICY_ONCE         0x02
#define PIV_PIN_POLICY_ALWAYS       0x03

#define PIV_TOUCH_POLICY_DEFAULT    0x00
#define PIV_TOUCH_POLICY_NEVER      0x01
#define PIV_TOUCH_POLICY_ALWAYS     0x02
#define PIV_TOUCH_POLICY_CACHED     0x03

#define PIV_ORIGIN_GENERATED        0x01
#define PIV_ORIGIN_IMPORTED         0x02

#define TAG_OBJ_DATA                0x53
#define TAG_OBJ_ID                  0x5C
#define TAG_DYN_AUTH                0x7C
#define TAG_AUTH_WITNESS            0x80
#define TAG_AUTH_CHALLENGE          0x81
#define TAG_AUTH_RESPONSE           0x82
#define TAG_AUTH_EXPONENTIATION     0x85
#define TAG_GEN_ALGORITHM           0x80
#define TAG_PIN_POLICY              0xAA
#define TAG_TOUCH_POLICY            0xAB

#define TAG_METADATA_ALGO           0x01
#define TAG_METADATA_POLICY         0x02
#define TAG_METADATA_ORIGIN         0x03
#define TAG_METADATA_PUBLIC_KEY     0x04
#define TAG_METADATA_IS_DEFAULT     0x05
#define TAG_METADATA_RETRIES        0x06

#define PIV_SLOT_COUNT              25
#define PIV_PIN_LEN                 8
#define PIV_MGM_MAX_KEY_LEN         32
#define PIV_TOUCH_CACHE_MS          15000u

#define PIV_SECURE_OVERHEAD         (12u + 16u)
#define PIV_STATE_MAGIC             0x50495631u
#define PIV_KEY_MAGIC               0x504B5931u

typedef struct {
    uint32_t magic;
    uint8_t pin[PIV_PIN_LEN];
    uint8_t puk[PIV_PIN_LEN];
    uint8_t max_pin_retries;
    uint8_t pin_retries;
    uint8_t max_puk_retries;
    uint8_t puk_retries;
    uint8_t pin_is_default;
    uint8_t puk_is_default;
    uint8_t mgm_type;
    uint8_t mgm_len;
    uint8_t mgm_touch_policy;
    uint8_t mgm_is_default;
    uint8_t mgm_key[PIV_MGM_MAX_KEY_LEN];
} piv_state_t;

typedef struct {
    uint32_t magic;
    uint8_t key_type;
    uint8_t pin_policy;
    uint8_t touch_policy;
    uint8_t origin;
    uint16_t pub_len;
    uint16_t priv_len;
} piv_key_header_t;

static const uint8_t piv_default_pin[PIV_PIN_LEN] = { '1', '2', '3', '4', '5', '6', 0xFF, 0xFF };
static const uint8_t piv_default_puk[PIV_PIN_LEN] = { '1', '2', '3', '4', '5', '6', '7', '8' };
static const uint8_t piv_default_mgm[24] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
};

static const uint8_t piv_aid[] = {
    5,
    0xA0, 0x00, 0x00, 0x03, 0x08
};

static bool piv_pin_verified = false;
static bool piv_pin_verified_once_used = false;
static bool piv_mgm_authenticated = false;
static bool piv_mgm_challenge_valid = false;
static uint8_t piv_mgm_challenge[16] = { 0 };
static uint8_t piv_mgm_challenge_len = 0;
static uint32_t piv_last_touch_ms = 0;

static int piv_process_apdu(void);
static int piv_unload(void);
static int piv_ensure_attestation_ready(void);

static int piv_derive_master_key(uint8_t key[32]) {
    uint8_t kbase[32];
    derive_kbase(kbase);
    int ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                           pico_serial_hash, sizeof(pico_serial_hash),
                           kbase, sizeof(kbase),
                           (const uint8_t *)"PIV/MASTER/V1", 13,
                           key, 32);
    mbedtls_platform_zeroize(kbase, sizeof(kbase));
    return ret == 0 ? PICOKEYS_OK : PICOKEYS_EXEC_ERROR;
}

static bool piv_check_touch(uint8_t touch_policy) {
    if (touch_policy != PIV_TOUCH_POLICY_ALWAYS && touch_policy != PIV_TOUCH_POLICY_CACHED) {
        return true;
    }
    uint32_t now = board_millis();
    if (touch_policy == PIV_TOUCH_POLICY_CACHED && piv_last_touch_ms != 0 && (now - piv_last_touch_ms) < PIV_TOUCH_CACHE_MS) {
        return true;
    }
#ifdef ENABLE_EMULATION
    bool ok = check_user_presence();
#else
    uint32_t timeout_s = button_timeout_seconds();
    if (timeout_s == 0) {
        timeout_s = 15;
    }
    bool ok = (wait_button_pressed_timeout(timeout_s) == 0);
#endif
    if (ok && touch_policy == PIV_TOUCH_POLICY_CACHED) {
        piv_last_touch_ms = board_millis();
        if (piv_last_touch_ms == 0) {
            piv_last_touch_ms = 1;
        }
    }
    return ok;
}

static int piv_slot_index(uint8_t slot) {
    switch (slot) {
        case PIV_SLOT_AUTH: return 0;
        case PIV_SLOT_SIGNATURE: return 1;
        case PIV_SLOT_KEY_MGM: return 2;
        case PIV_SLOT_CARD_AUTH: return 3;
        case PIV_SLOT_ATTESTATION: return 24;
        default:
            if (slot >= PIV_SLOT_RETIRED_FIRST && slot <= PIV_SLOT_RETIRED_LAST) {
                return 4 + (int)(slot - PIV_SLOT_RETIRED_FIRST);
            }
            return -1;
    }
}

static const uint32_t piv_object_ids[] = {
    0x5FC107u, // 0: CAPABILITY (CCC)
    0x5FC102u, // 1: CHUID
    0x5FC105u, // 2: AUTHENTICATION (9A)
    0x5FC103u, // 3: FINGERPRINTS
    0x5FC106u, // 4: SECURITY
    0x5FC108u, // 5: FACIAL
    0x5FC109u, // 6: PRINTED / PIVMAN_PROTECTED_DATA
    0x5FC10Au, // 7: SIGNATURE (9C)
    0x5FC10Bu, // 8: KEY_MANAGEMENT (9D)
    0x5FC101u, // 9: CARD_AUTH (9E)
    0x00007Eu, // 10: DISCOVERY
    0x5FC10Cu, // 11: KEY_HISTORY
    0x5FC121u, // 12: IRIS
    0x5FC10Du, // 13..32: RETIRED 1..20 (82..95)
    0x5FC10Eu,
    0x5FC10Fu,
    0x5FC110u,
    0x5FC111u,
    0x5FC112u,
    0x5FC113u,
    0x5FC114u,
    0x5FC115u,
    0x5FC116u,
    0x5FC117u,
    0x5FC118u,
    0x5FC119u,
    0x5FC11Au,
    0x5FC11Bu,
    0x5FC11Cu,
    0x5FC11Du,
    0x5FC11Eu,
    0x5FC11Fu,
    0x5FC120u,
    0x5FFF00u, // 33: PIVMAN_DATA
    0x5FFF01u  // 34: ATTESTATION (F9)
};
#define PIV_OBJECT_COUNT (sizeof(piv_object_ids) / sizeof(piv_object_ids[0]))

static int piv_object_index(uint32_t obj_id) {
    for (size_t i = 0; i < PIV_OBJECT_COUNT; i++) {
        if (piv_object_ids[i] == obj_id) {
            return (int)i;
        }
    }
    return -1;
}

static void piv_state_init_defaults(piv_state_t *st) {
    memset(st, 0, sizeof(*st));
    st->magic = PIV_STATE_MAGIC;
    memcpy(st->pin, piv_default_pin, PIV_PIN_LEN);
    memcpy(st->puk, piv_default_puk, PIV_PIN_LEN);
    st->max_pin_retries = 3;
    st->pin_retries = 3;
    st->max_puk_retries = 3;
    st->puk_retries = 3;
    st->pin_is_default = 1;
    st->puk_is_default = 1;
    st->mgm_type = PIV_ALG_3DES;
    st->mgm_len = 24;
    st->mgm_touch_policy = PIV_TOUCH_POLICY_NEVER;
    st->mgm_is_default = 1;
    memcpy(st->mgm_key, piv_default_mgm, 24);
}

static int piv_load_state(piv_state_t *st) {
    piv_state_init_defaults(st);
    file_t *ef = file_search(EF_PIV_STATE);
    if (!file_has_data(ef)) {
        return PICOKEYS_OK;
    }
    uint32_t sz = file_get_size(ef);
    if (sz != sizeof(piv_state_t) + PIV_SECURE_OVERHEAD) {
        return PICOKEYS_OK;
    }
    uint8_t mkey[32];
    if (piv_derive_master_key(mkey) != PICOKEYS_OK) {
        return PICOKEYS_EXEC_ERROR;
    }
    piv_state_t tmp;
    int ret = decrypt_with_aad(mkey, CONST_BYTE_ARRAY(file_get_data(ef), sz), PIN_KDF_V2, (uint8_t *)&tmp);
    mbedtls_platform_zeroize(mkey, sizeof(mkey));
    if (ret == PICOKEYS_OK && tmp.magic == PIV_STATE_MAGIC) {
        memcpy(st, &tmp, sizeof(*st));
    }
    mbedtls_platform_zeroize(&tmp, sizeof(tmp));
    return PICOKEYS_OK;
}

static int piv_save_state(const piv_state_t *st) {
    uint8_t mkey[32];
    if (piv_derive_master_key(mkey) != PICOKEYS_OK) {
        return PICOKEYS_EXEC_ERROR;
    }
    uint8_t enc[sizeof(piv_state_t) + PIV_SECURE_OVERHEAD];
    int ret = encrypt_with_aad(mkey, CONST_BYTE_ARRAY((const uint8_t *)st, sizeof(*st)), PIN_KDF_V2, enc);
    mbedtls_platform_zeroize(mkey, sizeof(mkey));
    if (ret != PICOKEYS_OK) {
        mbedtls_platform_zeroize(enc, sizeof(enc));
        return ret;
    }
    file_t *ef = file_search(EF_PIV_STATE);
    if (!ef) {
        ef = file_new(EF_PIV_STATE);
    }
    if (!ef || file_put_data(ef, CONST_BYTE_ARRAY(enc, sizeof(enc))) != PICOKEYS_OK) {
        mbedtls_platform_zeroize(enc, sizeof(enc));
        return PICOKEYS_ERR_MEMORY_FATAL;
    }
    mbedtls_platform_zeroize(enc, sizeof(enc));
    flash_commit();
    return PICOKEYS_OK;
}

static uint8_t *piv_append_tlv(uint8_t *p, uint16_t tag, const uint8_t *val, size_t len) {
    if (tag > 0xFF) {
        *p++ = (uint8_t)(tag >> 8);
    }
    *p++ = (uint8_t)(tag & 0xFF);
    p += tlv_format_len((uint16_t)len, p);
    if (len > 0 && val != NULL) {
        memcpy(p, val, len);
        p += len;
    }
    return p;
}

static int piv_store_slot_key(uint8_t slot, uint8_t key_type, uint8_t pin_policy, uint8_t touch_policy, uint8_t origin, const uint8_t *pub_tlv, uint16_t pub_len, const uint8_t *priv_plain, uint16_t priv_len) {
    int idx = piv_slot_index(slot);
    if (idx < 0) {
        return PICOKEYS_WRONG_DATA;
    }
    if (pin_policy == PIV_PIN_POLICY_DEFAULT) {
        if (slot == PIV_SLOT_SIGNATURE) {
            pin_policy = PIV_PIN_POLICY_ALWAYS;
        }
        else if (slot == PIV_SLOT_CARD_AUTH) {
            pin_policy = PIV_PIN_POLICY_NEVER;
        }
        else {
            pin_policy = PIV_PIN_POLICY_ONCE;
        }
    }
    if (touch_policy == PIV_TOUCH_POLICY_DEFAULT) {
        touch_policy = PIV_TOUCH_POLICY_NEVER;
    }

    size_t plain_total = sizeof(piv_key_header_t) + pub_len + priv_len;
    size_t enc_total = plain_total + PIV_SECURE_OVERHEAD;
    if (enc_total > UINT16_MAX) {
        return PICOKEYS_WRONG_LENGTH;
    }
    uint8_t *plain = (uint8_t *)calloc(1, plain_total);
    uint8_t *enc = (uint8_t *)calloc(1, enc_total);
    if (!plain || !enc) {
        free(plain);
        free(enc);
        return PICOKEYS_ERR_NO_MEMORY;
    }

    piv_key_header_t hdr = {
        .magic = PIV_KEY_MAGIC,
        .key_type = key_type,
        .pin_policy = pin_policy,
        .touch_policy = touch_policy,
        .origin = origin,
        .pub_len = pub_len,
        .priv_len = priv_len
    };
    memcpy(plain, &hdr, sizeof(hdr));
    memcpy(plain + sizeof(hdr), pub_tlv, pub_len);
    memcpy(plain + sizeof(hdr) + pub_len, priv_plain, priv_len);

    uint8_t mkey[32];
    int ret = piv_derive_master_key(mkey);
    if (ret == PICOKEYS_OK) {
        ret = encrypt_with_aad(mkey, CONST_BYTE_ARRAY(plain, plain_total), PIN_KDF_V2, enc);
    }
    mbedtls_platform_zeroize(mkey, sizeof(mkey));
    mbedtls_platform_zeroize(plain, plain_total);
    free(plain);

    if (ret == PICOKEYS_OK) {
        uint16_t fid = (uint16_t)(EF_PIV_KEY_BASE + idx);
        file_t *ef = file_search(fid);
        if (!ef) {
            ef = file_new(fid);
        }
        if (!ef || file_put_data(ef, CONST_BYTE_ARRAY(enc, enc_total)) != PICOKEYS_OK) {
            ret = PICOKEYS_ERR_MEMORY_FATAL;
        }
        else {
            flash_commit();
        }
    }
    mbedtls_platform_zeroize(enc, enc_total);
    free(enc);
    return ret;
}

static int piv_load_slot_key(uint8_t slot, piv_key_header_t *hdr_out, uint8_t **pub_out, uint8_t **priv_out) {
    int idx = piv_slot_index(slot);
    if (idx < 0) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    uint16_t fid = (uint16_t)(EF_PIV_KEY_BASE + idx);
    file_t *ef = file_search(fid);
    if (!file_has_data(ef)) {
        if (slot == PIV_SLOT_ATTESTATION) {
            if (piv_ensure_attestation_ready() != PICOKEYS_OK) {
                return PICOKEYS_ERR_FILE_NOT_FOUND;
            }
            ef = file_search(fid);
            if (!file_has_data(ef)) {
                return PICOKEYS_ERR_FILE_NOT_FOUND;
            }
        }
        else {
            return PICOKEYS_ERR_FILE_NOT_FOUND;
        }
    }
    uint32_t enc_len = file_get_size(ef);
    if (enc_len <= sizeof(piv_key_header_t) + PIV_SECURE_OVERHEAD) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    size_t plain_len = enc_len - PIV_SECURE_OVERHEAD;
    uint8_t *plain = (uint8_t *)calloc(1, plain_len);
    if (!plain) {
        return PICOKEYS_ERR_NO_MEMORY;
    }
    uint8_t mkey[32];
    int ret = piv_derive_master_key(mkey);
    if (ret == PICOKEYS_OK) {
        ret = decrypt_with_aad(mkey, CONST_BYTE_ARRAY(file_get_data(ef), enc_len), PIN_KDF_V2, plain);
    }
    mbedtls_platform_zeroize(mkey, sizeof(mkey));
    if (ret != PICOKEYS_OK) {
        mbedtls_platform_zeroize(plain, plain_len);
        free(plain);
        return PICOKEYS_EXEC_ERROR;
    }

    piv_key_header_t hdr;
    memcpy(&hdr, plain, sizeof(hdr));
    if (hdr.magic != PIV_KEY_MAGIC || (size_t)sizeof(hdr) + hdr.pub_len + hdr.priv_len != plain_len) {
        mbedtls_platform_zeroize(plain, plain_len);
        free(plain);
        return PICOKEYS_WRONG_DATA;
    }
    if (hdr_out) {
        *hdr_out = hdr;
    }
    if (pub_out) {
        *pub_out = (uint8_t *)calloc(1, hdr.pub_len ? hdr.pub_len : 1);
        if (!*pub_out) {
            mbedtls_platform_zeroize(plain, plain_len);
            free(plain);
            return PICOKEYS_ERR_NO_MEMORY;
        }
        memcpy(*pub_out, plain + sizeof(hdr), hdr.pub_len);
    }
    if (priv_out) {
        *priv_out = (uint8_t *)calloc(1, hdr.priv_len ? hdr.priv_len : 1);
        if (!*priv_out) {
            if (pub_out && *pub_out) {
                free(*pub_out);
                *pub_out = NULL;
            }
            mbedtls_platform_zeroize(plain, plain_len);
            free(plain);
            return PICOKEYS_ERR_NO_MEMORY;
        }
        memcpy(*priv_out, plain + sizeof(hdr) + hdr.pub_len, hdr.priv_len);
    }
    mbedtls_platform_zeroize(plain, plain_len);
    free(plain);
    return PICOKEYS_OK;
}

static size_t piv_rsa_bits(uint8_t key_type) {
    switch (key_type) {
        case PIV_ALG_RSA1024: return 1024;
        case PIV_ALG_RSA2048: return 2048;
        case PIV_ALG_RSA3072: return 3072;
        case PIV_ALG_RSA4096: return 4096;
        default: return 0;
    }
}

static mbedtls_ecp_group_id piv_ecp_group(uint8_t key_type) {
    switch (key_type) {
        case PIV_ALG_ECCP256: return MBEDTLS_ECP_DP_SECP256R1;
        case PIV_ALG_ECCP384: return MBEDTLS_ECP_DP_SECP384R1;
#ifdef MBEDTLS_EDDSA_C
        case PIV_ALG_ED25519: return MBEDTLS_ECP_DP_ED25519;
#endif
        case PIV_ALG_X25519: return MBEDTLS_ECP_DP_CURVE25519;
        default: return MBEDTLS_ECP_DP_NONE;
    }
}

static int piv_select(app_t *a, uint8_t force) {
    (void)force;
    if (!cap_supported(CAP_PIV)) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    a->process_apdu = piv_process_apdu;
    a->unload = piv_unload;
    piv_pin_verified = false;
    piv_pin_verified_once_used = false;
    piv_mgm_authenticated = false;
    piv_mgm_challenge_valid = false;
    piv_last_touch_ms = 0;

    static const uint8_t select_resp[] = {
        0x61, 0x2B,
        0x4F, 0x06, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
        0x79, 0x07, 0x4F, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08,
        0x50, 0x0B, 'Y', 'u', 'b', 'i', 'K', 'e', 'y', ' ', 'P', 'I', 'V',
        0xAC, 0x0B, 0x80, 0x01, 0x07, 0x80, 0x01, 0x11, 0x80, 0x01, 0x14, 0x06, 0x01, 0x00
    };
    memcpy(res_APDU, select_resp, sizeof(select_resp));
    res_APDU_size = sizeof(select_resp);
    apdu.ne = res_APDU_size;
    return PICOKEYS_OK;
}

static int piv_unload(void) {
    piv_pin_verified = false;
    piv_pin_verified_once_used = false;
    piv_mgm_authenticated = false;
    piv_mgm_challenge_valid = false;
    piv_last_touch_ms = 0;
    return PICOKEYS_OK;
}

INITIALIZER(piv_ctor) {
    register_app(piv_select, piv_aid);
}

static int piv_pin_actual_len(const uint8_t pin[PIV_PIN_LEN]) {
    int len = 0;
    while (len < PIV_PIN_LEN && pin[len] != 0xFF) {
        len++;
    }
    for (int i = len; i < PIV_PIN_LEN; i++) {
        if (pin[i] != 0xFF) {
            return -1;
        }
    }
    return len;
}

static int cmd_piv_get_version(void) {
    res_APDU[0] = PIV_VERSION_MAJOR;
    res_APDU[1] = PIV_VERSION_MINOR;
    res_APDU[2] = PIV_VERSION_PATCH;
    res_APDU_size = 3;
    return SW_OK();
}

static int cmd_piv_get_serial(void) {
    memcpy(res_APDU, pico_serial.id, 4);
    res_APDU[0] &= (uint8_t)~0xFCu;
    res_APDU_size = 4;
    return SW_OK();
}

static int cmd_piv_verify(void) {
    uint8_t p1 = P1(apdu), p2 = P2(apdu);
    if (p2 == PIV_SLOT_OCC_AUTH) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (p2 != PIV_PIN_P2) {
        return SW_INCORRECT_P1P2();
    }
    piv_state_t st;
    piv_load_state(&st);

    if (p1 == 0xFF) {
        if (apdu.nc != 0) {
            mbedtls_platform_zeroize(&st, sizeof(st));
            return SW_WRONG_LENGTH();
        }
        piv_pin_verified = false;
        piv_pin_verified_once_used = false;
        mbedtls_platform_zeroize(&st, sizeof(st));
        return SW_OK();
    }
    if (p1 != 0x00) {
        mbedtls_platform_zeroize(&st, sizeof(st));
        return SW_INCORRECT_P1P2();
    }
    if (apdu.nc == 0) {
        uint8_t rem = st.pin_retries;
        mbedtls_platform_zeroize(&st, sizeof(st));
        if (rem == 0) {
            return SW_PIN_BLOCKED();
        }
        return set_res_sw(0x63, (uint8_t)(0xC0u | MIN(rem, 15u)));
    }
    if (apdu.nc != PIV_PIN_LEN) {
        mbedtls_platform_zeroize(&st, sizeof(st));
        return SW_WRONG_LENGTH();
    }
    if (st.pin_retries == 0) {
        mbedtls_platform_zeroize(&st, sizeof(st));
        return SW_PIN_BLOCKED();
    }
    if (mbedtls_ct_memcmp(st.pin, apdu.data, PIV_PIN_LEN) == 0) {
        if (st.pin_retries != st.max_pin_retries) {
            st.pin_retries = st.max_pin_retries;
            piv_save_state(&st);
        }
        piv_pin_verified = true;
        piv_pin_verified_once_used = false;
        mbedtls_platform_zeroize(&st, sizeof(st));
        return SW_OK();
    }
    st.pin_retries--;
    uint8_t rem = st.pin_retries;
    piv_pin_verified = false;
    piv_pin_verified_once_used = false;
    piv_save_state(&st);
    mbedtls_platform_zeroize(&st, sizeof(st));
    return set_res_sw(0x63, (uint8_t)(0xC0u | MIN(rem, 15u)));
}

static int cmd_piv_change_reference(void) {
    uint8_t p1 = P1(apdu), p2 = P2(apdu);
    if (p1 != 0x00 || (p2 != PIV_PIN_P2 && p2 != PIV_PUK_P2)) {
        return SW_INCORRECT_P1P2();
    }
    if (apdu.nc != 2 * PIV_PIN_LEN) {
        return SW_WRONG_LENGTH();
    }
    const uint8_t *old_val = apdu.data;
    const uint8_t *new_val = apdu.data + PIV_PIN_LEN;

    piv_state_t st;
    piv_load_state(&st);

    if (p2 == PIV_PIN_P2) {
        if (st.pin_retries == 0) {
            mbedtls_platform_zeroize(&st, sizeof(st));
            return SW_PIN_BLOCKED();
        }
        if (mbedtls_ct_memcmp(st.pin, old_val, PIV_PIN_LEN) != 0) {
            st.pin_retries--;
            uint8_t rem = st.pin_retries;
            piv_pin_verified = false;
            piv_save_state(&st);
            mbedtls_platform_zeroize(&st, sizeof(st));
            return set_res_sw(0x63, (uint8_t)(0xC0u | MIN(rem, 15u)));
        }
        int new_len = piv_pin_actual_len(new_val);
        if (new_len < 6 || new_len > 8) {
            mbedtls_platform_zeroize(&st, sizeof(st));
            return SW_WRONG_DATA();
        }
        memcpy(st.pin, new_val, PIV_PIN_LEN);
        st.pin_retries = st.max_pin_retries;
        st.pin_is_default = (mbedtls_ct_memcmp(new_val, piv_default_pin, PIV_PIN_LEN) == 0) ? 1 : 0;
    }
    else {
        if (st.puk_retries == 0) {
            mbedtls_platform_zeroize(&st, sizeof(st));
            return SW_PIN_BLOCKED();
        }
        if (mbedtls_ct_memcmp(st.puk, old_val, PIV_PIN_LEN) != 0) {
            st.puk_retries--;
            uint8_t rem = st.puk_retries;
            piv_save_state(&st);
            mbedtls_platform_zeroize(&st, sizeof(st));
            return set_res_sw(0x63, (uint8_t)(0xC0u | MIN(rem, 15u)));
        }
        int new_len = piv_pin_actual_len(new_val);
        if (new_len < 6 || new_len > 8) {
            mbedtls_platform_zeroize(&st, sizeof(st));
            return SW_WRONG_DATA();
        }
        memcpy(st.puk, new_val, PIV_PIN_LEN);
        st.puk_retries = st.max_puk_retries;
        st.puk_is_default = (mbedtls_ct_memcmp(new_val, piv_default_puk, PIV_PIN_LEN) == 0) ? 1 : 0;
    }
    piv_save_state(&st);
    mbedtls_platform_zeroize(&st, sizeof(st));
    return SW_OK();
}

static int cmd_piv_reset_retry(void) {
    if (P1(apdu) != 0x00 || P2(apdu) != PIV_PIN_P2) {
        return SW_INCORRECT_P1P2();
    }
    if (apdu.nc != 2 * PIV_PIN_LEN) {
        return SW_WRONG_LENGTH();
    }
    const uint8_t *puk_val = apdu.data;
    const uint8_t *new_pin = apdu.data + PIV_PIN_LEN;

    piv_state_t st;
    piv_load_state(&st);
    if (st.puk_retries == 0) {
        mbedtls_platform_zeroize(&st, sizeof(st));
        return SW_PIN_BLOCKED();
    }
    if (mbedtls_ct_memcmp(st.puk, puk_val, PIV_PIN_LEN) != 0) {
        st.puk_retries--;
        uint8_t rem = st.puk_retries;
        piv_save_state(&st);
        mbedtls_platform_zeroize(&st, sizeof(st));
        return set_res_sw(0x63, (uint8_t)(0xC0u | MIN(rem, 15u)));
    }
    int new_len = piv_pin_actual_len(new_pin);
    if (new_len < 6 || new_len > 8) {
        mbedtls_platform_zeroize(&st, sizeof(st));
        return SW_WRONG_DATA();
    }
    memcpy(st.pin, new_pin, PIV_PIN_LEN);
    st.pin_retries = st.max_pin_retries;
    st.puk_retries = st.max_puk_retries;
    st.pin_is_default = (mbedtls_ct_memcmp(new_pin, piv_default_pin, PIV_PIN_LEN) == 0) ? 1 : 0;
    piv_save_state(&st);
    mbedtls_platform_zeroize(&st, sizeof(st));
    return SW_OK();
}

static int cmd_piv_set_pin_retries(void) {
    if (!piv_mgm_authenticated || !piv_pin_verified) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    uint8_t pin_att = P1(apdu), puk_att = P2(apdu);
    if (pin_att == 0 || puk_att == 0) {
        return SW_INCORRECT_P1P2();
    }
    piv_state_t st;
    piv_load_state(&st);
    memcpy(st.pin, piv_default_pin, PIV_PIN_LEN);
    memcpy(st.puk, piv_default_puk, PIV_PIN_LEN);
    st.max_pin_retries = pin_att;
    st.pin_retries = pin_att;
    st.max_puk_retries = puk_att;
    st.puk_retries = puk_att;
    st.pin_is_default = 1;
    st.puk_is_default = 1;
    piv_save_state(&st);
    mbedtls_platform_zeroize(&st, sizeof(st));
    return SW_OK();
}

static int cmd_piv_reset(void) {
    if (P1(apdu) != 0x00 || P2(apdu) != 0x00) {
        return SW_INCORRECT_P1P2();
    }
    piv_state_t st;
    piv_load_state(&st);
    if (st.pin_retries > 0 || st.puk_retries > 0) {
        mbedtls_platform_zeroize(&st, sizeof(st));
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    for (uint16_t i = 0; i < PIV_SLOT_COUNT; i++) {
        file_t *ef = file_search((uint16_t)(EF_PIV_KEY_BASE + i));
        if (file_has_data(ef)) {
            file_delete_no_commit(ef);
        }
    }
    for (uint16_t i = 0; i < PIV_OBJECT_COUNT; i++) {
        file_t *ef = file_search((uint16_t)(EF_PIV_OBJ_BASE + i));
        if (file_has_data(ef)) {
            file_delete_no_commit(ef);
        }
    }
    piv_state_init_defaults(&st);
    piv_save_state(&st);
    mbedtls_platform_zeroize(&st, sizeof(st));
    piv_pin_verified = false;
    piv_pin_verified_once_used = false;
    piv_mgm_authenticated = false;
    piv_mgm_challenge_valid = false;
    return SW_OK();
}

static int piv_mgm_ecb_crypt(const piv_state_t *st, bool encrypt, const uint8_t *in, uint8_t *out) {
    if (st->mgm_type == PIV_ALG_3DES) {
        mbedtls_des3_context ctx;
        mbedtls_des3_init(&ctx);
        int ret = encrypt ? mbedtls_des3_set3key_enc(&ctx, st->mgm_key)
                          : mbedtls_des3_set3key_dec(&ctx, st->mgm_key);
        if (ret == 0) {
            ret = mbedtls_des3_crypt_ecb(&ctx, in, out);
        }
        mbedtls_des3_free(&ctx);
        return ret;
    }
    else if (st->mgm_type == PIV_ALG_AES128 || st->mgm_type == PIV_ALG_AES192 || st->mgm_type == PIV_ALG_AES256) {
        mbedtls_aes_context ctx;
        mbedtls_aes_init(&ctx);
        unsigned int keybits = (unsigned int)st->mgm_len * 8u;
        int ret = encrypt ? mbedtls_aes_setkey_enc(&ctx, st->mgm_key, keybits)
                          : mbedtls_aes_setkey_dec(&ctx, st->mgm_key, keybits);
        if (ret == 0) {
            ret = mbedtls_aes_crypt_ecb(&ctx, encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT, in, out);
        }
        mbedtls_aes_free(&ctx);
        return ret;
    }
    return -1;
}

static int cmd_piv_set_mgmkey(void) {
    if (!piv_mgm_authenticated) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (P1(apdu) != 0xFF || (P2(apdu) != 0xFF && P2(apdu) != 0xFE)) {
        return SW_INCORRECT_P1P2();
    }
    if (apdu.nc < 3) {
        return SW_WRONG_LENGTH();
    }
    uint8_t alg = apdu.data[0];
    uint8_t slot = apdu.data[1];
    uint8_t key_len = apdu.data[2];
    if (slot != PIV_SLOT_CARD_MGM || apdu.nc != (uint32_t)(3 + key_len)) {
        return SW_WRONG_DATA();
    }
    uint8_t expected_len = 0;
    if (alg == PIV_ALG_3DES || alg == PIV_ALG_AES192) {
        expected_len = 24;
    }
    else if (alg == PIV_ALG_AES128) {
        expected_len = 16;
    }
    else if (alg == PIV_ALG_AES256) {
        expected_len = 32;
    }
    else {
        return SW_WRONG_DATA();
    }
    if (key_len != expected_len) {
        return SW_WRONG_DATA();
    }
    piv_state_t st;
    piv_load_state(&st);
    st.mgm_type = alg;
    st.mgm_len = key_len;
    st.mgm_touch_policy = (P2(apdu) == 0xFE) ? PIV_TOUCH_POLICY_ALWAYS : PIV_TOUCH_POLICY_NEVER;
    st.mgm_is_default = (alg == PIV_ALG_3DES && mbedtls_ct_memcmp(apdu.data + 3, piv_default_mgm, 24) == 0) ? 1 : 0;
    memset(st.mgm_key, 0, sizeof(st.mgm_key));
    memcpy(st.mgm_key, apdu.data + 3, key_len);
    piv_save_state(&st);
    mbedtls_platform_zeroize(&st, sizeof(st));
    return SW_OK();
}

static int cmd_piv_get_metadata(void) {
    if (P1(apdu) != 0x00) {
        return SW_INCORRECT_P1P2();
    }
    uint8_t p2 = P2(apdu);
    if (p2 == PIV_SLOT_OCC_AUTH) {
        return SW_REFERENCE_NOT_FOUND();
    }
    piv_state_t st;
    piv_load_state(&st);
    uint8_t *p = res_APDU;

    if (p2 == PIV_PIN_P2 || p2 == PIV_PUK_P2) {
        uint8_t algo = 0xFF;
        uint8_t is_def = (p2 == PIV_PIN_P2) ? st.pin_is_default : st.puk_is_default;
        uint8_t retries[2] = {
            (p2 == PIV_PIN_P2) ? st.max_pin_retries : st.max_puk_retries,
            (p2 == PIV_PIN_P2) ? st.pin_retries : st.puk_retries
        };
        p = piv_append_tlv(p, TAG_METADATA_ALGO, &algo, 1);
        p = piv_append_tlv(p, TAG_METADATA_IS_DEFAULT, &is_def, 1);
        p = piv_append_tlv(p, TAG_METADATA_RETRIES, retries, 2);
        res_APDU_size = (uint16_t)(p - res_APDU);
        mbedtls_platform_zeroize(&st, sizeof(st));
        return SW_OK();
    }
    if (p2 == PIV_SLOT_CARD_MGM) {
        uint8_t policy[2] = { 0x00, st.mgm_touch_policy };
        p = piv_append_tlv(p, TAG_METADATA_ALGO, &st.mgm_type, 1);
        p = piv_append_tlv(p, TAG_METADATA_POLICY, policy, 2);
        p = piv_append_tlv(p, TAG_METADATA_IS_DEFAULT, &st.mgm_is_default, 1);
        res_APDU_size = (uint16_t)(p - res_APDU);
        mbedtls_platform_zeroize(&st, sizeof(st));
        return SW_OK();
    }
    mbedtls_platform_zeroize(&st, sizeof(st));

    piv_key_header_t hdr;
    uint8_t *pub_tlv = NULL;
    if (piv_load_slot_key(p2, &hdr, &pub_tlv, NULL) != PICOKEYS_OK) {
        return SW_REFERENCE_NOT_FOUND();
    }
    uint8_t policy[2] = { hdr.pin_policy, hdr.touch_policy };
    p = piv_append_tlv(p, TAG_METADATA_ALGO, &hdr.key_type, 1);
    p = piv_append_tlv(p, TAG_METADATA_POLICY, policy, 2);
    p = piv_append_tlv(p, TAG_METADATA_ORIGIN, &hdr.origin, 1);
    p = piv_append_tlv(p, TAG_METADATA_PUBLIC_KEY, pub_tlv, hdr.pub_len);
    free(pub_tlv);
    res_APDU_size = (uint16_t)(p - res_APDU);
    return SW_OK();
}

static int cmd_piv_get_data(void) {
    if (P1(apdu) != 0x3F || P2(apdu) != 0xFF) {
        return SW_INCORRECT_P1P2();
    }
    tlv_ctx_t ctx, tag_id = { 0 };
    tlv_ctx_init(BYTE_ARRAY(apdu.data, apdu.nc), &ctx);
    if (!tlv_find_tag(&ctx, TAG_OBJ_ID, &tag_id) || tag_id.len == 0 || tag_id.len > 3) {
        return SW_WRONG_DATA();
    }
    uint32_t obj_id = 0;
    for (uint16_t i = 0; i < tag_id.len; i++) {
        obj_id = (obj_id << 8) | tag_id.data[i];
    }

    if (obj_id == 0x5FC109u && !piv_pin_verified) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }

    int idx = piv_object_index(obj_id);
    if (idx < 0) {
        return SW_FILE_NOT_FOUND();
    }
    uint16_t fid = (uint16_t)(EF_PIV_OBJ_BASE + idx);
    file_t *ef = file_search(fid);
    if (!file_has_data(ef)) {
        if (obj_id == 0x5FFF01u) {
            if (piv_ensure_attestation_ready() == PICOKEYS_OK) {
                ef = file_search(fid);
            }
        }
        else if (obj_id == 0x00007Eu) {
            static const uint8_t default_discovery[] = {
                0x4F, 0x0B, 0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
                0x5F, 0x2F, 0x02, 0x40, 0x00
            };
            uint8_t *p = piv_append_tlv(res_APDU, 0x7E, default_discovery, sizeof(default_discovery));
            res_APDU_size = (uint16_t)(p - res_APDU);
            return SW_OK();
        }
        if (!file_has_data(ef)) {
            return SW_FILE_NOT_FOUND();
        }
    }
    uint32_t obj_len = file_get_size(ef);
    uint16_t outer_tag = (obj_id == 0x00007Eu) ? 0x7Eu : TAG_OBJ_DATA;
    uint8_t *p = piv_append_tlv(res_APDU, outer_tag, file_get_data(ef), obj_len);
    res_APDU_size = (uint16_t)(p - res_APDU);
    return SW_OK();
}

static int cmd_piv_put_data(void) {
    if (!piv_mgm_authenticated) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (P1(apdu) != 0x3F || P2(apdu) != 0xFF) {
        return SW_INCORRECT_P1P2();
    }
    tlv_ctx_t ctx, tag_id = { 0 }, tag_data = { 0 };
    tlv_ctx_init(BYTE_ARRAY(apdu.data, apdu.nc), &ctx);
    if (!tlv_find_tag(&ctx, TAG_OBJ_ID, &tag_id) || tag_id.len == 0 || tag_id.len > 3) {
        return SW_WRONG_DATA();
    }
    if (!tlv_find_tag(&ctx, TAG_OBJ_DATA, &tag_data)) {
        return SW_WRONG_DATA();
    }
    uint32_t obj_id = 0;
    for (uint16_t i = 0; i < tag_id.len; i++) {
        obj_id = (obj_id << 8) | tag_id.data[i];
    }
    int idx = piv_object_index(obj_id);
    if (idx < 0) {
        return SW_FILE_NOT_FOUND();
    }
    uint16_t fid = (uint16_t)(EF_PIV_OBJ_BASE + idx);
    file_t *ef = file_search(fid);
    if (tag_data.len == 0) {
        if (file_has_data(ef)) {
            file_delete(ef);
        }
        return SW_OK();
    }
    if (!ef) {
        ef = file_new(fid);
    }
    if (!ef || file_put_data(ef, CONST_BYTE_ARRAY(tag_data.data, tag_data.len)) != PICOKEYS_OK) {
        return SW_MEMORY_FAILURE();
    }
    flash_commit();
    return SW_OK();
}

static int cmd_piv_generate_asymmetric(void) {
    if (!piv_mgm_authenticated) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    if (P1(apdu) != 0x00) {
        return SW_INCORRECT_P1P2();
    }
    uint8_t slot = P2(apdu);
    if (piv_slot_index(slot) < 0) {
        return SW_INCORRECT_P1P2();
    }

    tlv_ctx_t outer, inner;
    tlv_ctx_init(BYTE_ARRAY(apdu.data, apdu.nc), &outer);
    if (!tlv_find_tag(&outer, 0xAC, &inner)) {
        return SW_WRONG_DATA();
    }
    uint8_t key_type = 0;
    uint8_t pin_policy = PIV_PIN_POLICY_DEFAULT;
    uint8_t touch_policy = PIV_TOUCH_POLICY_DEFAULT;

    uint8_t *p = NULL;
    tlv_item_t item;
    while (tlv_walk(&inner, &p, &item)) {
        if (item.tag == TAG_GEN_ALGORITHM && item.value.len == 1) {
            key_type = item.value.data[0];
        }
        else if (item.tag == TAG_PIN_POLICY && item.value.len == 1) {
            pin_policy = item.value.data[0];
        }
        else if (item.tag == TAG_TOUCH_POLICY && item.value.len == 1) {
            touch_policy = item.value.data[0];
        }
    }

    size_t rsa_bits = piv_rsa_bits(key_type);
    mbedtls_ecp_group_id grp_id = piv_ecp_group(key_type);
    if (rsa_bits == 0 && grp_id == MBEDTLS_ECP_DP_NONE) {
        return SW_WRONG_DATA();
    }

    uint8_t *pub_tlv = (uint8_t *)calloc(1, 600);
    uint8_t *priv_buf = (uint8_t *)calloc(1, 600);
    if (!pub_tlv || !priv_buf) {
        free(pub_tlv);
        free(priv_buf);
        return SW_MEMORY_FAILURE();
    }
    uint16_t pub_len = 0;
    uint16_t priv_len = 0;

    if (rsa_bits > 0) {
        mbedtls_rsa_context rsa;
        mbedtls_rsa_init(&rsa);
        int ret = mbedtls_rsa_gen_key(&rsa, random_fill_iterator, NULL, (unsigned int)rsa_bits, 65537);
        if (ret != 0) {
            mbedtls_rsa_free(&rsa);
            free(pub_tlv);
            free(priv_buf);
            return SW_EXEC_ERROR();
        }
        size_t n_len = rsa_bits / 8u;
        size_t p_len = rsa_bits / 16u;
        uint8_t *n_buf = (uint8_t *)calloc(1, n_len);
        if (!n_buf) {
            mbedtls_rsa_free(&rsa);
            free(pub_tlv);
            free(priv_buf);
            return SW_MEMORY_FAILURE();
        }
        uint8_t e_buf[3] = { 0x01, 0x00, 0x01 };
        ret = mbedtls_rsa_export_raw(&rsa, n_buf, n_len, priv_buf, p_len, priv_buf + p_len, p_len, NULL, 0, NULL, 0);
        mbedtls_rsa_free(&rsa);
        if (ret != 0) {
            free(n_buf);
            mbedtls_platform_zeroize(priv_buf, 600);
            free(pub_tlv);
            free(priv_buf);
            return SW_EXEC_ERROR();
        }
        uint8_t *wp = pub_tlv;
        wp = piv_append_tlv(wp, 0x81, n_buf, n_len);
        wp = piv_append_tlv(wp, 0x82, e_buf, sizeof(e_buf));
        pub_len = (uint16_t)(wp - pub_tlv);
        priv_len = (uint16_t)(2u * p_len);
        free(n_buf);
    }
    else {
        mbedtls_ecp_keypair kp;
        mbedtls_ecp_keypair_init(&kp);
        size_t sk_len = (key_type == PIV_ALG_ECCP384) ? 48u : 32u;
        size_t pk_len = 0;
        uint8_t pk_raw[100];
        int ret = 0;
        if (grp_id == MBEDTLS_ECP_DP_SECP256R1 || grp_id == MBEDTLS_ECP_DP_SECP384R1) {
            ret = mbedtls_ecp_gen_key(grp_id, &kp, random_fill_iterator, NULL);
            if (ret == 0) {
                ret = mbedtls_ecp_write_key_ext(&kp, &sk_len, priv_buf, 600);
            }
        }
        else {
            random_fill_buffer(BYTE_ARRAY(priv_buf, sk_len));
            if (priv_buf[sk_len - 1] == 0) {
                priv_buf[sk_len - 1] = 0x01;
            }
            ret = mbedtls_ecp_group_load(&kp.grp, grp_id);
            if (ret == 0) {
                ret = mbedtls_ecp_read_key(grp_id, &kp, priv_buf, sk_len);
            }
            if (ret == 0) {
                ret = mbedtls_ecp_keypair_calc_public(&kp, random_fill_iterator, NULL);
            }
        }
        if (ret == 0) {
            int pf = (grp_id == MBEDTLS_ECP_DP_CURVE25519
#ifdef MBEDTLS_EDDSA_C
                      || grp_id == MBEDTLS_ECP_DP_ED25519
#endif
                     ) ? MBEDTLS_ECP_PF_COMPRESSED : MBEDTLS_ECP_PF_UNCOMPRESSED;
            ret = mbedtls_ecp_point_write_binary(&kp.grp, &kp.Q, pf, &pk_len, pk_raw, sizeof(pk_raw));
        }
        mbedtls_ecp_keypair_free(&kp);
        if (ret != 0) {
            mbedtls_platform_zeroize(priv_buf, 600);
            free(pub_tlv);
            free(priv_buf);
            return SW_EXEC_ERROR();
        }
        uint8_t *wp = piv_append_tlv(pub_tlv, 0x86, pk_raw, pk_len);
        pub_len = (uint16_t)(wp - pub_tlv);
        priv_len = (uint16_t)sk_len;
    }

    int store_ret = piv_store_slot_key(slot, key_type, pin_policy, touch_policy, PIV_ORIGIN_GENERATED, pub_tlv, pub_len, priv_buf, priv_len);
    mbedtls_platform_zeroize(priv_buf, 600);
    free(priv_buf);
    if (store_ret != PICOKEYS_OK) {
        free(pub_tlv);
        return SW_MEMORY_FAILURE();
    }

    uint8_t *rp = piv_append_tlv(res_APDU, 0x7F49, pub_tlv, pub_len);
    res_APDU_size = (uint16_t)(rp - res_APDU);
    free(pub_tlv);
    return SW_OK();
}

static int cmd_piv_import_key(void) {
    if (!piv_mgm_authenticated) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    uint8_t key_type = P1(apdu);
    uint8_t slot = P2(apdu);
    if (piv_slot_index(slot) < 0) {
        return SW_INCORRECT_P1P2();
    }

    size_t rsa_bits = piv_rsa_bits(key_type);
    mbedtls_ecp_group_id grp_id = piv_ecp_group(key_type);
    if (rsa_bits == 0 && grp_id == MBEDTLS_ECP_DP_NONE) {
        return SW_INCORRECT_P1P2();
    }

    uint8_t pin_policy = PIV_PIN_POLICY_DEFAULT;
    uint8_t touch_policy = PIV_TOUCH_POLICY_DEFAULT;
    tlv_ctx_t ctx, t_p = { 0 }, t_q = { 0 }, t_ec = { 0 };
    tlv_ctx_init(BYTE_ARRAY(apdu.data, apdu.nc), &ctx);

    uint8_t *p = NULL;
    tlv_item_t item;
    while (tlv_walk(&ctx, &p, &item)) {
        if (item.tag == TAG_PIN_POLICY && item.value.len == 1) {
            pin_policy = item.value.data[0];
        }
        else if (item.tag == TAG_TOUCH_POLICY && item.value.len == 1) {
            touch_policy = item.value.data[0];
        }
        else if (item.tag == 0x01) {
            t_p.data = (uint8_t *)item.value.data;
            t_p.len = (uint16_t)item.value.len;
        }
        else if (item.tag == 0x02) {
            t_q.data = (uint8_t *)item.value.data;
            t_q.len = (uint16_t)item.value.len;
        }
        else if (item.tag == 0x06 || item.tag == 0x07 || item.tag == 0x08) {
            t_ec.data = (uint8_t *)item.value.data;
            t_ec.len = (uint16_t)item.value.len;
        }
    }

    uint8_t *pub_tlv = (uint8_t *)calloc(1, 600);
    uint8_t *priv_buf = (uint8_t *)calloc(1, 600);
    if (!pub_tlv || !priv_buf) {
        free(pub_tlv);
        free(priv_buf);
        return SW_MEMORY_FAILURE();
    }
    uint16_t pub_len = 0;
    uint16_t priv_len = 0;

    if (rsa_bits > 0) {
        size_t p_len = rsa_bits / 16u;
        size_t n_len = rsa_bits / 8u;
        if (!t_p.data || !t_q.data || t_p.len > p_len || t_q.len > p_len) {
            free(pub_tlv);
            free(priv_buf);
            return SW_WRONG_DATA();
        }
        memcpy(priv_buf + (p_len - t_p.len), t_p.data, t_p.len);
        memcpy(priv_buf + p_len + (p_len - t_q.len), t_q.data, t_q.len);
        priv_len = (uint16_t)(2u * p_len);

        uint8_t e_buf[3] = { 0x01, 0x00, 0x01 };
        mbedtls_rsa_context rsa;
        mbedtls_rsa_init(&rsa);
        int ret = mbedtls_rsa_import_raw(&rsa, NULL, 0, priv_buf, p_len, priv_buf + p_len, p_len, NULL, 0, e_buf, sizeof(e_buf));
        if (ret == 0) {
            ret = mbedtls_rsa_complete(&rsa);
        }
        uint8_t *n_buf = (uint8_t *)calloc(1, n_len);
        if (ret == 0 && n_buf != NULL) {
            ret = mbedtls_rsa_export_raw(&rsa, n_buf, n_len, NULL, 0, NULL, 0, NULL, 0, NULL, 0);
        }
        else {
            ret = -1;
        }
        mbedtls_rsa_free(&rsa);
        if (ret != 0) {
            free(n_buf);
            mbedtls_platform_zeroize(priv_buf, 600);
            free(pub_tlv);
            free(priv_buf);
            return SW_WRONG_DATA();
        }
        uint8_t *wp = pub_tlv;
        wp = piv_append_tlv(wp, 0x81, n_buf, n_len);
        wp = piv_append_tlv(wp, 0x82, e_buf, sizeof(e_buf));
        pub_len = (uint16_t)(wp - pub_tlv);
        free(n_buf);
    }
    else {
        size_t expected_len = (key_type == PIV_ALG_ECCP384) ? 48u : 32u;
        if (!t_ec.data || t_ec.len == 0 || t_ec.len > expected_len) {
            free(pub_tlv);
            free(priv_buf);
            return SW_WRONG_DATA();
        }
        memcpy(priv_buf + (expected_len - t_ec.len), t_ec.data, t_ec.len);
        priv_len = (uint16_t)expected_len;

        mbedtls_ecp_keypair kp;
        mbedtls_ecp_keypair_init(&kp);
        int ret = mbedtls_ecp_read_key(grp_id, &kp, priv_buf, priv_len);
        if (ret == 0) {
            ret = mbedtls_ecp_keypair_calc_public(&kp, random_fill_iterator, NULL);
        }
        uint8_t pk_raw[100];
        size_t pk_len = 0;
        if (ret == 0) {
            int pf = (grp_id == MBEDTLS_ECP_DP_CURVE25519
#ifdef MBEDTLS_EDDSA_C
                      || grp_id == MBEDTLS_ECP_DP_ED25519
#endif
                     ) ? MBEDTLS_ECP_PF_COMPRESSED : MBEDTLS_ECP_PF_UNCOMPRESSED;
            ret = mbedtls_ecp_point_write_binary(&kp.grp, &kp.Q, pf, &pk_len, pk_raw, sizeof(pk_raw));
        }
        mbedtls_ecp_keypair_free(&kp);
        if (ret != 0) {
            mbedtls_platform_zeroize(priv_buf, 600);
            free(pub_tlv);
            free(priv_buf);
            return SW_WRONG_DATA();
        }
        uint8_t *wp = piv_append_tlv(pub_tlv, 0x86, pk_raw, pk_len);
        pub_len = (uint16_t)(wp - pub_tlv);
    }

    int store_ret = piv_store_slot_key(slot, key_type, pin_policy, touch_policy, PIV_ORIGIN_IMPORTED, pub_tlv, pub_len, priv_buf, priv_len);
    mbedtls_platform_zeroize(priv_buf, 600);
    free(priv_buf);
    free(pub_tlv);
    return store_ret == PICOKEYS_OK ? SW_OK() : SW_MEMORY_FAILURE();
}

static int cmd_piv_move_key(void) {
    if (!piv_mgm_authenticated) {
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }
    uint8_t to_slot = P1(apdu);
    uint8_t from_slot = P2(apdu);
    int from_idx = piv_slot_index(from_slot);
    if (from_idx < 0) {
        return SW_INCORRECT_P1P2();
    }
    uint16_t from_fid = (uint16_t)(EF_PIV_KEY_BASE + from_idx);
    file_t *from_ef = file_search(from_fid);
    if (!file_has_data(from_ef)) {
        return SW_REFERENCE_NOT_FOUND();
    }
    if (to_slot == 0xFF) {
        return file_delete(from_ef) == PICOKEYS_OK ? SW_OK() : SW_MEMORY_FAILURE();
    }
    int to_idx = piv_slot_index(to_slot);
    if (to_idx < 0) {
        return SW_INCORRECT_P1P2();
    }
    uint16_t to_fid = (uint16_t)(EF_PIV_KEY_BASE + to_idx);
    file_t *to_ef = file_search(to_fid);
    if (file_has_data(to_ef)) {
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    if (!to_ef) {
        to_ef = file_new(to_fid);
    }
    uint32_t sz = file_get_size(from_ef);
    uint8_t *copy = (uint8_t *)calloc(1, sz);
    if (!copy) {
        return SW_MEMORY_FAILURE();
    }
    memcpy(copy, file_get_data(from_ef), sz);
    int ret = file_put_data(to_ef, CONST_BYTE_ARRAY(copy, sz));
    mbedtls_platform_zeroize(copy, sz);
    free(copy);
    if (ret != PICOKEYS_OK) {
        return SW_MEMORY_FAILURE();
    }
    file_delete(from_ef);
    return SW_OK();
}

static int piv_encode_ecdsa_der(const mbedtls_mpi *r, const mbedtls_mpi *s, uint8_t *out, size_t out_cap, size_t *out_len) {
    uint8_t buf[160];
    unsigned char *p = buf + sizeof(buf);
    size_t len = 0;
    int ret = mbedtls_asn1_write_mpi(&p, buf, s);
    if (ret < 0) {
        return ret;
    }
    len += (size_t)ret;
    ret = mbedtls_asn1_write_mpi(&p, buf, r);
    if (ret < 0) {
        return ret;
    }
    len += (size_t)ret;
    ret = mbedtls_asn1_write_len(&p, buf, len);
    if (ret < 0) {
        return ret;
    }
    len += (size_t)ret;
    ret = mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (ret < 0) {
        return ret;
    }
    len += (size_t)ret;
    if (len > out_cap) {
        return -1;
    }
    memcpy(out, p, len);
    *out_len = len;
    return 0;
}

static int cmd_piv_authenticate(void) {
    uint8_t alg = P1(apdu);
    uint8_t slot = P2(apdu);

    tlv_ctx_t outer, dyn;
    tlv_ctx_init(BYTE_ARRAY(apdu.data, apdu.nc), &outer);
    if (!tlv_find_tag(&outer, TAG_DYN_AUTH, &dyn)) {
        return SW_WRONG_DATA();
    }

    if (slot == PIV_SLOT_CARD_MGM) {
        piv_state_t st;
        piv_load_state(&st);
        if (alg != st.mgm_type) {
            mbedtls_platform_zeroize(&st, sizeof(st));
            return SW_INCORRECT_P1P2();
        }
        uint8_t block_len = (alg == PIV_ALG_3DES) ? 8 : 16;

        bool has_witness = false, has_challenge = false, has_response = false;
        tlv_ctx_t t_wit = { 0 }, t_chal = { 0 }, t_resp = { 0 };
        uint8_t *p = NULL;
        tlv_item_t item;
        while (tlv_walk(&dyn, &p, &item)) {
            if (item.tag == TAG_AUTH_WITNESS) {
                has_witness = true;
                t_wit.data = (uint8_t *)item.value.data;
                t_wit.len = (uint16_t)item.value.len;
            }
            else if (item.tag == TAG_AUTH_CHALLENGE) {
                has_challenge = true;
                t_chal.data = (uint8_t *)item.value.data;
                t_chal.len = (uint16_t)item.value.len;
            }
            else if (item.tag == TAG_AUTH_RESPONSE) {
                has_response = true;
                t_resp.data = (uint8_t *)item.value.data;
                t_resp.len = (uint16_t)item.value.len;
            }
        }

        if (has_witness && t_wit.len == 0) {
            random_fill_buffer(BYTE_ARRAY(piv_mgm_challenge, block_len));
            piv_mgm_challenge_len = block_len;
            piv_mgm_challenge_valid = true;
            piv_mgm_authenticated = false;

            uint8_t enc_wit[16] = { 0 };
            if (piv_mgm_ecb_crypt(&st, true, piv_mgm_challenge, enc_wit) != 0) {
                mbedtls_platform_zeroize(&st, sizeof(st));
                return SW_EXEC_ERROR();
            }
            uint8_t inner_tlv[20];
            uint8_t *ip = piv_append_tlv(inner_tlv, TAG_AUTH_WITNESS, enc_wit, block_len);
            uint8_t *rp = piv_append_tlv(res_APDU, TAG_DYN_AUTH, inner_tlv, (size_t)(ip - inner_tlv));
            res_APDU_size = (uint16_t)(rp - res_APDU);
            mbedtls_platform_zeroize(&st, sizeof(st));
            return SW_OK();
        }
        if (has_challenge && t_chal.len == 0 && !has_witness) {
            random_fill_buffer(BYTE_ARRAY(piv_mgm_challenge, block_len));
            uint8_t enc_chal[16] = { 0 };
            if (piv_mgm_ecb_crypt(&st, true, piv_mgm_challenge, enc_chal) != 0) {
                mbedtls_platform_zeroize(&st, sizeof(st));
                return SW_EXEC_ERROR();
            }
            memcpy(piv_mgm_challenge, enc_chal, block_len);
            piv_mgm_challenge_len = block_len;
            piv_mgm_challenge_valid = true;
            piv_mgm_authenticated = false;

            uint8_t inner_tlv[20];
            uint8_t *ip = piv_append_tlv(inner_tlv, TAG_AUTH_CHALLENGE, piv_mgm_challenge, block_len);
            uint8_t *rp = piv_append_tlv(res_APDU, TAG_DYN_AUTH, inner_tlv, (size_t)(ip - inner_tlv));
            res_APDU_size = (uint16_t)(rp - res_APDU);
            mbedtls_platform_zeroize(&st, sizeof(st));
            return SW_OK();
        }
        if (has_witness && t_wit.len == block_len && has_challenge && t_chal.len == block_len) {
            if (!piv_mgm_challenge_valid || piv_mgm_challenge_len != block_len ||
                mbedtls_ct_memcmp(t_wit.data, piv_mgm_challenge, block_len) != 0) {
                piv_mgm_challenge_valid = false;
                piv_mgm_authenticated = false;
                mbedtls_platform_zeroize(&st, sizeof(st));
                return SW_SECURITY_STATUS_NOT_SATISFIED();
            }
            if (!piv_check_touch(st.mgm_touch_policy)) {
                piv_mgm_challenge_valid = false;
                piv_mgm_authenticated = false;
                mbedtls_platform_zeroize(&st, sizeof(st));
                return SW_SECURITY_STATUS_NOT_SATISFIED();
            }
            uint8_t host_resp[16] = { 0 };
            if (piv_mgm_ecb_crypt(&st, true, t_chal.data, host_resp) != 0) {
                mbedtls_platform_zeroize(&st, sizeof(st));
                return SW_EXEC_ERROR();
            }
            piv_mgm_challenge_valid = false;
            piv_mgm_authenticated = true;

            uint8_t inner_tlv[20];
            uint8_t *ip = piv_append_tlv(inner_tlv, TAG_AUTH_RESPONSE, host_resp, block_len);
            uint8_t *rp = piv_append_tlv(res_APDU, TAG_DYN_AUTH, inner_tlv, (size_t)(ip - inner_tlv));
            res_APDU_size = (uint16_t)(rp - res_APDU);
            mbedtls_platform_zeroize(&st, sizeof(st));
            return SW_OK();
        }
        if (has_response && t_resp.len == block_len && piv_mgm_challenge_valid) {
            uint8_t expected[16] = { 0 };
            if (piv_mgm_ecb_crypt(&st, true, piv_mgm_challenge, expected) != 0 ||
                mbedtls_ct_memcmp(t_resp.data, expected, block_len) != 0) {
                piv_mgm_challenge_valid = false;
                piv_mgm_authenticated = false;
                mbedtls_platform_zeroize(&st, sizeof(st));
                return SW_SECURITY_STATUS_NOT_SATISFIED();
            }
            piv_mgm_challenge_valid = false;
            piv_mgm_authenticated = true;
            mbedtls_platform_zeroize(&st, sizeof(st));
            return SW_OK();
        }
        mbedtls_platform_zeroize(&st, sizeof(st));
        return SW_WRONG_DATA();
    }

    piv_key_header_t hdr;
    uint8_t *priv_buf = NULL;
    if (piv_load_slot_key(slot, &hdr, NULL, &priv_buf) != PICOKEYS_OK) {
        return SW_INCORRECT_P1P2();
    }
    if (hdr.key_type != alg) {
        mbedtls_platform_zeroize(priv_buf, hdr.priv_len);
        free(priv_buf);
        return SW_INCORRECT_P1P2();
    }

    if (hdr.pin_policy == PIV_PIN_POLICY_ONCE) {
        if (!piv_pin_verified) {
            mbedtls_platform_zeroize(priv_buf, hdr.priv_len);
            free(priv_buf);
            return SW_SECURITY_STATUS_NOT_SATISFIED();
        }
    }
    else if (hdr.pin_policy == PIV_PIN_POLICY_ALWAYS) {
        if (!piv_pin_verified || piv_pin_verified_once_used) {
            mbedtls_platform_zeroize(priv_buf, hdr.priv_len);
            free(priv_buf);
            return SW_SECURITY_STATUS_NOT_SATISFIED();
        }
        piv_pin_verified_once_used = true;
    }

    if (!piv_check_touch(hdr.touch_policy)) {
        mbedtls_platform_zeroize(priv_buf, hdr.priv_len);
        free(priv_buf);
        return SW_SECURITY_STATUS_NOT_SATISFIED();
    }

    tlv_ctx_t t_chal = { 0 }, t_exp = { 0 };
    bool has_chal = false, has_exp = false;
    uint8_t *p = NULL;
    tlv_item_t item;
    while (tlv_walk(&dyn, &p, &item)) {
        if (item.tag == TAG_AUTH_CHALLENGE) {
            has_chal = true;
            t_chal.data = (uint8_t *)item.value.data;
            t_chal.len = (uint16_t)item.value.len;
        }
        else if (item.tag == TAG_AUTH_EXPONENTIATION) {
            has_exp = true;
            t_exp.data = (uint8_t *)item.value.data;
            t_exp.len = (uint16_t)item.value.len;
        }
    }

    uint8_t *out_buf = (uint8_t *)calloc(1, 600);
    uint8_t *inner_buf = (uint8_t *)calloc(1, 620);
    if (!out_buf || !inner_buf) {
        free(out_buf);
        free(inner_buf);
        mbedtls_platform_zeroize(priv_buf, hdr.priv_len);
        free(priv_buf);
        return SW_MEMORY_FAILURE();
    }
    size_t out_len = 0;
    int ret = -1;

    size_t rsa_bits = piv_rsa_bits(alg);
    mbedtls_ecp_group_id grp_id = piv_ecp_group(alg);

    if (rsa_bits > 0 && has_chal) {
        size_t n_len = rsa_bits / 8u;
        size_t p_len = rsa_bits / 16u;
        if (t_chal.len != n_len || hdr.priv_len != 2u * p_len) {
            free(out_buf);
            free(inner_buf);
            mbedtls_platform_zeroize(priv_buf, hdr.priv_len);
            free(priv_buf);
            return SW_WRONG_DATA();
        }
        uint8_t e_buf[3] = { 0x01, 0x00, 0x01 };
        mbedtls_rsa_context rsa;
        mbedtls_rsa_init(&rsa);
        ret = mbedtls_rsa_import_raw(&rsa, NULL, 0, priv_buf, p_len, priv_buf + p_len, p_len, NULL, 0, e_buf, sizeof(e_buf));
        if (ret == 0) {
            ret = mbedtls_rsa_complete(&rsa);
        }
        if (ret == 0) {
            ret = mbedtls_rsa_private(&rsa, random_fill_iterator, NULL, t_chal.data, out_buf);
            out_len = n_len;
        }
        mbedtls_rsa_free(&rsa);
    }
    else if ((alg == PIV_ALG_ECCP256 || alg == PIV_ALG_ECCP384) && has_chal) {
        size_t grp_bytes = (alg == PIV_ALG_ECCP384) ? 48u : 32u;
        const uint8_t *digest = t_chal.data;
        size_t digest_len = t_chal.len > grp_bytes ? grp_bytes : t_chal.len;
        mbedtls_ecp_keypair kp;
        mbedtls_ecp_keypair_init(&kp);
        mbedtls_mpi r_mpi, s_mpi;
        mbedtls_mpi_init(&r_mpi);
        mbedtls_mpi_init(&s_mpi);
        ret = mbedtls_ecp_read_key(grp_id, &kp, priv_buf, hdr.priv_len);
        if (ret == 0) {
            ret = mbedtls_ecdsa_sign(&kp.grp, &r_mpi, &s_mpi, &kp.d, digest, digest_len, random_fill_iterator, NULL);
        }
        if (ret == 0) {
            ret = piv_encode_ecdsa_der(&r_mpi, &s_mpi, out_buf, 600, &out_len);
        }
        mbedtls_mpi_free(&r_mpi);
        mbedtls_mpi_free(&s_mpi);
        mbedtls_ecp_keypair_free(&kp);
    }
#ifdef MBEDTLS_EDDSA_C
    else if (alg == PIV_ALG_ED25519 && has_chal) {
        mbedtls_ecp_keypair kp;
        mbedtls_ecp_keypair_init(&kp);
        ret = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_ED25519, &kp, priv_buf, hdr.priv_len);
        if (ret == 0) {
            ret = mbedtls_eddsa_write_signature(&kp, t_chal.data, t_chal.len, out_buf, 600, &out_len, MBEDTLS_EDDSA_PURE, NULL, 0, random_fill_iterator, NULL);
        }
        mbedtls_ecp_keypair_free(&kp);
    }
#endif
    else if ((alg == PIV_ALG_ECCP256 || alg == PIV_ALG_ECCP384 || alg == PIV_ALG_X25519) && has_exp) {
        mbedtls_ecdh_context ecdh_ctx;
        mbedtls_ecp_keypair ours, theirs;
        mbedtls_ecdh_init(&ecdh_ctx);
        mbedtls_ecp_keypair_init(&ours);
        mbedtls_ecp_keypair_init(&theirs);

        ret = mbedtls_ecp_group_load(&ours.grp, grp_id);
        if (ret == 0) {
            ret = mbedtls_ecp_group_load(&theirs.grp, grp_id);
        }
        if (ret == 0) {
            ret = mbedtls_ecp_read_key(grp_id, &ours, priv_buf, hdr.priv_len);
        }
        if (ret == 0) {
            ret = mbedtls_ecp_point_read_binary(&theirs.grp, &theirs.Q, t_exp.data, t_exp.len);
        }
        if (ret == 0) {
            ret = mbedtls_ecdh_setup(&ecdh_ctx, grp_id);
        }
        if (ret == 0) {
            ret = mbedtls_ecdh_get_params(&ecdh_ctx, &ours, MBEDTLS_ECDH_OURS);
        }
        if (ret == 0) {
            ret = mbedtls_ecdh_get_params(&ecdh_ctx, &theirs, MBEDTLS_ECDH_THEIRS);
        }
        if (ret == 0) {
            ret = mbedtls_ecdh_calc_secret(&ecdh_ctx, &out_len, out_buf, 600, random_fill_iterator, NULL);
        }
        mbedtls_ecdh_free(&ecdh_ctx);
        mbedtls_ecp_keypair_free(&ours);
        mbedtls_ecp_keypair_free(&theirs);
    }

    mbedtls_platform_zeroize(priv_buf, hdr.priv_len);
    free(priv_buf);

    if (ret != 0) {
        free(out_buf);
        free(inner_buf);
        return SW_INCORRECT_PARAMS();
    }

    uint8_t *ip = piv_append_tlv(inner_buf, TAG_AUTH_RESPONSE, out_buf, out_len);
    uint8_t *rp = piv_append_tlv(res_APDU, TAG_DYN_AUTH, inner_buf, (size_t)(ip - inner_buf));
    res_APDU_size = (uint16_t)(rp - res_APDU);
    free(out_buf);
    free(inner_buf);
    return SW_OK();
}

static int piv_build_x509_cert(mbedtls_ecp_keypair *issuer_kp, const char *subject_dn, mbedtls_pk_context *subj_pk, bool is_ca, uint8_t slot_pin_policy, uint8_t slot_touch_policy, bool include_attest_ext, uint8_t *der_out, size_t der_cap, size_t *der_len) {
    mbedtls_x509write_cert crt;
    mbedtls_pk_context issuer_pk;
    mbedtls_x509write_crt_init(&crt);
    mbedtls_pk_init(&issuer_pk);

    issuer_pk.pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY);
    issuer_pk.pk_ctx = issuer_kp;

    mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_validity(&crt, "20240101000000", "20541231235959");
    mbedtls_x509write_crt_set_issuer_name(&crt, "CN=Yubico PIV Attestation");
    mbedtls_x509write_crt_set_subject_name(&crt, subject_dn);
    uint8_t serial[8];
    random_fill_buffer(BYTE_ARRAY(serial, sizeof(serial)));
    serial[0] &= 0x7F;
    mbedtls_x509write_crt_set_serial_raw(&crt, serial, sizeof(serial));
    mbedtls_x509write_crt_set_subject_key(&crt, subj_pk);
    mbedtls_x509write_crt_set_issuer_key(&crt, &issuer_pk);
    mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_basic_constraints(&crt, is_ca ? 1 : 0, is_ca ? 0 : -1);

    if (include_attest_ext) {
        // 1.3.6.1.4.1.41482.3.3: Firmware version (3 bytes: 5, 7, 2)
        const uint8_t fw_ver[3] = { PIV_VERSION_MAJOR, PIV_VERSION_MINOR, PIV_VERSION_PATCH };
        mbedtls_x509write_crt_set_extension(&crt, "\x2B\x06\x01\x04\x01\x82\xE4\x0A\x03\x03", 10, 0, fw_ver, sizeof(fw_ver));
        // 1.3.6.1.4.1.41482.3.7: Serial number (INTEGER 4 bytes)
        uint8_t ser_der[6] = { 0x02, 0x04, pico_serial.id[0] & (uint8_t)~0xFCu, pico_serial.id[1], pico_serial.id[2], pico_serial.id[3] };
        mbedtls_x509write_crt_set_extension(&crt, "\x2B\x06\x01\x04\x01\x82\xE4\x0A\x03\x07", 10, 0, ser_der, sizeof(ser_der));
        // 1.3.6.1.4.1.41482.3.8: Policy (2 bytes: pin_policy, touch_policy)
        uint8_t pol_ext[2] = { slot_pin_policy, slot_touch_policy };
        mbedtls_x509write_crt_set_extension(&crt, "\x2B\x06\x01\x04\x01\x82\xE4\x0A\x03\x08", 10, 0, pol_ext, sizeof(pol_ext));
        // 1.3.6.1.4.1.41482.3.9: Form factor (1 byte: 0x01)
        const uint8_t ff_ext[1] = { 0x01 };
        mbedtls_x509write_crt_set_extension(&crt, "\x2B\x06\x01\x04\x01\x82\xE4\x0A\x03\x09", 10, 0, ff_ext, sizeof(ff_ext));
    }

    int ret = mbedtls_x509write_crt_der(&crt, der_out, der_cap, random_fill_iterator, NULL);
    mbedtls_x509write_crt_free(&crt);
    if (ret <= 0) {
        return -1;
    }
    *der_len = (size_t)ret;
    memmove(der_out, der_out + der_cap - *der_len, *der_len);
    return 0;
}

static int piv_ensure_attestation_ready(void) {
    uint16_t key_fid = (uint16_t)(EF_PIV_KEY_BASE + 24);
    int obj_idx = piv_object_index(0x5FFF01u);
    uint16_t obj_fid = (uint16_t)(EF_PIV_OBJ_BASE + obj_idx);
    if (file_has_data(file_search(key_fid)) && file_has_data(file_search(obj_fid))) {
        return PICOKEYS_OK;
    }

    mbedtls_ecp_keypair kp;
    mbedtls_ecp_keypair_init(&kp);
    int ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, &kp, random_fill_iterator, NULL);
    uint8_t sk_raw[32] = { 0 };
    uint8_t pk_raw[65] = { 0 };
    size_t sk_len = 0, pk_len = 0;
    if (ret == 0) {
        ret = mbedtls_ecp_write_key_ext(&kp, &sk_len, sk_raw, sizeof(sk_raw));
    }
    if (ret == 0) {
        ret = mbedtls_ecp_point_write_binary(&kp.grp, &kp.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &pk_len, pk_raw, sizeof(pk_raw));
    }
    if (ret != 0) {
        mbedtls_ecp_keypair_free(&kp);
        return PICOKEYS_EXEC_ERROR;
    }

    uint8_t pub_tlv[70];
    uint8_t *wp = piv_append_tlv(pub_tlv, 0x86, pk_raw, pk_len);
    int store_ret = piv_store_slot_key(PIV_SLOT_ATTESTATION, PIV_ALG_ECCP256, PIV_PIN_POLICY_NEVER, PIV_TOUCH_POLICY_NEVER, PIV_ORIGIN_IMPORTED, pub_tlv, (uint16_t)(wp - pub_tlv), sk_raw, (uint16_t)sk_len);
    mbedtls_platform_zeroize(sk_raw, sizeof(sk_raw));
    if (store_ret != PICOKEYS_OK) {
        mbedtls_ecp_keypair_free(&kp);
        return store_ret;
    }

    uint8_t *cert_der = (uint8_t *)calloc(1, 1024);
    uint8_t *obj_buf = (uint8_t *)calloc(1, 1060);
    if (!cert_der || !obj_buf) {
        free(cert_der);
        free(obj_buf);
        mbedtls_ecp_keypair_free(&kp);
        return PICOKEYS_ERR_NO_MEMORY;
    }
    mbedtls_pk_context subj_pk;
    mbedtls_pk_init(&subj_pk);
    subj_pk.pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY);
    subj_pk.pk_ctx = &kp;

    size_t cert_len = 0;
    ret = piv_build_x509_cert(&kp, "CN=Yubico PIV Attestation", &subj_pk, true, 0, 0, false, cert_der, 1024, &cert_len);
    mbedtls_ecp_keypair_free(&kp);
    if (ret == 0) {
        uint8_t cert_info = 0x00;
        uint8_t *op = obj_buf;
        op = piv_append_tlv(op, 0x70, cert_der, cert_len);
        op = piv_append_tlv(op, 0x71, &cert_info, 1);
        op = piv_append_tlv(op, 0xFE, NULL, 0);
        file_t *ef = file_search(obj_fid);
        if (!ef) {
            ef = file_new(obj_fid);
        }
        if (ef) {
            file_put_data(ef, CONST_BYTE_ARRAY(obj_buf, (size_t)(op - obj_buf)));
            flash_commit();
        }
    }
    free(cert_der);
    free(obj_buf);
    return ret == 0 ? PICOKEYS_OK : PICOKEYS_EXEC_ERROR;
}

static int cmd_piv_attest(void) {
    uint8_t slot = P1(apdu);
    if (P2(apdu) != 0x00 || slot == PIV_SLOT_ATTESTATION || piv_slot_index(slot) < 0) {
        return SW_INCORRECT_P1P2();
    }
    piv_key_header_t hdr;
    uint8_t *priv_buf = NULL;
    if (piv_load_slot_key(slot, &hdr, NULL, &priv_buf) != PICOKEYS_OK) {
        return SW_INCORRECT_P1P2();
    }
    if (hdr.origin != PIV_ORIGIN_GENERATED) {
        mbedtls_platform_zeroize(priv_buf, hdr.priv_len);
        free(priv_buf);
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    if (piv_ensure_attestation_ready() != PICOKEYS_OK) {
        mbedtls_platform_zeroize(priv_buf, hdr.priv_len);
        free(priv_buf);
        return SW_EXEC_ERROR();
    }

    piv_key_header_t att_hdr;
    uint8_t *att_priv = NULL;
    if (piv_load_slot_key(PIV_SLOT_ATTESTATION, &att_hdr, NULL, &att_priv) != PICOKEYS_OK) {
        mbedtls_platform_zeroize(priv_buf, hdr.priv_len);
        free(priv_buf);
        return SW_EXEC_ERROR();
    }

    mbedtls_ecp_keypair issuer_kp;
    mbedtls_ecp_keypair_init(&issuer_kp);
    int ret = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, &issuer_kp, att_priv, att_hdr.priv_len);
    if (ret == 0) {
        ret = mbedtls_ecp_keypair_calc_public(&issuer_kp, random_fill_iterator, NULL);
    }
    mbedtls_platform_zeroize(att_priv, att_hdr.priv_len);
    free(att_priv);
    if (ret != 0) {
        mbedtls_ecp_keypair_free(&issuer_kp);
        mbedtls_platform_zeroize(priv_buf, hdr.priv_len);
        free(priv_buf);
        return SW_EXEC_ERROR();
    }

    mbedtls_pk_context subj_pk;
    mbedtls_pk_init(&subj_pk);
    mbedtls_ecp_keypair subj_ecp;
    mbedtls_ecp_keypair_init(&subj_ecp);
    mbedtls_rsa_context subj_rsa;
    mbedtls_rsa_init(&subj_rsa);

    size_t rsa_bits = piv_rsa_bits(hdr.key_type);
    mbedtls_ecp_group_id grp_id = piv_ecp_group(hdr.key_type);
    if (rsa_bits > 0) {
        size_t p_len = rsa_bits / 16u;
        uint8_t e_buf[3] = { 0x01, 0x00, 0x01 };
        ret = mbedtls_rsa_import_raw(&subj_rsa, NULL, 0, priv_buf, p_len, priv_buf + p_len, p_len, NULL, 0, e_buf, sizeof(e_buf));
        if (ret == 0) {
            ret = mbedtls_rsa_complete(&subj_rsa);
        }
        subj_pk.pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_RSA);
        subj_pk.pk_ctx = &subj_rsa;
    }
    else if (grp_id == MBEDTLS_ECP_DP_SECP256R1 || grp_id == MBEDTLS_ECP_DP_SECP384R1) {
        ret = mbedtls_ecp_read_key(grp_id, &subj_ecp, priv_buf, hdr.priv_len);
        if (ret == 0) {
            ret = mbedtls_ecp_keypair_calc_public(&subj_ecp, random_fill_iterator, NULL);
        }
        subj_pk.pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY);
        subj_pk.pk_ctx = &subj_ecp;
    }
    else {
        ret = -1;
    }
    mbedtls_platform_zeroize(priv_buf, hdr.priv_len);
    free(priv_buf);

    if (ret != 0) {
        mbedtls_ecp_keypair_free(&issuer_kp);
        mbedtls_ecp_keypair_free(&subj_ecp);
        mbedtls_rsa_free(&subj_rsa);
        return SW_INCORRECT_P1P2();
    }

    char subj_dn[40];
    snprintf(subj_dn, sizeof(subj_dn), "CN=YubiKey PIV Attestation %02x", slot);
    size_t der_len = 0;
    ret = piv_build_x509_cert(&issuer_kp, subj_dn, &subj_pk, false, hdr.pin_policy, hdr.touch_policy, true, res_APDU, 1500, &der_len);
    mbedtls_ecp_keypair_free(&issuer_kp);
    mbedtls_ecp_keypair_free(&subj_ecp);
    mbedtls_rsa_free(&subj_rsa);
    if (ret != 0) {
        return SW_EXEC_ERROR();
    }
    res_APDU_size = (uint16_t)der_len;
    return SW_OK();
}

static const cmd_t piv_cmds[] = {
    { INS_VERIFY, cmd_piv_verify },
    { INS_CHANGE_REFERENCE, cmd_piv_change_reference },
    { INS_RESET_RETRY, cmd_piv_reset_retry },
    { INS_GENERATE_ASYMMETRIC, cmd_piv_generate_asymmetric },
    { INS_AUTHENTICATE, cmd_piv_authenticate },
    { INS_GET_DATA, cmd_piv_get_data },
    { INS_PUT_DATA, cmd_piv_put_data },
    { INS_MOVE_KEY, cmd_piv_move_key },
    { INS_GET_METADATA, cmd_piv_get_metadata },
    { INS_GET_SERIAL, cmd_piv_get_serial },
    { INS_ATTEST, cmd_piv_attest },
    { INS_SET_PIN_RETRIES, cmd_piv_set_pin_retries },
    { INS_RESET, cmd_piv_reset },
    { INS_GET_VERSION, cmd_piv_get_version },
    { INS_IMPORT_KEY, cmd_piv_import_key },
    { INS_SET_MGMKEY, cmd_piv_set_mgmkey },
    { 0x00, NULL }
};

static int piv_process_apdu(void) {
    if (CLA(apdu) != 0x00) {
        return SW_CLA_NOT_SUPPORTED();
    }
    if (!cap_supported(CAP_PIV)) {
        return SW_INS_NOT_SUPPORTED();
    }
    for (const cmd_t *cmd = piv_cmds; cmd->ins != 0x00; cmd++) {
        if (cmd->ins == INS(apdu)) {
            return cmd->cmd_handler();
        }
    }
    return SW_INS_NOT_SUPPORTED();
}
