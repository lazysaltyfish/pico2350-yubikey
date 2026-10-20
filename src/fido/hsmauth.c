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
#include "crypto_utils.h"
#include "management.h"
#include "fido.h"
#include "button.h"
#include "pico_time.h"
#include "mbedtls/cmac.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/sha256.h"
#include "mbedtls/gcm.h"
#include "mbedtls/constant_time.h"
#include "mbedtls/platform_util.h"

#define HSMAUTH_INS_PUT                        0x01
#define HSMAUTH_INS_DELETE                     0x02
#define HSMAUTH_INS_CALCULATE                  0x03
#define HSMAUTH_INS_GET_CHALLENGE              0x04
#define HSMAUTH_INS_LIST                       0x05
#define HSMAUTH_INS_RESET                      0x06
#define HSMAUTH_INS_GET_VERSION                0x07
#define HSMAUTH_INS_PUT_MANAGEMENT_KEY         0x08
#define HSMAUTH_INS_GET_MANAGEMENT_KEY_RETRIES 0x09
#define HSMAUTH_INS_GET_PUBLIC_KEY             0x0A
#define HSMAUTH_INS_CHANGE_CREDENTIAL_PASSWORD 0x0B

#define HSMAUTH_TAG_LABEL               0x71
#define HSMAUTH_TAG_LABEL_LIST          0x72
#define HSMAUTH_TAG_CREDENTIAL_PASSWORD 0x73
#define HSMAUTH_TAG_ALGORITHM           0x74
#define HSMAUTH_TAG_KEY_ENC             0x75
#define HSMAUTH_TAG_KEY_MAC             0x76
#define HSMAUTH_TAG_CONTEXT             0x77
#define HSMAUTH_TAG_RESPONSE            0x78
#define HSMAUTH_TAG_VERSION             0x79
#define HSMAUTH_TAG_TOUCH               0x7A
#define HSMAUTH_TAG_MANAGEMENT_KEY      0x7B
#define HSMAUTH_TAG_PUBLIC_KEY          0x7C
#define HSMAUTH_TAG_PRIVATE_KEY         0x7D

#define HSMAUTH_ALG_AES128 38 /* 0x26 */
#define HSMAUTH_ALG_ECP256 39 /* 0x27 */

#define HSMAUTH_MAX_CREDS       32
#define HSMAUTH_MAX_LABEL_LEN   64
#define HSMAUTH_LIST_ITEM_OVERHEAD 5
#define HSMAUTH_INITIAL_RETRIES 8
#define HSMAUTH_STATE_MAGIC     0x48534D41UL

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint8_t mgm_key[16];
    uint8_t mgm_retries;
} hsmauth_state_t;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint8_t algo;
    uint8_t touch_required;
    uint8_t retries;
    uint8_t label_len;
    uint8_t label[64];
    uint8_t cred_pw[16];
    uint8_t secret[32]; /* For AES128: key_enc(16)||key_mac(16); For ECP256: priv_d(32) */
    uint8_t pub_point[65]; /* 04 || X(32) || Y(32) for ECP256 */
    uint8_t iv[12];
    uint8_t tag[16];
} hsmauth_cred_t;

static uint8_t ephem_priv[32];
static uint8_t ephem_pub[65];
static bool ephem_valid = false;
/* LIST can exceed the USB transmit buffer. Keep its public metadata stable
 * while the APDU layer copies bounded chunks for ISO GET RESPONSE. */
static uint8_t hsmauth_list_response[HSMAUTH_MAX_CREDS * (HSMAUTH_MAX_LABEL_LEN + HSMAUTH_LIST_ITEM_OVERHEAD)];

static int hsmauth_rng(void *ctx, unsigned char *buf, size_t len) {
    (void)ctx;
    random_fill_buffer(BYTE_ARRAY(buf, len));
    return 0;
}

static void hsmauth_derive_mk(uint8_t mk[32]) {
    uint8_t kbase[32];
    derive_kbase(kbase);
    uint8_t seed[64];
    memcpy(seed, kbase, 32);
    static const char label[32] = "PICO-FIDO-HSMAUTH-MK-V1";
    memcpy(seed + 32, label, 32);
    mbedtls_sha256(seed, sizeof(seed), mk, 0);
    mbedtls_platform_zeroize(kbase, sizeof(kbase));
    mbedtls_platform_zeroize(seed, sizeof(seed));
}

static void hsmauth_default_state(hsmauth_state_t *st) {
    memset(st, 0, sizeof(*st));
    st->magic = HSMAUTH_STATE_MAGIC;
    st->mgm_retries = HSMAUTH_INITIAL_RETRIES;
}

static void hsmauth_save_state(const hsmauth_state_t *st) {
    file_t *ef = file_search(EF_HSMAUTH_STATE);
    if (!ef) ef = file_new(EF_HSMAUTH_STATE);
    if (ef) {
        file_put_data(ef, CONST_BYTE_ARRAY((const uint8_t *)st, sizeof(*st)));
        flash_commit();
    }
}

static void hsmauth_load_state(hsmauth_state_t *st) {
    file_t *ef = file_search(EF_HSMAUTH_STATE);
    if (ef && file_has_data(ef) && file_get_size(ef) == sizeof(*st)) {
        memcpy(st, file_get_data(ef), sizeof(*st));
        if (st->magic == HSMAUTH_STATE_MAGIC) {
            return;
        }
    }
    hsmauth_default_state(st);
}

static bool hsmauth_load_cred(uint8_t idx, hsmauth_cred_t *cred) {
    if (idx >= HSMAUTH_MAX_CREDS) return false;
    file_t *ef = file_search((uint16_t)(EF_HSMAUTH_CRED_BASE + idx));
    if (!ef || !file_has_data(ef) || file_get_size(ef) != sizeof(*cred)) {
        return false;
    }
    memcpy(cred, file_get_data(ef), sizeof(*cred));
    if (cred->magic != HSMAUTH_STATE_MAGIC || cred->label_len == 0 || cred->label_len > sizeof(cred->label)) {
        return false;
    }
    uint8_t mk[32];
    hsmauth_derive_mk(mk);
    uint8_t plain[48];
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int r = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, mk, 256);
    if (r == 0) {
        r = mbedtls_gcm_auth_decrypt(&gcm, 48, cred->iv, sizeof(cred->iv),
                                     cred->label, cred->label_len,
                                     cred->tag, sizeof(cred->tag),
                                     cred->cred_pw, plain);
    }
    mbedtls_gcm_free(&gcm);
    mbedtls_platform_zeroize(mk, sizeof(mk));
    if (r != 0) {
        return false;
    }
    memcpy(cred->cred_pw, plain, 16);
    memcpy(cred->secret, plain + 16, 32);
    mbedtls_platform_zeroize(plain, sizeof(plain));
    return true;
}

static bool hsmauth_save_cred(uint8_t idx, const hsmauth_cred_t *cred_in) {
    if (idx >= HSMAUTH_MAX_CREDS) return false;
    hsmauth_cred_t stored = *cred_in;
    stored.magic = HSMAUTH_STATE_MAGIC;
    random_fill_buffer(BYTE_ARRAY(stored.iv, sizeof(stored.iv)));

    uint8_t plain[48];
    memcpy(plain, cred_in->cred_pw, 16);
    memcpy(plain + 16, cred_in->secret, 32);

    uint8_t mk[32];
    hsmauth_derive_mk(mk);
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int r = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, mk, 256);
    if (r == 0) {
        r = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, 48,
                                      stored.iv, sizeof(stored.iv),
                                      stored.label, stored.label_len,
                                      plain, stored.cred_pw,
                                      sizeof(stored.tag), stored.tag);
    }
    mbedtls_gcm_free(&gcm);
    mbedtls_platform_zeroize(mk, sizeof(mk));
    mbedtls_platform_zeroize(plain, sizeof(plain));
    if (r != 0) return false;

    uint16_t fid = (uint16_t)(EF_HSMAUTH_CRED_BASE + idx);
    file_t *ef = file_search(fid);
    if (!ef) ef = file_new(fid);
    if (!ef) return false;
    file_put_data(ef, CONST_BYTE_ARRAY((const uint8_t *)&stored, sizeof(stored)));
    flash_commit();
    return true;
}

static int hsmauth_find_cred(const uint8_t *label, size_t label_len, hsmauth_cred_t *cred_out) {
    for (uint8_t i = 0; i < HSMAUTH_MAX_CREDS; i++) {
        hsmauth_cred_t c;
        if (hsmauth_load_cred(i, &c)) {
            if (c.label_len == label_len && memcmp(c.label, label, label_len) == 0) {
                if (cred_out) *cred_out = c;
                mbedtls_platform_zeroize(&c, sizeof(c));
                return i;
            }
            mbedtls_platform_zeroize(&c, sizeof(c));
        }
    }
    return -1;
}

static int hsmauth_find_free_slot(void) {
    for (uint8_t i = 0; i < HSMAUTH_MAX_CREDS; i++) {
        file_t *ef = file_search((uint16_t)(EF_HSMAUTH_CRED_BASE + i));
        if (!ef || !file_has_data(ef)) {
            return i;
        }
    }
    return -1;
}

static bool hsmauth_next_tlv(const uint8_t *buf, size_t buf_len, size_t *pos, uint8_t *tag, const uint8_t **val, size_t *len) {
    if (*pos + 2 > buf_len) return false;
    size_t p = *pos;
    uint8_t t = buf[p++];
    size_t l = buf[p++];
    if (l == 0x81) {
        if (p >= buf_len) return false;
        l = buf[p++];
    }
    else if (l == 0x82) {
        if (p + 1 >= buf_len) return false;
        l = ((size_t)buf[p] << 8) | buf[p + 1];
        p += 2;
    }
    if (p + l > buf_len) return false;
    *tag = t;
    *val = buf + p;
    *len = l;
    *pos = p + l;
    return true;
}

static int hsmauth_verify_mgm(hsmauth_state_t *st, const uint8_t *mgm, size_t mgm_len) {
    if (!mgm || mgm_len != 16) return SW_WRONG_DATA();
    if (st->mgm_retries == 0) return SW_PIN_BLOCKED();
    if (mbedtls_ct_memcmp(st->mgm_key, mgm, 16) == 0) {
        if (st->mgm_retries != HSMAUTH_INITIAL_RETRIES) {
            st->mgm_retries = HSMAUTH_INITIAL_RETRIES;
            hsmauth_save_state(st);
        }
        return SW_OK();
    }
    st->mgm_retries--;
    hsmauth_save_state(st);
    return set_res_sw(0x63, (uint8_t)(0xC0 | (st->mgm_retries & 0x0F)));
}

static int hsmauth_verify_cred_pw(uint8_t slot, hsmauth_cred_t *cred, const uint8_t *pw, size_t pw_len) {
    if (!pw || pw_len != 16) return SW_WRONG_DATA();
    if (cred->retries == 0) return SW_PIN_BLOCKED();
    if (mbedtls_ct_memcmp(cred->cred_pw, pw, 16) == 0) {
        if (cred->retries != HSMAUTH_INITIAL_RETRIES) {
            cred->retries = HSMAUTH_INITIAL_RETRIES;
            hsmauth_save_cred(slot, cred);
        }
        return SW_OK();
    }
    cred->retries--;
    hsmauth_save_cred(slot, cred);
    return set_res_sw(0x63, (uint8_t)(0xC0 | (cred->retries & 0x0F)));
}

static void hsmauth_scp03_kdf(const uint8_t key[16], uint8_t deriv_const, uint16_t out_bits,
                              const uint8_t context[16], uint8_t out[16]) {
    uint8_t msg[32];
    memset(msg, 0, 11);
    msg[11] = deriv_const;
    msg[12] = 0x00;
    msg[13] = (uint8_t)(out_bits >> 8);
    msg[14] = (uint8_t)(out_bits & 0xFF);
    msg[15] = 0x01;
    memcpy(msg + 16, context, 16);
    const mbedtls_cipher_info_t *ci = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
    mbedtls_cipher_cmac(ci, key, 128, msg, sizeof(msg), out);
}

static int cmd_hsmauth_get_version(void) {
    res_APDU[0] = 5;
    res_APDU[1] = 8;
    res_APDU[2] = 0;
    res_APDU_size = 3;
    return SW_OK();
}

static int cmd_hsmauth_get_mgm_retries(void) {
    hsmauth_state_t st;
    hsmauth_load_state(&st);
    res_APDU[0] = st.mgm_retries;
    res_APDU_size = 1;
    return SW_OK();
}

static int cmd_hsmauth_put_mgm_key(void) {
    size_t pos = 0;
    uint8_t t = 0;
    const uint8_t *v = NULL;
    size_t l = 0;
    const uint8_t *old_mgm = NULL, *new_mgm = NULL;
    while (hsmauth_next_tlv(apdu.data, apdu.nc, &pos, &t, &v, &l)) {
        if (t == HSMAUTH_TAG_MANAGEMENT_KEY && l == 16) {
            if (!old_mgm) old_mgm = v;
            else if (!new_mgm) new_mgm = v;
        }
    }
    if (!old_mgm || !new_mgm) return SW_WRONG_DATA();
    hsmauth_state_t st;
    hsmauth_load_state(&st);
    int rc = hsmauth_verify_mgm(&st, old_mgm, 16);
    if (rc != SW_OK()) return rc;
    memcpy(st.mgm_key, new_mgm, 16);
    st.mgm_retries = HSMAUTH_INITIAL_RETRIES;
    hsmauth_save_state(&st);
    return SW_OK();
}

static int cmd_hsmauth_list(void) {
    size_t off = 0;
    for (uint8_t i = 0; i < HSMAUTH_MAX_CREDS; i++) {
        hsmauth_cred_t c;
        if (hsmauth_load_cred(i, &c)) {
            size_t size = HSMAUTH_LIST_ITEM_OVERHEAD + c.label_len;
            if (size > sizeof(hsmauth_list_response) - off) {
                mbedtls_platform_zeroize(&c, sizeof(c));
                return SW_MEMORY_FAILURE();
            }
            uint8_t item_len = (uint8_t)(3 + c.label_len);
            hsmauth_list_response[off++] = HSMAUTH_TAG_LABEL_LIST;
            hsmauth_list_response[off++] = item_len;
            hsmauth_list_response[off++] = c.algo;
            hsmauth_list_response[off++] = c.touch_required;
            memcpy(hsmauth_list_response + off, c.label, c.label_len);
            off += c.label_len;
            hsmauth_list_response[off++] = c.retries;
            mbedtls_platform_zeroize(&c, sizeof(c));
        }
    }
    apdu_set_response_buffer(hsmauth_list_response, (uint16_t)off);
    return SW_OK();
}

static int cmd_hsmauth_put(void) {
    size_t pos = 0;
    uint8_t t = 0;
    const uint8_t *v = NULL;
    size_t l = 0;
    const uint8_t *mgm = NULL, *label = NULL, *k_enc = NULL, *k_mac = NULL, *priv = NULL, *pw = NULL;
    size_t label_len = 0, priv_len = 0;
    bool has_priv = false;
    uint8_t algo = 0;
    uint8_t touch = 0;

    while (hsmauth_next_tlv(apdu.data, apdu.nc, &pos, &t, &v, &l)) {
        switch (t) {
            case HSMAUTH_TAG_MANAGEMENT_KEY: if (l == 16) mgm = v; break;
            case HSMAUTH_TAG_LABEL: label = v; label_len = l; break;
            case HSMAUTH_TAG_ALGORITHM: if (l == 1) algo = v[0]; break;
            case HSMAUTH_TAG_KEY_ENC: if (l == 16) k_enc = v; break;
            case HSMAUTH_TAG_KEY_MAC: if (l == 16) k_mac = v; break;
            case HSMAUTH_TAG_PRIVATE_KEY: has_priv = true; priv = v; priv_len = l; break;
            case HSMAUTH_TAG_CREDENTIAL_PASSWORD: if (l == 16) pw = v; break;
            case HSMAUTH_TAG_TOUCH: if (l == 1) touch = v[0] ? 1 : 0; break;
            default: break;
        }
    }
    if (!mgm || !label || label_len < 1 || label_len > 64 || !pw) {
        return SW_WRONG_DATA();
    }
    hsmauth_state_t st;
    hsmauth_load_state(&st);
    int rc = hsmauth_verify_mgm(&st, mgm, 16);
    if (rc != SW_OK()) return rc;

    if (hsmauth_find_cred(label, label_len, NULL) >= 0) {
        return SW_COMMAND_NOT_ALLOWED();
    }
    int slot = hsmauth_find_free_slot();
    if (slot < 0) return SW_FILE_FULL();

    hsmauth_cred_t cred;
    memset(&cred, 0, sizeof(cred));
    cred.algo = algo;
    cred.touch_required = touch;
    cred.retries = HSMAUTH_INITIAL_RETRIES;
    cred.label_len = (uint8_t)label_len;
    memcpy(cred.label, label, label_len);
    memcpy(cred.cred_pw, pw, 16);

    if (algo == HSMAUTH_ALG_AES128) {
        if (!k_enc || !k_mac) return SW_WRONG_DATA();
        memcpy(cred.secret, k_enc, 16);
        memcpy(cred.secret + 16, k_mac, 16);
    }
    else if (algo == HSMAUTH_ALG_ECP256) {
        if (!has_priv || (priv_len != 0 && priv_len != 32)) return SW_WRONG_DATA();
        mbedtls_ecp_keypair kp;
        mbedtls_ecp_keypair_init(&kp);
        int ret = -1;
        if (priv_len == 0) {
            ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, &kp, hsmauth_rng, NULL);
            if (ret == 0) ret = mbedtls_mpi_write_binary(&kp.d, cred.secret, 32);
        }
        else {
            memcpy(cred.secret, priv, 32);
            ret = mbedtls_ecp_group_load(&kp.grp, MBEDTLS_ECP_DP_SECP256R1);
            if (ret == 0) ret = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, &kp, cred.secret, 32);
            if (ret == 0) ret = mbedtls_ecp_keypair_calc_public(&kp, hsmauth_rng, NULL);
        }
        if (ret == 0) {
            size_t olen = 0;
            ret = mbedtls_ecp_point_write_binary(&kp.grp, &kp.Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                                 &olen, cred.pub_point, sizeof(cred.pub_point));
        }
        mbedtls_ecp_keypair_free(&kp);
        if (ret != 0) {
            mbedtls_platform_zeroize(&cred, sizeof(cred));
            return SW_WRONG_DATA();
        }
    }
    else {
        return SW_WRONG_DATA();
    }

    bool ok = hsmauth_save_cred((uint8_t)slot, &cred);
    mbedtls_platform_zeroize(&cred, sizeof(cred));
    return ok ? SW_OK() : SW_MEMORY_FAILURE();
}

static int cmd_hsmauth_get_public_key(void) {
    size_t pos = 0;
    uint8_t t = 0;
    const uint8_t *v = NULL;
    size_t l = 0;
    const uint8_t *label = NULL;
    size_t label_len = 0;
    while (hsmauth_next_tlv(apdu.data, apdu.nc, &pos, &t, &v, &l)) {
        if (t == HSMAUTH_TAG_LABEL) { label = v; label_len = l; }
    }
    if (!label || label_len < 1 || label_len > 64) return SW_WRONG_DATA();
    hsmauth_cred_t cred;
    int slot = hsmauth_find_cred(label, label_len, &cred);
    if (slot < 0 || cred.algo != HSMAUTH_ALG_ECP256) {
        mbedtls_platform_zeroize(&cred, sizeof(cred));
        return SW_FILE_NOT_FOUND();
    }
    memcpy(res_APDU, cred.pub_point, 65);
    res_APDU_size = 65;
    mbedtls_platform_zeroize(&cred, sizeof(cred));
    return SW_OK();
}

static int cmd_hsmauth_delete(void) {
    size_t pos = 0;
    uint8_t t = 0;
    const uint8_t *v = NULL;
    size_t l = 0;
    const uint8_t *mgm = NULL, *label = NULL;
    size_t label_len = 0;
    while (hsmauth_next_tlv(apdu.data, apdu.nc, &pos, &t, &v, &l)) {
        if (t == HSMAUTH_TAG_MANAGEMENT_KEY && l == 16) mgm = v;
        else if (t == HSMAUTH_TAG_LABEL) { label = v; label_len = l; }
    }
    if (!mgm || !label || label_len < 1 || label_len > 64) return SW_WRONG_DATA();
    hsmauth_state_t st;
    hsmauth_load_state(&st);
    int rc = hsmauth_verify_mgm(&st, mgm, 16);
    if (rc != SW_OK()) return rc;

    int slot = hsmauth_find_cred(label, label_len, NULL);
    if (slot < 0) return SW_FILE_NOT_FOUND();
    file_t *ef = file_search((uint16_t)(EF_HSMAUTH_CRED_BASE + slot));
    if (ef && file_has_data(ef)) {
        file_delete(ef);
        flash_commit();
    }
    return SW_OK();
}

static int cmd_hsmauth_change_cred_password(void) {
    uint8_t p1 = P1(apdu);
    if (P2(apdu) != 0x00 || (p1 != 0x00 && p1 != 0x01)) {
        return SW_INCORRECT_P1P2();
    }
    size_t pos = 0;
    uint8_t t = 0;
    const uint8_t *v = NULL;
    size_t l = 0;
    const uint8_t *label = NULL, *mgm = NULL, *pw1 = NULL, *pw2 = NULL;
    size_t label_len = 0;
    while (hsmauth_next_tlv(apdu.data, apdu.nc, &pos, &t, &v, &l)) {
        if (t == HSMAUTH_TAG_LABEL) { label = v; label_len = l; }
        else if (t == HSMAUTH_TAG_MANAGEMENT_KEY && l == 16) mgm = v;
        else if (t == HSMAUTH_TAG_CREDENTIAL_PASSWORD && l == 16) {
            if (!pw1) pw1 = v;
            else if (!pw2) pw2 = v;
        }
    }
    if (!label || label_len < 1 || label_len > 64) return SW_WRONG_DATA();
    hsmauth_cred_t cred;
    int slot = hsmauth_find_cred(label, label_len, &cred);
    if (slot < 0) return SW_FILE_NOT_FOUND();

    if (p1 == 0x00) {
        if (!pw1 || !pw2) {
            mbedtls_platform_zeroize(&cred, sizeof(cred));
            return SW_WRONG_DATA();
        }
        int rc = hsmauth_verify_cred_pw((uint8_t)slot, &cred, pw1, 16);
        if (rc != SW_OK()) {
            mbedtls_platform_zeroize(&cred, sizeof(cred));
            return rc;
        }
        memcpy(cred.cred_pw, pw2, 16);
        cred.retries = HSMAUTH_INITIAL_RETRIES;
        hsmauth_save_cred((uint8_t)slot, &cred);
    }
    else {
        if (!mgm || !pw1) {
            mbedtls_platform_zeroize(&cred, sizeof(cred));
            return SW_WRONG_DATA();
        }
        hsmauth_state_t st;
        hsmauth_load_state(&st);
        int rc = hsmauth_verify_mgm(&st, mgm, 16);
        if (rc != SW_OK()) {
            mbedtls_platform_zeroize(&cred, sizeof(cred));
            return rc;
        }
        memcpy(cred.cred_pw, pw1, 16);
        cred.retries = HSMAUTH_INITIAL_RETRIES;
        hsmauth_save_cred((uint8_t)slot, &cred);
    }
    mbedtls_platform_zeroize(&cred, sizeof(cred));
    return SW_OK();
}

static int cmd_hsmauth_get_challenge(void) {
    size_t pos = 0;
    uint8_t t = 0;
    const uint8_t *v = NULL;
    size_t l = 0;
    const uint8_t *label = NULL, *pw = NULL;
    size_t label_len = 0;
    while (hsmauth_next_tlv(apdu.data, apdu.nc, &pos, &t, &v, &l)) {
        if (t == HSMAUTH_TAG_LABEL) { label = v; label_len = l; }
        else if (t == HSMAUTH_TAG_CREDENTIAL_PASSWORD && l == 16) pw = v;
    }
    if (!label || label_len < 1 || label_len > 64) return SW_WRONG_DATA();
    hsmauth_cred_t cred;
    int slot = hsmauth_find_cred(label, label_len, &cred);
    if (slot < 0) return SW_FILE_NOT_FOUND();

    if (cred.algo == HSMAUTH_ALG_AES128) {
        random_fill_buffer(BYTE_ARRAY(res_APDU, 8));
        res_APDU_size = 8;
        mbedtls_platform_zeroize(&cred, sizeof(cred));
        return SW_OK();
    }
    else {
        if (pw) {
            int rc = hsmauth_verify_cred_pw((uint8_t)slot, &cred, pw, 16);
            if (rc != SW_OK()) {
                mbedtls_platform_zeroize(&cred, sizeof(cred));
                return rc;
            }
        }
        mbedtls_platform_zeroize(&cred, sizeof(cred));
        mbedtls_ecp_keypair kp;
        mbedtls_ecp_keypair_init(&kp);
        int ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, &kp, hsmauth_rng, NULL);
        if (ret == 0) ret = mbedtls_mpi_write_binary(&kp.d, ephem_priv, 32);
        if (ret == 0) {
            size_t olen = 0;
            ret = mbedtls_ecp_point_write_binary(&kp.grp, &kp.Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                                 &olen, ephem_pub, sizeof(ephem_pub));
        }
        mbedtls_ecp_keypair_free(&kp);
        if (ret != 0) return SW_EXEC_ERROR();
        ephem_valid = true;
        memcpy(res_APDU, ephem_pub, 65);
        res_APDU_size = 65;
        return SW_OK();
    }
}

static int cmd_hsmauth_calculate(void) {
    size_t pos = 0;
    uint8_t t = 0;
    const uint8_t *v = NULL;
    size_t l = 0;
    const uint8_t *label = NULL, *ctx = NULL, *pk_sd = NULL, *card_crypto = NULL, *pw = NULL;
    size_t label_len = 0, ctx_len = 0, pk_sd_len = 0, crypto_len = 0;
    while (hsmauth_next_tlv(apdu.data, apdu.nc, &pos, &t, &v, &l)) {
        switch (t) {
            case HSMAUTH_TAG_LABEL: label = v; label_len = l; break;
            case HSMAUTH_TAG_CONTEXT: ctx = v; ctx_len = l; break;
            case HSMAUTH_TAG_PUBLIC_KEY: pk_sd = v; pk_sd_len = l; break;
            case HSMAUTH_TAG_RESPONSE: card_crypto = v; crypto_len = l; break;
            case HSMAUTH_TAG_CREDENTIAL_PASSWORD: if (l == 16) pw = v; break;
            default: break;
        }
    }
    if (!label || label_len < 1 || label_len > 64 || !pw || !ctx || !card_crypto) {
        return SW_WRONG_DATA();
    }
    hsmauth_cred_t cred;
    int slot = hsmauth_find_cred(label, label_len, &cred);
    if (slot < 0) return SW_FILE_NOT_FOUND();

    int rc = hsmauth_verify_cred_pw((uint8_t)slot, &cred, pw, 16);
    if (rc != SW_OK()) {
        mbedtls_platform_zeroize(&cred, sizeof(cred));
        return rc;
    }

    if (cred.touch_required) {
#ifdef ENABLE_EMULATION
        if (!check_user_presence()) {
            mbedtls_platform_zeroize(&cred, sizeof(cred));
            return SW_SECURITY_STATUS_NOT_SATISFIED();
        }
#else
        uint32_t timeout_s = button_timeout_seconds();
        if (timeout_s == 0) timeout_s = 15;
        if (wait_button_pressed_timeout(timeout_s) != 0) {
            mbedtls_platform_zeroize(&cred, sizeof(cred));
            return SW_SECURITY_STATUS_NOT_SATISFIED();
        }
#endif
    }

    if (cred.algo == HSMAUTH_ALG_AES128) {
        if (ctx_len != 16 || crypto_len != 8) {
            mbedtls_platform_zeroize(&cred, sizeof(cred));
            return SW_WRONG_DATA();
        }
        hsmauth_scp03_kdf(cred.secret,      0x04, 0x0080, ctx, res_APDU);
        hsmauth_scp03_kdf(cred.secret + 16, 0x06, 0x0080, ctx, res_APDU + 16);
        hsmauth_scp03_kdf(cred.secret + 16, 0x07, 0x0080, ctx, res_APDU + 32);
        res_APDU_size = 48;
        mbedtls_platform_zeroize(&cred, sizeof(cred));
        return SW_OK();
    }
    else {
        if (ctx_len != 130 || pk_sd_len != 65 || crypto_len != 16) {
            mbedtls_platform_zeroize(&cred, sizeof(cred));
            return SW_WRONG_DATA();
        }
        /* Compute ShSss = ECDH(sk_oce, pk_sd) and ShSee = ECDH(esk_oce, epk_sd) */
        mbedtls_ecp_group grp;
        mbedtls_ecp_point Q_sd, Q_epk_sd;
        mbedtls_mpi d_static, d_ephem, z_sss, z_see;
        mbedtls_ecp_group_init(&grp);
        mbedtls_ecp_point_init(&Q_sd);
        mbedtls_ecp_point_init(&Q_epk_sd);
        mbedtls_mpi_init(&d_static);
        mbedtls_mpi_init(&d_ephem);
        mbedtls_mpi_init(&z_sss);
        mbedtls_mpi_init(&z_see);

        int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
        if (ret == 0) ret = mbedtls_mpi_read_binary(&d_static, cred.secret, 32);
        if (ret == 0) ret = mbedtls_mpi_read_binary(&d_ephem, ephem_valid ? ephem_priv : cred.secret, 32);
        if (ret == 0) ret = mbedtls_ecp_point_read_binary(&grp, &Q_sd, pk_sd, 65);
        if (ret == 0) ret = mbedtls_ecp_point_read_binary(&grp, &Q_epk_sd, ctx + 65, 65);
        if (ret == 0) ret = mbedtls_ecdh_compute_shared(&grp, &z_see, &Q_epk_sd, &d_ephem, hsmauth_rng, NULL);
        if (ret == 0) ret = mbedtls_ecdh_compute_shared(&grp, &z_sss, &Q_sd, &d_static, hsmauth_rng, NULL);

        uint8_t sh_see[32], sh_sss[32];
        if (ret == 0) ret = mbedtls_mpi_write_binary(&z_see, sh_see, 32);
        if (ret == 0) ret = mbedtls_mpi_write_binary(&z_sss, sh_sss, 32);

        mbedtls_ecp_group_free(&grp);
        mbedtls_ecp_point_free(&Q_sd);
        mbedtls_ecp_point_free(&Q_epk_sd);
        mbedtls_mpi_free(&d_static);
        mbedtls_mpi_free(&d_ephem);
        mbedtls_mpi_free(&z_sss);
        mbedtls_mpi_free(&z_see);
        mbedtls_platform_zeroize(&cred, sizeof(cred));

        if (ret != 0) {
            return SW_WRONG_DATA();
        }
        /* X9.63 SHA-256 KDF over sh_see || sh_sss || counter(1,2) || ctx */
        uint8_t kdf_in[64 + 4 + 130], block1[32], block2[32];
        memcpy(kdf_in, sh_see, 32);
        memcpy(kdf_in + 32, sh_sss, 32);
        memcpy(kdf_in + 68, ctx, 130);
        kdf_in[64] = 0; kdf_in[65] = 0; kdf_in[66] = 0; kdf_in[67] = 1;
        mbedtls_sha256(kdf_in, sizeof(kdf_in), block1, 0);
        kdf_in[67] = 2;
        mbedtls_sha256(kdf_in, sizeof(kdf_in), block2, 0);
        /* Skip first 16 bytes (receipt key), return key_senc(16) || key_smac(16) || key_srmac(16) */
        memcpy(res_APDU, block1 + 16, 16);
        memcpy(res_APDU + 16, block2, 32);
        res_APDU_size = 48;
        mbedtls_platform_zeroize(kdf_in, sizeof(kdf_in));
        return SW_OK();
    }
}

static int cmd_hsmauth_reset(void) {
    if (P1(apdu) != 0xDE || P2(apdu) != 0xAD) {
        return SW_INCORRECT_P1P2();
    }
    for (uint8_t i = 0; i < HSMAUTH_MAX_CREDS; i++) {
        file_t *ef = file_search((uint16_t)(EF_HSMAUTH_CRED_BASE + i));
        if (ef && file_has_data(ef)) {
            file_delete_no_commit(ef);
        }
    }
    hsmauth_state_t st;
    hsmauth_default_state(&st);
    hsmauth_save_state(&st);
    ephem_valid = false;
    return SW_OK();
}

static int hsmauth_unload(void) {
    apdu_clear_response_buffer();
    ephem_valid = false;
    return PICOKEYS_OK;
}

static int hsmauth_process_apdu(void) {
    if (!cap_supported(CAP_HSMAUTH)) {
        return SW_INS_NOT_SUPPORTED();
    }
    switch (INS(apdu)) {
        case HSMAUTH_INS_PUT:                        return cmd_hsmauth_put();
        case HSMAUTH_INS_DELETE:                     return cmd_hsmauth_delete();
        case HSMAUTH_INS_CALCULATE:                  return cmd_hsmauth_calculate();
        case HSMAUTH_INS_GET_CHALLENGE:              return cmd_hsmauth_get_challenge();
        case HSMAUTH_INS_LIST:                       return cmd_hsmauth_list();
        case HSMAUTH_INS_RESET:                      return cmd_hsmauth_reset();
        case HSMAUTH_INS_GET_VERSION:                return cmd_hsmauth_get_version();
        case HSMAUTH_INS_PUT_MANAGEMENT_KEY:         return cmd_hsmauth_put_mgm_key();
        case HSMAUTH_INS_GET_MANAGEMENT_KEY_RETRIES: return cmd_hsmauth_get_mgm_retries();
        case HSMAUTH_INS_GET_PUBLIC_KEY:             return cmd_hsmauth_get_public_key();
        case HSMAUTH_INS_CHANGE_CREDENTIAL_PASSWORD: return cmd_hsmauth_change_cred_password();
        default:                                     return SW_INS_NOT_SUPPORTED();
    }
}

static const uint8_t hsmauth_aid[] = {
    8,
    0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x07, 0x01
};

static int hsmauth_select(app_t *a, uint8_t force) {
    (void)force;
    if (!cap_supported(CAP_HSMAUTH)) {
        return PICOKEYS_ERR_FILE_NOT_FOUND;
    }
    a->process_apdu = hsmauth_process_apdu;
    a->unload = hsmauth_unload;
    res_APDU[0] = HSMAUTH_TAG_VERSION;
    res_APDU[1] = 3;
    res_APDU[2] = 5;
    res_APDU[3] = 8;
    res_APDU[4] = 0;
    res_APDU_size = 5;
    apdu.ne = 5;
    return PICOKEYS_OK;
}

INITIALIZER(hsmauth_ctor) {
    register_app(hsmauth_select, hsmauth_aid);
}
