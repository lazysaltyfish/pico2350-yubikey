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

typedef struct {
    bool valid;
    uint8_t slot;
    uint8_t algo;
    uint8_t credential_hash[32];
    uint8_t priv[32];
    uint8_t pub[65];
    uint8_t nonce[8];
} hsmauth_challenge_t;

static hsmauth_challenge_t challenge;

static void hsmauth_clear_challenge(void) {
    mbedtls_platform_zeroize(&challenge, sizeof(challenge));
}

static int hsmauth_bind_challenge(uint8_t slot, const hsmauth_cred_t *cred) {
    /* Bind the challenge to credential contents, excluding the storage IV/tag
     * and retry counter, which change on an otherwise harmless PIN verify. */
    hsmauth_cred_t identity = *cred;
    identity.retries = 0;
    int ret = mbedtls_sha256((const uint8_t *)&identity, offsetof(hsmauth_cred_t, iv),
                             challenge.credential_hash, 0);
    mbedtls_platform_zeroize(&identity, sizeof(identity));
    if (ret == 0) {
        challenge.slot = slot;
        challenge.algo = cred->algo;
        challenge.valid = true;
    }
    return ret;
}

static bool hsmauth_challenge_matches(const hsmauth_challenge_t *pending,
                                       uint8_t slot, const hsmauth_cred_t *cred) {
    if (!pending->valid || pending->slot != slot || pending->algo != cred->algo) return false;
    hsmauth_cred_t identity = *cred;
    identity.retries = 0;
    uint8_t digest[32];
    int ret = mbedtls_sha256((const uint8_t *)&identity, offsetof(hsmauth_cred_t, iv), digest, 0);
    bool matches = ret == 0 && mbedtls_ct_memcmp(digest, pending->credential_hash, sizeof(digest)) == 0;
    mbedtls_platform_zeroize(&identity, sizeof(identity));
    mbedtls_platform_zeroize(digest, sizeof(digest));
    return matches;
}
/* LIST can exceed the USB transmit buffer. Keep its public metadata stable
 * while the APDU layer copies bounded chunks for ISO GET RESPONSE. */
static uint8_t hsmauth_list_response[HSMAUTH_MAX_CREDS * (HSMAUTH_MAX_LABEL_LEN + HSMAUTH_LIST_ITEM_OVERHEAD)];

static int hsmauth_rng(void *ctx, unsigned char *buf, size_t len) {
    (void)ctx;
    return random_fill_buffer(BYTE_ARRAY(buf, len));
}

static void hsmauth_default_state(hsmauth_state_t *st) {
    memset(st, 0, sizeof(*st));
    st->magic = HSMAUTH_STATE_MAGIC;
    st->mgm_retries = HSMAUTH_INITIAL_RETRIES;
}

static applet_txn_t hsmauth_txn = APPLET_TXN_INITIALIZER(EF_HSMAUTH_TXN);

static bool hsmauth_record_save(uint16_t fid, const void *data, size_t len) {
    bool ok = applet_txn_ready(&hsmauth_txn) && applet_storage_save(fid, data, len) && flash_commit_sync(5000);
    if (!ok) applet_txn_fail(&hsmauth_txn);
    return ok;
}

static bool hsmauth_record_delete(file_t *ef) {
    bool ok = file_delete_no_commit(ef) == PICOKEYS_OK && flash_commit_sync(5000);
    if (!ok) applet_txn_fail(&hsmauth_txn);
    return ok;
}

static bool hsmauth_save_state(const hsmauth_state_t *st) {
    return hsmauth_record_save(EF_HSMAUTH_STATE, st, sizeof(*st));
}

static bool hsmauth_load_state(hsmauth_state_t *st) {
    memset(st, 0, sizeof(*st));
    if (!applet_txn_ready(&hsmauth_txn)) return false;
    file_t *ef = file_search(EF_HSMAUTH_STATE);
    if (ef && file_has_data(ef)) {
        bool ok = applet_storage_load(EF_HSMAUTH_STATE, st, sizeof(*st)) &&
                  st->magic == HSMAUTH_STATE_MAGIC && st->mgm_retries <= HSMAUTH_INITIAL_RETRIES;
        if (!ok) mbedtls_platform_zeroize(st, sizeof(*st));
        return ok;
    }
    /* Missing authentication state must never grant default access to
     * credentials that survived an incomplete erase or legacy upgrade. */
    for (uint16_t i = 0; i < HSMAUTH_MAX_CREDS; i++) {
        if (file_has_data(file_search((uint16_t)(EF_HSMAUTH_CRED_BASE + i)))) return false;
    }
    hsmauth_default_state(st);
    return hsmauth_save_state(st);
}

static bool hsmauth_load_cred(uint8_t idx, hsmauth_cred_t *cred) {
    if (idx >= HSMAUTH_MAX_CREDS) return false;
    bool ok = applet_storage_load((uint16_t)(EF_HSMAUTH_CRED_BASE + idx), cred, sizeof(*cred)) &&
              cred->magic == HSMAUTH_STATE_MAGIC && cred->label_len > 0 &&
              cred->label_len <= sizeof(cred->label) && cred->touch_required <= 1 &&
              cred->retries <= HSMAUTH_INITIAL_RETRIES &&
              (cred->algo == HSMAUTH_ALG_AES128 || cred->algo == HSMAUTH_ALG_ECP256);
    if (!ok) mbedtls_platform_zeroize(cred, sizeof(*cred));
    return ok;
}

static bool hsmauth_save_cred(uint8_t idx, const hsmauth_cred_t *cred) {
    if (idx >= HSMAUTH_MAX_CREDS) return false;
    hsmauth_cred_t stored = *cred;
    stored.magic = HSMAUTH_STATE_MAGIC;
    memset(stored.iv, 0, sizeof(stored.iv));
    memset(stored.tag, 0, sizeof(stored.tag));
    bool ok = hsmauth_record_save((uint16_t)(EF_HSMAUTH_CRED_BASE + idx), &stored, sizeof(stored));
    mbedtls_platform_zeroize(&stored, sizeof(stored));
    return ok;
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
    st->mgm_retries--;
    if (!hsmauth_save_state(st)) return SW_MEMORY_FAILURE();
    /* Persist the attempt before comparing, so cutting power cannot undo a
     * guess whose correctness might be inferred from later processing. */
    if (mbedtls_ct_memcmp(st->mgm_key, mgm, 16) != 0)
        return set_res_sw(0x63, (uint8_t)(0xC0 | st->mgm_retries));
    st->mgm_retries = HSMAUTH_INITIAL_RETRIES;
    return hsmauth_save_state(st) ? SW_OK() : SW_MEMORY_FAILURE();
}

static int hsmauth_verify_cred_pw(uint8_t slot, hsmauth_cred_t *cred, const uint8_t *pw, size_t pw_len) {
    if (!pw || pw_len != 16) return SW_WRONG_DATA();
    if (cred->retries == 0) return SW_PIN_BLOCKED();
    cred->retries--;
    if (!hsmauth_save_cred(slot, cred)) return SW_MEMORY_FAILURE();
    if (mbedtls_ct_memcmp(cred->cred_pw, pw, 16) != 0)
        return set_res_sw(0x63, (uint8_t)(0xC0 | cred->retries));
    cred->retries = HSMAUTH_INITIAL_RETRIES;
    return hsmauth_save_cred(slot, cred) ? SW_OK() : SW_MEMORY_FAILURE();
}

static int hsmauth_scp03_kdf(const uint8_t key[16], uint8_t deriv_const, uint16_t out_bits,
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
    return mbedtls_cipher_cmac(ci, key, 128, msg, sizeof(msg), out);
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
    if (!hsmauth_load_state(&st)) return SW_EXEC_ERROR();
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
    if (!hsmauth_load_state(&st)) return SW_EXEC_ERROR();
    int rc = hsmauth_verify_mgm(&st, old_mgm, 16);
    if (rc != SW_OK()) return rc;
    memcpy(st.mgm_key, new_mgm, 16);
    st.mgm_retries = HSMAUTH_INITIAL_RETRIES;
    if (!hsmauth_save_state(&st)) return SW_MEMORY_FAILURE();
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
    if (!hsmauth_load_state(&st)) return SW_EXEC_ERROR();
    if (!applet_txn_begin(&hsmauth_txn)) return SW_MEMORY_FAILURE();
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
    if (!hsmauth_load_state(&st)) return SW_EXEC_ERROR();
    if (!applet_txn_begin(&hsmauth_txn)) return SW_MEMORY_FAILURE();
    int rc = hsmauth_verify_mgm(&st, mgm, 16);
    if (rc != SW_OK()) return rc;

    int slot = hsmauth_find_cred(label, label_len, NULL);
    if (slot < 0) return SW_FILE_NOT_FOUND();
    file_t *ef = file_search((uint16_t)(EF_HSMAUTH_CRED_BASE + slot));
    if (ef && file_has_data(ef)) {
        if (!hsmauth_record_delete(ef)) return SW_MEMORY_FAILURE();
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
        if (!hsmauth_save_cred((uint8_t)slot, &cred)) {
            mbedtls_platform_zeroize(&cred, sizeof(cred));
            return SW_MEMORY_FAILURE();
        }
    }
    else {
        if (!mgm || !pw1) {
            mbedtls_platform_zeroize(&cred, sizeof(cred));
            return SW_WRONG_DATA();
        }
        hsmauth_state_t st;
        if (!hsmauth_load_state(&st)) return SW_EXEC_ERROR();
        if (!applet_txn_begin(&hsmauth_txn)) {
            mbedtls_platform_zeroize(&cred, sizeof(cred));
            return SW_MEMORY_FAILURE();
        }
        int rc = hsmauth_verify_mgm(&st, mgm, 16);
        if (rc != SW_OK()) {
            mbedtls_platform_zeroize(&cred, sizeof(cred));
            return rc;
        }
        memcpy(cred.cred_pw, pw1, 16);
        cred.retries = HSMAUTH_INITIAL_RETRIES;
        if (!hsmauth_save_cred((uint8_t)slot, &cred)) {
            mbedtls_platform_zeroize(&cred, sizeof(cred));
            return SW_MEMORY_FAILURE();
        }
    }
    mbedtls_platform_zeroize(&cred, sizeof(cred));
    return SW_OK();
}

static int cmd_hsmauth_get_challenge(void) {
    hsmauth_clear_challenge();
    size_t pos = 0, label_len = 0;
    uint8_t t;
    const uint8_t *v, *label = NULL, *pw = NULL;
    size_t l;
    while (hsmauth_next_tlv(apdu.data, apdu.nc, &pos, &t, &v, &l)) {
        if (t == HSMAUTH_TAG_LABEL) {
            if (label) return SW_WRONG_DATA();
            label = v;
            label_len = l;
        }
        else if (t == HSMAUTH_TAG_CREDENTIAL_PASSWORD) {
            if (pw || l != 16) return SW_WRONG_DATA();
            pw = v;
        }
    }
    if (pos != apdu.nc || !label || label_len < 1 || label_len > 64) return SW_WRONG_DATA();
    hsmauth_cred_t cred;
    int slot = hsmauth_find_cred(label, label_len, &cred);
    if (slot < 0) return SW_FILE_NOT_FOUND();
    int ret = PICOKEYS_OK;
    if (cred.algo == HSMAUTH_ALG_AES128) {
        ret = random_fill_buffer(BYTE_ARRAY(challenge.nonce, sizeof(challenge.nonce)));
    }
    else if (cred.algo == HSMAUTH_ALG_ECP256) {
        /* Firmware 5.8 requires the credential password before allocating an
         * asymmetric exchange. It is checked again when session keys are used. */
        if (!pw) {
            mbedtls_platform_zeroize(&cred, sizeof(cred));
            return SW_WRONG_DATA();
        }
        int rc = hsmauth_verify_cred_pw((uint8_t)slot, &cred, pw, 16);
        if (rc != SW_OK()) {
            mbedtls_platform_zeroize(&cred, sizeof(cred));
            return rc;
        }
        mbedtls_ecp_keypair kp;
        mbedtls_ecp_keypair_init(&kp);
        ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, &kp, hsmauth_rng, NULL);
        if (ret == 0) ret = mbedtls_mpi_write_binary(&kp.d, challenge.priv, sizeof(challenge.priv));
        if (ret == 0) {
            size_t olen = 0;
            ret = mbedtls_ecp_point_write_binary(&kp.grp, &kp.Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                                 &olen, challenge.pub, sizeof(challenge.pub));
            if (ret == 0 && olen != sizeof(challenge.pub)) ret = PICOKEYS_EXEC_ERROR;
        }
        mbedtls_ecp_keypair_free(&kp);
    }
    else {
        ret = PICOKEYS_WRONG_DATA;
    }
    if (ret == 0) ret = hsmauth_bind_challenge((uint8_t)slot, &cred);
    mbedtls_platform_zeroize(&cred, sizeof(cred));
    if (ret != 0) {
        hsmauth_clear_challenge();
        return SW_EXEC_ERROR();
    }
    res_APDU_size = challenge.algo == HSMAUTH_ALG_AES128 ? sizeof(challenge.nonce) : sizeof(challenge.pub);
    memcpy(res_APDU, challenge.algo == HSMAUTH_ALG_AES128 ? challenge.nonce : challenge.pub, res_APDU_size);
    return SW_OK();
}

static int hsmauth_calculate(const hsmauth_challenge_t *pending) {
    size_t pos = 0;
    uint8_t t;
    const uint8_t *v;
    size_t l;
    const uint8_t *label = NULL, *ctx = NULL, *pk_sd = NULL, *card_crypto = NULL, *pw = NULL;
    size_t label_len = 0, ctx_len = 0, pk_sd_len = 0, crypto_len = 0;
    while (hsmauth_next_tlv(apdu.data, apdu.nc, &pos, &t, &v, &l)) {
        switch (t) {
            case HSMAUTH_TAG_LABEL:
                if (label) return SW_WRONG_DATA();
                label = v; label_len = l; break;
            case HSMAUTH_TAG_CONTEXT:
                if (ctx) return SW_WRONG_DATA();
                ctx = v; ctx_len = l; break;
            case HSMAUTH_TAG_PUBLIC_KEY:
                if (pk_sd) return SW_WRONG_DATA();
                pk_sd = v; pk_sd_len = l; break;
            case HSMAUTH_TAG_RESPONSE:
                if (card_crypto) return SW_WRONG_DATA();
                card_crypto = v; crypto_len = l; break;
            case HSMAUTH_TAG_CREDENTIAL_PASSWORD:
                if (pw || l != 16) return SW_WRONG_DATA();
                pw = v; break;
            default: break;
        }
    }
    if (pos != apdu.nc || !label || label_len < 1 || label_len > 64 || !pw || !ctx || !card_crypto) {
        return SW_WRONG_DATA();
    }
    hsmauth_cred_t cred;
    int slot = hsmauth_find_cred(label, label_len, &cred);
    if (slot < 0) return SW_FILE_NOT_FOUND();

    bool matches = hsmauth_challenge_matches(pending, (uint8_t)slot, &cred);
    if ((pending->valid && !matches) || (cred.algo == HSMAUTH_ALG_ECP256 && !matches)) {
        mbedtls_platform_zeroize(&cred, sizeof(cred));
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    if ((cred.algo == HSMAUTH_ALG_AES128 && (ctx_len != 16 || crypto_len != 8 ||
         (pending->valid && mbedtls_ct_memcmp(ctx, pending->nonce, 8) != 0))) ||
        (cred.algo == HSMAUTH_ALG_ECP256 && (ctx_len != 130 || !pk_sd || pk_sd_len != 65 ||
         crypto_len != 16 || mbedtls_ct_memcmp(ctx, pending->pub, 65) != 0)) ||
        (cred.algo != HSMAUTH_ALG_AES128 && cred.algo != HSMAUTH_ALG_ECP256)) {
        mbedtls_platform_zeroize(&cred, sizeof(cred));
        return SW_WRONG_DATA();
    }
    int rc = hsmauth_verify_cred_pw((uint8_t)slot, &cred, pw, 16);
    if (rc != SW_OK()) {
        mbedtls_platform_zeroize(&cred, sizeof(cred));
        return rc;
    }
    if (cred.touch_required) {
#ifdef ENABLE_EMULATION
        bool present = check_user_presence();
#else
        uint32_t timeout_s = button_timeout_seconds();
        if (timeout_s == 0) timeout_s = 15;
        bool present = wait_button_pressed_timeout(timeout_s) == 0;
#endif
        if (!present) {
            mbedtls_platform_zeroize(&cred, sizeof(cred));
            return SW_SECURITY_STATUS_NOT_SATISFIED();
        }
    }

    /* Derive into private temporaries. Session material is copied into the
     * response only after constant-time verification of the peer's proof. */
    uint8_t keys[64] = {0}, expected[16] = {0};
    int ret;
    if (cred.algo == HSMAUTH_ALG_AES128) {
        /* Older symmetric clients supply their own host challenge. Preserve
         * that flow when no challenge is pending; the proof authenticates the
         * supplied context but does not establish local freshness by itself. */
        ret = hsmauth_scp03_kdf(cred.secret, 0x04, 128, ctx, keys);
        if (ret == 0) ret = hsmauth_scp03_kdf(cred.secret + 16, 0x06, 128, ctx, keys + 16);
        if (ret == 0) ret = hsmauth_scp03_kdf(cred.secret + 16, 0x07, 128, ctx, keys + 32);
        if (ret == 0) ret = hsmauth_scp03_kdf(keys + 16, 0x00, 64, ctx, expected);
        if (ret == 0 && mbedtls_ct_memcmp(expected, card_crypto, 8) != 0) ret = PICOKEYS_VERIFICATION_FAILED;
        if (ret == 0) memcpy(res_APDU, keys, 48);
    }
    else {
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
        ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
        if (ret == 0) ret = mbedtls_mpi_read_binary(&d_static, cred.secret, 32);
        if (ret == 0) ret = mbedtls_mpi_read_binary(&d_ephem, pending->priv, 32);
        if (ret == 0) ret = mbedtls_ecp_check_privkey(&grp, &d_static);
        if (ret == 0) ret = mbedtls_ecp_check_privkey(&grp, &d_ephem);
        if (ret == 0) ret = mbedtls_ecp_point_read_binary(&grp, &Q_sd, pk_sd, 65);
        if (ret == 0) ret = mbedtls_ecp_check_pubkey(&grp, &Q_sd);
        if (ret == 0) ret = mbedtls_ecp_point_read_binary(&grp, &Q_epk_sd, ctx + 65, 65);
        if (ret == 0) ret = mbedtls_ecp_check_pubkey(&grp, &Q_epk_sd);
        if (ret == 0) ret = mbedtls_ecdh_compute_shared(&grp, &z_see, &Q_epk_sd, &d_ephem, hsmauth_rng, NULL);
        if (ret == 0) ret = mbedtls_ecdh_compute_shared(&grp, &z_sss, &Q_sd, &d_static, hsmauth_rng, NULL);

        /* X9.63 with the YubiHSM asymmetric authentication sharedInfo. */
        uint8_t kdf_in[64 + 4 + 3] = {0};
        if (ret == 0) ret = mbedtls_mpi_write_binary(&z_see, kdf_in, 32);
        if (ret == 0) ret = mbedtls_mpi_write_binary(&z_sss, kdf_in + 32, 32);
        memcpy(kdf_in + 68, "\x3c\x88\x10", 3);
        kdf_in[67] = 1;
        if (ret == 0) ret = mbedtls_sha256(kdf_in, sizeof(kdf_in), keys, 0);
        kdf_in[67] = 2;
        if (ret == 0) ret = mbedtls_sha256(kdf_in, sizeof(kdf_in), keys + 32, 0);
        const mbedtls_cipher_info_t *ci = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
        uint8_t receipt_input[130];
        memcpy(receipt_input, ctx + 65, 65);
        memcpy(receipt_input + 65, ctx, 65);
        if (ret == 0) ret = mbedtls_cipher_cmac(ci, keys, 128, receipt_input, sizeof(receipt_input), expected);
        if (ret == 0 && mbedtls_ct_memcmp(expected, card_crypto, 16) != 0) ret = PICOKEYS_VERIFICATION_FAILED;
        if (ret == 0) memcpy(res_APDU, keys + 16, 48);
        mbedtls_platform_zeroize(kdf_in, sizeof(kdf_in));
        mbedtls_ecp_group_free(&grp);
        mbedtls_ecp_point_free(&Q_sd);
        mbedtls_ecp_point_free(&Q_epk_sd);
        mbedtls_mpi_free(&d_static);
        mbedtls_mpi_free(&d_ephem);
        mbedtls_mpi_free(&z_sss);
        mbedtls_mpi_free(&z_see);
    }
    mbedtls_platform_zeroize(keys, sizeof(keys));
    mbedtls_platform_zeroize(expected, sizeof(expected));
    mbedtls_platform_zeroize(&cred, sizeof(cred));
    if (ret != 0) return SW_SECURITY_STATUS_NOT_SATISFIED();
    res_APDU_size = 48;
    return SW_OK();
}

static int cmd_hsmauth_calculate(void) {
    hsmauth_challenge_t pending = challenge;
    hsmauth_clear_challenge(); /* Every attempt consumes state, even malformed requests. */
    int ret = hsmauth_calculate(&pending);
    mbedtls_platform_zeroize(&pending, sizeof(pending));
    return ret;
}

static int cmd_hsmauth_reset(void) {
    if (P1(apdu) != 0xDE || P2(apdu) != 0xAD) {
        return SW_INCORRECT_P1P2();
    }
    if (apdu.nc != 0) return SW_WRONG_LENGTH();
#ifdef ENABLE_EMULATION
    if (!check_user_presence()) return SW_SECURITY_STATUS_NOT_SATISFIED();
#else
    uint32_t timeout_s = button_timeout_seconds();
    if (timeout_s == 0) timeout_s = 15;
    if (wait_button_pressed_timeout(timeout_s) != 0) return SW_SECURITY_STATUS_NOT_SATISFIED();
#endif
    if (!applet_txn_recover_begin(&hsmauth_txn)) return SW_MEMORY_FAILURE();
    for (uint8_t i = 0; i < HSMAUTH_MAX_CREDS; i++) {
        file_t *ef = file_search((uint16_t)(EF_HSMAUTH_CRED_BASE + i));
        if (ef && file_has_data(ef) && !hsmauth_record_delete(ef)) return SW_MEMORY_FAILURE();
    }
    hsmauth_state_t st;
    hsmauth_default_state(&st);
    if (!hsmauth_save_state(&st)) return SW_MEMORY_FAILURE();
    hsmauth_clear_challenge();
    return applet_txn_commit(&hsmauth_txn) ? SW_OK() : SW_MEMORY_FAILURE();
}

static int hsmauth_unload(void) {
    apdu_clear_response_buffer();
    hsmauth_clear_challenge();
    return PICOKEYS_OK;
}

static int hsmauth_dispatch(void) {
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

static int hsmauth_process_apdu(void) {
    uint8_t ins = INS(apdu);
    if (ins == HSMAUTH_INS_PUT || ins == HSMAUTH_INS_DELETE ||
        ins == HSMAUTH_INS_CHANGE_CREDENTIAL_PASSWORD ||
        ins == HSMAUTH_INS_PUT_MANAGEMENT_KEY || ins == HSMAUTH_INS_RESET) {
        hsmauth_clear_challenge();
    }
    if (!cap_supported(CAP_HSMAUTH)) return SW_INS_NOT_SUPPORTED();
    if (ins == HSMAUTH_INS_RESET) return cmd_hsmauth_reset();
    hsmauth_state_t state;
    if (!hsmauth_load_state(&state)) {
        hsmauth_unload();
        return SW_EXEC_ERROR();
    }
    mbedtls_platform_zeroize(&state, sizeof(state));
    int ret = hsmauth_dispatch();
    if ((hsmauth_txn.active && !applet_txn_commit(&hsmauth_txn)) || hsmauth_txn.faulted) {
        mbedtls_platform_zeroize(res_APDU, res_APDU_size);
        hsmauth_unload();
        return SW_MEMORY_FAILURE();
    }
    return ret;
}

static const uint8_t hsmauth_aid[] = {
    8,
    0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x07, 0x01
};

static int hsmauth_select(app_t *a, uint8_t force) {
    (void)force;
    hsmauth_clear_challenge();
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
