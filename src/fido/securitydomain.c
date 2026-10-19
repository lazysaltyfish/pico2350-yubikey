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
#include "mbedtls/ecp.h"
#include "mbedtls/platform_util.h"

#define SD_INS_PERFORM_SECURITY_OPERATION 0x2A
#define SD_INS_INITIALIZE_UPDATE          0x50
#define SD_INS_EXTERNAL_AUTHENTICATE      0x82
#define SD_INS_INTERNAL_AUTHENTICATE      0x88
#define SD_INS_GET_DATA                   0xCA
#define SD_INS_PUT_KEY                    0xD8
#define SD_INS_STORE_DATA                 0xE2
#define SD_INS_DELETE                     0xE4
#define SD_INS_GENERATE_KEY               0xF1

#define SD_TAG_CARD_RECOGNITION_DATA 0x0066
#define SD_TAG_KEY_INFORMATION       0x00E0
#define SD_TAG_CERTIFICATE_STORE     0xBF21
#define SD_TAG_CA_KLOC_IDENTIFIERS   0xFF33
#define SD_TAG_CA_KLCC_IDENTIFIERS   0xFF34

#define SD_KEY_TYPE_AES            0x88
#define SD_KEY_TYPE_ECC_PUBLIC_KEY 0xB0
#define SD_KEY_TYPE_ECC_PRIV_KEY   0xB1
#define SD_KEY_TYPE_ECC_KEY_PARAMS 0xF0

#define SD_MAX_KEYS    8
#define SD_STATE_MAGIC 0x53444F4DUL

typedef struct __attribute__((packed)) {
    uint8_t used;
    uint8_t kid;
    uint8_t kvn;
    uint8_t is_ec;
    uint8_t curve_id;
    uint8_t pub_len;
    uint8_t priv_len;
    uint8_t has_ca_ski;
    uint8_t ca_klcc;
    uint8_t ca_ski_len;
    uint8_t ca_ski[32];
} sd_key_entry_t;

typedef struct __attribute__((packed)) {
    uint32_t magic;
    sd_key_entry_t keys[SD_MAX_KEYS];
} sd_state_t;

static int sd_rng(void *ctx, unsigned char *buf, size_t len) {
    (void)ctx;
    random_fill_buffer(BYTE_ARRAY(buf, len));
    return 0;
}

static mbedtls_ecp_group_id sd_curve_to_grp(uint8_t curve_id, uint8_t *pub_len_out, uint8_t *priv_len_out) {
    switch (curve_id) {
        case 0: *pub_len_out = 65;  *priv_len_out = 32; return MBEDTLS_ECP_DP_SECP256R1;
        case 1: *pub_len_out = 97;  *priv_len_out = 48; return MBEDTLS_ECP_DP_SECP384R1;
        case 2: *pub_len_out = 133; *priv_len_out = 66; return MBEDTLS_ECP_DP_SECP521R1;
        case 3: *pub_len_out = 65;  *priv_len_out = 32; return MBEDTLS_ECP_DP_BP256R1;
        case 5: *pub_len_out = 97;  *priv_len_out = 48; return MBEDTLS_ECP_DP_BP384R1;
        case 7: *pub_len_out = 129; *priv_len_out = 64; return MBEDTLS_ECP_DP_BP512R1;
        default: return MBEDTLS_ECP_DP_NONE;
    }
}

static void sd_default_state(sd_state_t *st) {
    memset(st, 0, sizeof(*st));
    st->magic = SD_STATE_MAGIC;
    /* Slot 0: Default SCP03 static AES-128 key set (KID=0x01, KVN=0xFF) */
    st->keys[0].used = 1;
    st->keys[0].kid = 0x01;
    st->keys[0].kvn = 0xFF;
    st->keys[0].is_ec = 0;
    /* Slot 1: Default SCP11b P-256 key (KID=0x13, KVN=0x01) */
    st->keys[1].used = 1;
    st->keys[1].kid = 0x13;
    st->keys[1].kvn = 0x01;
    st->keys[1].is_ec = 1;
    st->keys[1].curve_id = 0;
    st->keys[1].pub_len = 65;
    st->keys[1].priv_len = 32;
}

static void sd_save_state(const sd_state_t *st) {
    file_t *ef = file_search(EF_SD_STATE);
    if (!ef) ef = file_new(EF_SD_STATE);
    if (ef) {
        file_put_data(ef, CONST_BYTE_ARRAY((const uint8_t *)st, sizeof(*st)));
        flash_commit();
    }
}

static void sd_load_state(sd_state_t *st) {
    file_t *ef = file_search(EF_SD_STATE);
    if (ef && file_has_data(ef) && file_get_size(ef) == sizeof(*st)) {
        memcpy(st, file_get_data(ef), sizeof(*st));
        if (st->magic == SD_STATE_MAGIC) {
            return;
        }
    }
    sd_default_state(st);
}

static void sd_factory_reset(void) {
    for (uint8_t i = 0; i < SD_MAX_KEYS; i++) {
        file_t *ef = file_search((uint16_t)(EF_SD_CERT_BASE + i));
        if (ef && file_has_data(ef)) {
            file_delete_no_commit(ef);
        }
    }
    sd_state_t st;
    sd_default_state(&st);
    sd_save_state(&st);
}

static int sd_find_key(const sd_state_t *st, uint8_t kid, uint8_t kvn) {
    for (int i = 0; i < SD_MAX_KEYS; i++) {
        if (st->keys[i].used && st->keys[i].kid == kid && st->keys[i].kvn == kvn) {
            return i;
        }
    }
    return -1;
}

static int cmd_sd_get_data(void) {
    sd_state_t st;
    sd_load_state(&st);
    uint16_t tag = (uint16_t)((P1(apdu) << 8) | P2(apdu));

    if (tag == SD_TAG_KEY_INFORMATION) {
        size_t off = 0;
        for (int i = 0; i < SD_MAX_KEYS; i++) {
            if (!st.keys[i].used) continue;
            res_APDU[off++] = 0xC0;
            res_APDU[off++] = 8;
            res_APDU[off++] = st.keys[i].kid;
            res_APDU[off++] = st.keys[i].kvn;
            if (!st.keys[i].is_ec) {
                res_APDU[off++] = SD_KEY_TYPE_AES; res_APDU[off++] = 16;
                res_APDU[off++] = SD_KEY_TYPE_AES; res_APDU[off++] = 16;
                res_APDU[off++] = SD_KEY_TYPE_AES; res_APDU[off++] = 16;
            }
            else {
                res_APDU[off++] = SD_KEY_TYPE_ECC_PUBLIC_KEY; res_APDU[off++] = st.keys[i].pub_len;
                res_APDU[off++] = SD_KEY_TYPE_ECC_PRIV_KEY;   res_APDU[off++] = st.keys[i].priv_len;
                res_APDU[off++] = SD_KEY_TYPE_ECC_KEY_PARAMS; res_APDU[off++] = 1;
            }
        }
        res_APDU_size = (uint16_t)off;
        return SW_OK();
    }
    if (tag == SD_TAG_CARD_RECOGNITION_DATA) {
        static const uint8_t crd[] = {
            0x73, 0x2E,
            0x06, 0x07, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x01,
            0x60, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x02, 0x02, 0x02,
            0x63, 0x09, 0x06, 0x07, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x03,
            0x64, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xFC, 0x6B, 0x04, 0x03, 0x70
        };
        memcpy(res_APDU, crd, sizeof(crd));
        res_APDU_size = sizeof(crd);
        return SW_OK();
    }
    if (tag == SD_TAG_CA_KLOC_IDENTIFIERS || tag == SD_TAG_CA_KLCC_IDENTIFIERS) {
        uint8_t want_klcc = (tag == SD_TAG_CA_KLCC_IDENTIFIERS) ? 1 : 0;
        size_t off = 0;
        for (int i = 0; i < SD_MAX_KEYS; i++) {
            if (st.keys[i].used && st.keys[i].has_ca_ski && st.keys[i].ca_klcc == want_klcc) {
                res_APDU[off++] = 0x42;
                res_APDU[off++] = st.keys[i].ca_ski_len;
                memcpy(res_APDU + off, st.keys[i].ca_ski, st.keys[i].ca_ski_len);
                off += st.keys[i].ca_ski_len;
                res_APDU[off++] = 0x83;
                res_APDU[off++] = 0x02;
                res_APDU[off++] = st.keys[i].kid;
                res_APDU[off++] = st.keys[i].kvn;
            }
        }
        if (off == 0) {
            return SW_REFERENCE_NOT_FOUND();
        }
        res_APDU_size = (uint16_t)off;
        return SW_OK();
    }
    if (tag == SD_TAG_CERTIFICATE_STORE) {
        /* Expect A6 04 83 02 <kid> <kvn> */
        if (apdu.nc < 6 || apdu.data[0] != 0xA6 || apdu.data[2] != 0x83 || apdu.data[3] != 0x02) {
            return SW_WRONG_DATA();
        }
        int idx = sd_find_key(&st, apdu.data[4], apdu.data[5]);
        if (idx < 0) return SW_REFERENCE_NOT_FOUND();
        file_t *ef = file_search((uint16_t)(EF_SD_CERT_BASE + idx));
        if (!ef || !file_has_data(ef)) {
            return SW_REFERENCE_NOT_FOUND();
        }
        uint16_t sz = (uint16_t)file_get_size(ef);
        memcpy(res_APDU, file_get_data(ef), sz);
        res_APDU_size = sz;
        return SW_OK();
    }
    return SW_REFERENCE_NOT_FOUND();
}

static int cmd_sd_store_data(void) {
    if (apdu.nc < 6 || apdu.data[0] != 0xA6) {
        return SW_WRONG_DATA();
    }
    sd_state_t st;
    sd_load_state(&st);
    size_t a6_len = apdu.data[1];
    if (2 + a6_len > apdu.nc) return SW_WRONG_DATA();

    uint8_t kid = 0, kvn = 0, klcc = 0;
    const uint8_t *ski = NULL;
    uint8_t ski_len = 0;
    size_t pos = 2;
    while (pos + 2 <= 2 + a6_len) {
        uint8_t t = apdu.data[pos++];
        uint8_t l = apdu.data[pos++];
        if (pos + l > 2 + a6_len) break;
        if (t == 0x80 && l == 1) klcc = apdu.data[pos];
        else if (t == 0x42 && l <= 32) { ski = apdu.data + pos; ski_len = l; }
        else if (t == 0x83 && l == 2) { kid = apdu.data[pos]; kvn = apdu.data[pos + 1]; }
        pos += l;
    }
    int idx = sd_find_key(&st, kid, kvn);
    if (idx < 0) return SW_REFERENCE_NOT_FOUND();

    if (ski) {
        st.keys[idx].has_ca_ski = 1;
        st.keys[idx].ca_klcc = klcc;
        st.keys[idx].ca_ski_len = ski_len;
        memcpy(st.keys[idx].ca_ski, ski, ski_len);
        sd_save_state(&st);
        return SW_OK();
    }
    size_t rem = apdu.nc - (2 + a6_len);
    const uint8_t *rest = apdu.data + 2 + a6_len;
    if (rem >= 3 && rest[0] == 0xBF && rest[1] == 0x21) {
        size_t p = 2;
        size_t clen = rest[p++];
        if (clen == 0x81) clen = rest[p++];
        else if (clen == 0x82) { clen = ((size_t)rest[p] << 8) | rest[p + 1]; p += 2; }
        if (p + clen <= rem) {
            uint16_t fid = (uint16_t)(EF_SD_CERT_BASE + idx);
            file_t *ef = file_search(fid);
            if (!ef) ef = file_new(fid);
            if (ef) {
                file_put_data(ef, CONST_BYTE_ARRAY(rest + p, (uint16_t)clen));
                flash_commit();
            }
        }
    }
    return SW_OK();
}

static int cmd_sd_generate_key(void) {
    uint8_t replace_kvn = P1(apdu);
    uint8_t kid = P2(apdu);
    if (apdu.nc < 4 || apdu.data[1] != SD_KEY_TYPE_ECC_KEY_PARAMS || apdu.data[2] != 0x01) {
        return SW_WRONG_DATA();
    }
    uint8_t kvn = apdu.data[0];
    uint8_t curve_id = apdu.data[3];
    uint8_t pub_len = 0, priv_len = 0;
    mbedtls_ecp_group_id grp_id = sd_curve_to_grp(curve_id, &pub_len, &priv_len);
    if (grp_id == MBEDTLS_ECP_DP_NONE) {
        return SW_WRONG_DATA();
    }

    sd_state_t st;
    sd_load_state(&st);
    int slot = -1;
    if (replace_kvn != 0) {
        slot = sd_find_key(&st, kid, replace_kvn);
    }
    if (slot < 0) {
        slot = sd_find_key(&st, kid, kvn);
    }
    if (slot < 0) {
        for (int i = 0; i < SD_MAX_KEYS; i++) {
            if (!st.keys[i].used) { slot = i; break; }
        }
    }
    if (slot < 0) return SW_FILE_FULL();

    mbedtls_ecp_keypair kp;
    mbedtls_ecp_keypair_init(&kp);
    uint8_t pt[140];
    size_t olen = 0;
    int ret = mbedtls_ecp_gen_key(grp_id, &kp, sd_rng, NULL);
    if (ret == 0) {
        ret = mbedtls_ecp_point_write_binary(&kp.grp, &kp.Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                             &olen, pt, sizeof(pt));
    }
    mbedtls_ecp_keypair_free(&kp);
    if (ret != 0) return SW_EXEC_ERROR();

    st.keys[slot].used = 1;
    st.keys[slot].kid = kid;
    st.keys[slot].kvn = kvn;
    st.keys[slot].is_ec = 1;
    st.keys[slot].curve_id = curve_id;
    st.keys[slot].pub_len = (uint8_t)olen;
    st.keys[slot].priv_len = priv_len;
    sd_save_state(&st);

    size_t off = 0;
    res_APDU[off++] = SD_KEY_TYPE_ECC_PUBLIC_KEY;
    if (olen < 0x80) {
        res_APDU[off++] = (uint8_t)olen;
    }
    else {
        res_APDU[off++] = 0x81;
        res_APDU[off++] = (uint8_t)olen;
    }
    memcpy(res_APDU + off, pt, olen);
    res_APDU_size = (uint16_t)(off + olen);
    return SW_OK();
}

static int cmd_sd_delete(void) {
    sd_state_t st;
    sd_load_state(&st);
    uint8_t kid = 0, kvn = 0;
    bool has_kid = false, has_kvn = false;
    size_t pos = 0;
    while (pos + 2 <= apdu.nc) {
        uint8_t t = apdu.data[pos++];
        uint8_t l = apdu.data[pos++];
        if (pos + l > apdu.nc) break;
        if (t == 0xD0 && l == 1) { kid = apdu.data[pos]; has_kid = true; }
        else if (t == 0xD2 && l == 1) { kvn = apdu.data[pos]; has_kvn = true; }
        pos += l;
    }
    if (!has_kid && !has_kvn) return SW_WRONG_DATA();
    for (int i = 0; i < SD_MAX_KEYS; i++) {
        if (st.keys[i].used &&
            (!has_kid || st.keys[i].kid == kid) &&
            (!has_kvn || st.keys[i].kvn == kvn)) {
            memset(&st.keys[i], 0, sizeof(st.keys[i]));
            file_t *ef = file_search((uint16_t)(EF_SD_CERT_BASE + i));
            if (ef && file_has_data(ef)) file_delete_no_commit(ef);
        }
    }
    sd_save_state(&st);
    return SW_OK();
}

static int sd_unload(void) {
    return PICOKEYS_OK;
}

static int sd_process_apdu(void) {
    switch (INS(apdu)) {
        case SD_INS_GET_DATA:     return cmd_sd_get_data();
        case SD_INS_STORE_DATA:   return cmd_sd_store_data();
        case SD_INS_GENERATE_KEY: return cmd_sd_generate_key();
        case SD_INS_DELETE:       return cmd_sd_delete();
        case SD_INS_INITIALIZE_UPDATE:
        case SD_INS_EXTERNAL_AUTHENTICATE:
        case SD_INS_INTERNAL_AUTHENTICATE:
        case SD_INS_PERFORM_SECURITY_OPERATION:
            /* When SecurityDomainSession.reset() probes/exhausts keys, reset state and return 0x6983 */
            sd_factory_reset();
            return SW_PIN_BLOCKED();
        default:
            return SW_INS_NOT_SUPPORTED();
    }
}

static const uint8_t sd_aid[] = {
    8,
    0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00
};

static int sd_select(app_t *a, uint8_t force) {
    (void)force;
    a->process_apdu = sd_process_apdu;
    a->unload = sd_unload;
    return PICOKEYS_OK;
}

INITIALIZER(sd_ctor) {
    register_app(sd_select, sd_aid);
}
