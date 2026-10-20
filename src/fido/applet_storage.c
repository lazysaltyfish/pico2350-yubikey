/*
 * Pico-YubiKey (RP2350)
 * Copyright (c) 2026 lazysaltyfish
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#include "picokeys.h"
#include "applet_storage.h"
#include "otp.h"
#include "random.h"
#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/platform_util.h"

#define HEADER_SIZE 8u
#define NONCE_OFFSET HEADER_SIZE
#define TAG_OFFSET (HEADER_SIZE + 12u)

static bool storage_key(uint16_t fid, uint8_t key[32]) {
    /* OTP startup publishes this pointer only after validating the root. Never
     * accept derive_kbase's public serial-number fallback for applet storage. */
    if (!otp_key_1) return false;
    uint8_t info[] = "PICO-APPLET-STORAGE-V1\0\0";
    info[sizeof(info) - 3] = (uint8_t)(fid >> 8);
    info[sizeof(info) - 2] = (uint8_t)fid;
    int ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), NULL, 0,
                           otp_key_1, 32, info, sizeof(info), key, 32);
    return ret == 0;
}

static void storage_header(uint8_t header[HEADER_SIZE], uint16_t fid, size_t len) {
    memcpy(header, "PAS\1", 4);
    put_uint16_be(fid, header + 4);
    put_uint16_be((uint16_t)len, header + 6);
}

bool applet_storage_load_variable(uint16_t fid, void *plain, size_t capacity, size_t *len) {
    if (len) *len = 0;
    if (!plain || !len || capacity > UINT16_MAX - APPLET_STORAGE_OVERHEAD) return false;
    mbedtls_platform_zeroize(plain, capacity);
    file_t *ef = file_search(fid);
    if (!ef || !file_has_data(ef)) return false;
    size_t raw_len = file_get_size(ef);
    if (raw_len < APPLET_STORAGE_OVERHEAD || raw_len - APPLET_STORAGE_OVERHEAD > capacity) return false;
    size_t plain_len = raw_len - APPLET_STORAGE_OVERHEAD;
    uint8_t *raw = malloc(raw_len);
    if (!raw) return false;
    uint8_t key[32] = {0}, header[HEADER_SIZE];
    storage_header(header, fid, plain_len);
    bool ok = false;
    if (file_read_at(ef, 0, BYTE_ARRAY(raw, raw_len)) != PICOKEYS_OK ||
        memcmp(raw, header, sizeof(header)) != 0 || !storage_key(fid, key)) goto done;
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (ret == 0) {
        ret = mbedtls_gcm_auth_decrypt(&gcm, plain_len, raw + NONCE_OFFSET, 12,
                                      raw, HEADER_SIZE, raw + TAG_OFFSET, 16,
                                      raw + APPLET_STORAGE_OVERHEAD, plain);
    }
    mbedtls_gcm_free(&gcm);
    ok = ret == 0;
done:
    mbedtls_platform_zeroize(key, sizeof(key));
    mbedtls_platform_zeroize(raw, raw_len);
    free(raw);
    if (ok) *len = plain_len;
    else mbedtls_platform_zeroize(plain, capacity);
    return ok;
}

bool applet_storage_load(uint16_t fid, void *plain, size_t expected_len) {
    size_t len;
    if (!applet_storage_load_variable(fid, plain, expected_len, &len)) return false;
    if (len == expected_len) return true;
    mbedtls_platform_zeroize(plain, expected_len);
    return false;
}

bool applet_storage_save(uint16_t fid, const void *plain, size_t len) {
    if (!plain || len > UINT16_MAX - APPLET_STORAGE_OVERHEAD) return false;
    uint8_t key[32] = {0};
    if (!storage_key(fid, key)) return false;
    size_t raw_len = len + APPLET_STORAGE_OVERHEAD;
    uint8_t *raw = malloc(raw_len);
    if (!raw) {
        mbedtls_platform_zeroize(key, sizeof(key));
        return false;
    }
    storage_header(raw, fid, len);
    bool ok = false;
    if (random_fill_buffer(BYTE_ARRAY(raw + NONCE_OFFSET, 12)) != PICOKEYS_OK) goto done;
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (ret == 0) {
        ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, len,
                                       raw + NONCE_OFFSET, 12, raw, HEADER_SIZE,
                                       plain, raw + APPLET_STORAGE_OVERHEAD,
                                       16, raw + TAG_OFFSET);
    }
    mbedtls_gcm_free(&gcm);
    file_t *ef = ret == 0 ? file_search(fid) : NULL;
    if (ret == 0 && !ef) ef = file_new(fid);
    ok = ret == 0 && ef && file_put_data(ef, CONST_BYTE_ARRAY(raw, raw_len)) == PICOKEYS_OK;
    if (ok) flash_commit();
done:
    mbedtls_platform_zeroize(key, sizeof(key));
    mbedtls_platform_zeroize(raw, raw_len);
    free(raw);
    return ok;
}
