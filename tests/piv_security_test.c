/*
 * Pico-YubiKey (RP2350) host regression tests.
 * Copyright (c) 2026 lazysaltyfish
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Substitute only board services; exercise the production PIV dispatcher,
 * state storage, TLV parsing and mbedTLS block ciphers below. */
#define _SERIAL_H_
typedef struct { uint8_t id[8]; } picokey_serial_t;
picokey_serial_t pico_serial = { { 1, 2, 3, 4, 5, 6, 7, 8 } };
uint8_t pico_serial_hash[32];
#define TIME_H
static uint32_t board_millis(void) { return 100; }
#include "../src/fido/piv.c"
#include "mbedtls/gcm.h"

struct apdu apdu;
static uint8_t header[4];
static uint8_t request[2048];
static uint8_t response[2048];
static bool touch_allowed;
static unsigned touch_requests;
static bool rng_failed;
static uint8_t rng_block[16];
static uint32_t rng_state = 1;

typedef struct {
    file_t file;
    uint32_t size;
    uint8_t bytes[4096];
} test_file_t;
static test_file_t test_files[80];
static size_t test_file_count;

uint16_t set_res_sw(uint8_t sw1, uint8_t sw2) {
    apdu.sw = ((uint16_t)sw1 << 8) | sw2;
    return apdu.sw;
}

bool cap_supported(uint16_t cap) { return cap == CAP_PIV; }
int register_app(int (*select)(app_t *, uint8_t), const uint8_t *aid) {
    (void)select;
    (void)aid;
    return PICOKEYS_OK;
}
bool check_user_presence(void) {
    touch_requests++;
    return touch_allowed;
}
int random_fill_buffer(byte_array_t buffer) {
    if (rng_failed) {
        return PICOKEYS_EXEC_ERROR;
    }
    for (size_t i = 0; i < buffer.len; i++) {
        buffer.data[i] = rng_block[i % sizeof(rng_block)];
    }
    return PICOKEYS_OK;
}
int random_fill_iterator(void *ctx, unsigned char *out, size_t size) {
    (void)ctx;
    /* Repeatable entropy for test key generation, never firmware entropy. */
    for (size_t i = 0; i < size; i++) {
        rng_state ^= rng_state << 13;
        rng_state ^= rng_state >> 17;
        rng_state ^= rng_state << 5;
        out[i] = (uint8_t)rng_state;
    }
    return 0;
}
void derive_kbase(uint8_t key[32]) { memset(key, 0x42, 32); }

file_t *file_search(uint16_t fid) {
    for (size_t i = 0; i < test_file_count; i++) {
        if (test_files[i].file.fid == fid) {
            return &test_files[i].file;
        }
    }
    return NULL;
}
file_t *file_new(uint16_t fid) {
    file_t *existing = file_search(fid);
    if (existing) {
        return existing;
    }
    assert(test_file_count < sizeof(test_files) / sizeof(test_files[0]));
    test_file_t *entry = &test_files[test_file_count++];
    entry->file.fid = fid;
    entry->file.data = entry->bytes;
    return &entry->file;
}
static test_file_t *test_file(const file_t *file) {
    for (size_t i = 0; i < test_file_count; i++) {
        if (file == &test_files[i].file) {
            return &test_files[i];
        }
    }
    assert(!"invalid file handle");
    return NULL;
}
bool file_has_data(const file_t *file) { return file && test_file(file)->size > 0; }
uint32_t file_get_size(const file_t *file) { return test_file(file)->size; }
uint8_t *file_get_data(const file_t *file) { return test_file(file)->bytes; }
int file_put_data(file_t *file, const_byte_array_t bytes) {
    test_file_t *entry = test_file(file);
    assert(bytes.len <= sizeof(entry->bytes));
    memcpy(entry->bytes, bytes.data, bytes.len);
    entry->size = bytes.len;
    return PICOKEYS_OK;
}
int file_delete_no_commit(file_t *file) {
    test_file(file)->size = 0;
    return PICOKEYS_OK;
}
int file_delete(file_t *file) { return file_delete_no_commit(file); }
void flash_commit(void) {}

/* Stand in for the device's encrypted-record adapter with real AES-GCM.
 * This fixture tests PIV handlers, rather than the separately tested adapter. */
int encrypt_with_aad(const uint8_t key[32], const_byte_array_t in,
                     pin_kdf_version_t version, uint8_t *out) {
    assert(version == PIN_KDF_V2);
    memset(out, 0xA5, 12);
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (ret == 0) {
        ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, in.len,
                                       out, 12, NULL, 0, in.data, out + 12,
                                       16, out + 12 + in.len);
    }
    mbedtls_gcm_free(&gcm);
    return ret;
}
int decrypt_with_aad(const uint8_t key[32], const_byte_array_t in,
                     pin_kdf_version_t version, uint8_t *out) {
    assert(version == PIN_KDF_V2);
    assert(in.len >= 28);
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (ret == 0) {
        ret = mbedtls_gcm_auth_decrypt(&gcm, in.len - 28, in.data, 12,
                                      NULL, 0, in.data + in.len - 16, 16,
                                      in.data + 12, out);
    }
    mbedtls_gcm_free(&gcm);
    return ret;
}

static size_t unhex(const char *hex, uint8_t *out) {
    size_t n = strlen(hex) / 2;
    for (size_t i = 0; i < n; i++) {
        unsigned byte;
        assert(sscanf(hex + 2 * i, "%2x", &byte) == 1);
        out[i] = (uint8_t)byte;
    }
    return n;
}

static int command(uint8_t ins, uint8_t p1, uint8_t p2, const uint8_t *data, size_t len) {
    assert(len <= sizeof(request));
    if (len > 0) {
        memcpy(request, data, len);
    }
    header[0] = 0;
    header[1] = ins;
    header[2] = p1;
    header[3] = p2;
    apdu.header = header;
    apdu.data = request;
    apdu.nc = len;
    apdu.rdata = response;
    apdu.rlen = 0;
    return piv_process_apdu();
}

static int authenticate(uint8_t alg, const uint8_t *inner, size_t len) {
    uint8_t data[128];
    assert(len < 126);
    data[0] = TAG_DYN_AUTH;
    data[1] = len;
    memcpy(data + 2, inner, len);
    return command(INS_AUTHENTICATE, alg, PIV_SLOT_CARD_MGM, data, len + 2);
}

static void configure(uint8_t alg, const char *key_hex, uint8_t policy) {
    memset(test_files, 0, sizeof(test_files));
    test_file_count = 0;
    piv_unload();
    touch_allowed = true;
    touch_requests = 0;
    rng_failed = false;
    unhex("6bc1bee22e409f96e93d7e117393172a", rng_block);
    piv_state_t st;
    piv_state_init_defaults(&st);
    st.mgm_type = alg;
    st.mgm_len = unhex(key_hex, st.mgm_key);
    st.mgm_touch_policy = policy;
    assert(piv_save_state(&st) == PICOKEYS_OK);
}

static void assert_cleared(void) {
    assert(!piv_mgm_authenticated);
    assert(piv_mgm_auth_state == PIV_MGM_AUTH_IDLE);
    assert(piv_mgm_challenge_len == 0);
    assert(piv_mgm_challenge_alg == 0);
    for (size_t i = 0; i < sizeof(piv_mgm_challenge); i++) {
        assert(piv_mgm_challenge[i] == 0);
    }
    assert(command(INS_SET_MGMKEY, 0xFF, 0xFF, NULL, 0) == 0x6982);
}

static const char *aes128_key = "2b7e151628aed2a6abf7158809cf4f3c";
static const uint8_t start_mutual[] = { TAG_AUTH_WITNESS, 0 };
static const uint8_t start_single[] = { TAG_AUTH_CHALLENGE, 0 };

static void expect_cryptogram(uint8_t tag, const uint8_t *value, size_t len) {
    assert(apdu.rlen == len + 4);
    assert(response[0] == TAG_DYN_AUTH && response[1] == len + 2);
    assert(response[2] == tag && response[3] == len);
    assert(memcmp(response + 4, value, len) == 0);
}

static void finish_bytes(uint8_t *single, uint8_t *mutual, const uint8_t *encrypted, size_t len) {
    single[0] = TAG_AUTH_RESPONSE;
    single[1] = len;
    memcpy(single + 2, encrypted, len);
    mutual[0] = TAG_AUTH_WITNESS;
    mutual[1] = len;
    memcpy(mutual + 2, rng_block, len);
    mutual[len + 2] = TAG_AUTH_CHALLENGE;
    mutual[len + 3] = len;
    memcpy(mutual + len + 4, rng_block, len);
}

static void test_valid_handshakes(void) {
    /* NIST SP 800-38A AES-ECB vectors, plus a 3DES block independently
     * encrypted with the public mbedTLS primitive below. */
    const struct {
        uint8_t alg;
        const char *key;
        const char *encrypted;
    } vectors[] = {
        { PIV_ALG_AES128, "2b7e151628aed2a6abf7158809cf4f3c", "3ad77bb40d7a3660a89ecaf32466ef97" },
        { PIV_ALG_AES192, "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", "bd334f1d6e45f25ff712a214571fa5cc" },
        { PIV_ALG_AES256, "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "f3eed1bdb5d2a03c064b5a7e3db181f8" },
        { PIV_ALG_3DES, "010203040506070801020304050607080102030405060708", NULL },
    };
    for (size_t v = 0; v < sizeof(vectors) / sizeof(vectors[0]); v++) {
        uint8_t encrypted[16], single[18], mutual[36];
        size_t len = vectors[v].alg == PIV_ALG_3DES ? 8 : 16;
        configure(vectors[v].alg, vectors[v].key, PIV_TOUCH_POLICY_ALWAYS);
        if (vectors[v].encrypted) {
            unhex(vectors[v].encrypted, encrypted);
        }
        else {
            mbedtls_des3_context ctx;
            uint8_t key[24];
            unhex(vectors[v].key, key);
            mbedtls_des3_init(&ctx);
            assert(mbedtls_des3_set3key_enc(&ctx, key) == 0);
            assert(mbedtls_des3_crypt_ecb(&ctx, rng_block, encrypted) == 0);
            mbedtls_des3_free(&ctx);
        }
        finish_bytes(single, mutual, encrypted, len);
        assert(authenticate(vectors[v].alg, start_single, 2) == 0x9000);
        expect_cryptogram(TAG_AUTH_CHALLENGE, rng_block, len);
        assert(authenticate(vectors[v].alg, single, len + 2) == 0x9000);
        assert(piv_mgm_authenticated && touch_requests == 1);
        assert(authenticate(vectors[v].alg, single, len + 2) == 0x6982);
        assert_cleared();
        assert(authenticate(vectors[v].alg, start_mutual, 2) == 0x9000);
        expect_cryptogram(TAG_AUTH_WITNESS, encrypted, len);
        assert(authenticate(vectors[v].alg, mutual, 2 * len + 4) == 0x9000);
        expect_cryptogram(TAG_AUTH_RESPONSE, encrypted, len);
        assert(piv_mgm_authenticated && touch_requests == 2);
        assert(authenticate(vectors[v].alg, mutual, 2 * len + 4) == 0x6982);
        assert_cleared();
    }
}

static void test_mixing_and_touch(void) {
    uint8_t encrypted[16], single[18], mutual[36];
    unhex("3ad77bb40d7a3660a89ecaf32466ef97", encrypted);
    configure(PIV_ALG_AES128, aes128_key, PIV_TOUCH_POLICY_ALWAYS);
    finish_bytes(single, mutual, encrypted, 16);
    assert(authenticate(PIV_ALG_AES128, start_mutual, 2) == 0x9000);
    /* The exploit reflected the encrypted witness into the one-way response. */
    assert(authenticate(PIV_ALG_AES128, single, sizeof(single)) == 0x6982);
    assert_cleared();
    assert(authenticate(PIV_ALG_AES128, start_single, 2) == 0x9000);
    assert(authenticate(PIV_ALG_AES128, mutual, sizeof(mutual)) == 0x6982);
    assert_cleared();
    for (unsigned mode = 0; mode < 2; mode++) {
        const uint8_t *start = mode ? start_mutual : start_single;
        const uint8_t *finish = mode ? mutual : single;
        size_t finish_len = mode ? sizeof(mutual) : sizeof(single);
        assert(authenticate(PIV_ALG_AES128, start, 2) == 0x9000);
        touch_allowed = false;
        assert(authenticate(PIV_ALG_AES128, finish, finish_len) == 0x6982);
        assert_cleared();
        touch_allowed = true;
        assert(authenticate(PIV_ALG_AES128, finish, finish_len) == 0x6982);
        assert_cleared();
    }
    assert(touch_requests == 2);
}

static void test_invalid_attempts_consume_challenge(void) {
    static const uint8_t malformed[][10] = {
        { 0x7C, 4, 0x80, 0, 0x80, 0 }, /* Duplicate. */
        { 0x7C, 4, 0x80, 0, 0x82, 0 }, /* Mixed fields. */
        { 0x7C, 4, 0x80, 0, 0x83, 0 }, /* Unknown field. */
        { 0x7C, 3, 0x80, 0, 0x81 },    /* Lengthless marker. */
        { 0x7C, 4, 0x80, 0, 0x81, 1 }, /* Truncated value. */
        { 0x7C, 4, 0x80, 0, 0x81, 0x81 }, /* Truncated long length. */
        { 0x7C, 2, 0x80, 0, 0x7C, 0 }, /* Extra outer TLV. */
        { 0x7C, 0x80, 0x80, 0 },       /* Indefinite length. */
        { 0x80, 0 },                   /* Missing dynamic-auth template. */
        { 0x7C, 3, 0x82, 1, 0 },       /* Wrong response size. */
    };
    const size_t sizes[] = { 6, 6, 6, 5, 6, 6, 6, 4, 2, 5 };
    uint8_t encrypted[16], single[18], mutual[36];
    unhex("3ad77bb40d7a3660a89ecaf32466ef97", encrypted);
    configure(PIV_ALG_AES128, aes128_key, PIV_TOUCH_POLICY_NEVER);
    finish_bytes(single, mutual, encrypted, 16);
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        assert(authenticate(PIV_ALG_AES128, start_single, 2) == 0x9000);
        assert(command(INS_AUTHENTICATE, PIV_ALG_AES128, PIV_SLOT_CARD_MGM,
                       malformed[i], sizes[i]) == 0x6700);
        assert_cleared();
        assert(authenticate(PIV_ALG_AES128, single, sizeof(single)) == 0x6982);
        assert_cleared();
    }
    assert(authenticate(PIV_ALG_AES128, start_single, 2) == 0x9000);
    assert(authenticate(PIV_ALG_AES256, single, sizeof(single)) == 0x6A86);
    assert_cleared();
    assert(authenticate(PIV_ALG_AES128, single, sizeof(single)) == 0x6982);
    assert_cleared();
    assert(authenticate(PIV_ALG_AES128, start_mutual, 2) == 0x9000);
    mutual[2] ^= 1;
    assert(authenticate(PIV_ALG_AES128, mutual, sizeof(mutual)) == 0x6982);
    assert_cleared();
    mutual[2] ^= 1;
    assert(authenticate(PIV_ALG_AES128, mutual, sizeof(mutual)) == 0x6982);
    assert_cleared();
    rng_failed = true;
    assert(authenticate(PIV_ALG_AES128, start_mutual, 2) == 0x6400);
    assert_cleared();
    rng_failed = false;
    assert(authenticate(PIV_ALG_AES128, start_single, 2) == 0x9000);
    piv_unload();
    assert(authenticate(PIV_ALG_AES128, single, sizeof(single)) == 0x6982);
    assert_cleared();
}

int main(void) {
    test_valid_handshakes();
    test_mixing_and_touch();
    test_invalid_attempts_consume_challenge();
    puts("PIV security regression tests passed");
    return 0;
}
