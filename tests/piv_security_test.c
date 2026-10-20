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
static uint16_t fail_write_fid;
static size_t io_events, fail_at_event;
static bool fault_tripped, timeout_persists;
static unsigned sync_events;
static const uint8_t test_otp_root[32] = { 0x42 };
const uint8_t *otp_key_1 = test_otp_root;

typedef struct {
    file_t file;
    uint32_t size;
    uint8_t bytes[4096];
} test_file_t;
static test_file_t test_files[80];
static size_t test_file_count;
static test_file_t durable_files[80];
static size_t durable_file_count;

static void persist_files(void) {
    memcpy(durable_files, test_files, sizeof(durable_files));
    durable_file_count = test_file_count;
}
static bool io_allowed(bool sync) {
    io_events++;
    if (fault_tripped || (fail_at_event != 0 && io_events == fail_at_event)) {
        if (sync && timeout_persists) persist_files();
        fault_tripped = true;
        return false;
    }
    return true;
}
static void reboot_fixture(void) {
    memcpy(test_files, durable_files, sizeof(test_files));
    test_file_count = durable_file_count;
    for (size_t i = 0; i < test_file_count; i++) test_files[i].file.data = test_files[i].bytes;
    piv_unload();
    piv_txn = (applet_txn_t)APPLET_TXN_INITIALIZER(EF_PIV_TXN);
    fail_write_fid = 0;
    io_events = fail_at_event = 0;
    fault_tripped = timeout_persists = false;
    sync_events = 0;
}

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
    if (!io_allowed(false)) return PICOKEYS_ERR_MEMORY_FATAL;
    if (fail_write_fid != 0 && file->fid == fail_write_fid) {
        return PICOKEYS_ERR_MEMORY_FATAL;
    }
    test_file_t *entry = test_file(file);
    assert(bytes.len <= sizeof(entry->bytes));
    memcpy(entry->bytes, bytes.data, bytes.len);
    entry->size = bytes.len;
    return PICOKEYS_OK;
}
int file_delete_no_commit(file_t *file) {
    if (!io_allowed(false)) return PICOKEYS_ERR_MEMORY_FATAL;
    test_file(file)->size = 0;
    return PICOKEYS_OK;
}
int file_delete(file_t *file) { return file_delete_no_commit(file); }
void flash_commit(void) {}
bool flash_commit_sync(uint32_t timeout_ms) {
    assert(timeout_ms > 0);
    sync_events++;
    if (!io_allowed(true)) return false;
    persist_files();
    return true;
}
int file_read_at(const file_t *file, uint32_t offset, byte_array_t bytes) {
    test_file_t *entry = test_file(file);
    if (offset > entry->size || bytes.len > entry->size - offset) return PICOKEYS_WRONG_LENGTH;
    memcpy(bytes.data, entry->bytes + offset, bytes.len);
    return PICOKEYS_OK;
}

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

static void reset_empty(void) {
    memset(test_files, 0, sizeof(test_files));
    memset(durable_files, 0, sizeof(durable_files));
    test_file_count = durable_file_count = 0;
    piv_unload();
    piv_txn = (applet_txn_t)APPLET_TXN_INITIALIZER(EF_PIV_TXN);
    io_events = fail_at_event = 0;
    fault_tripped = timeout_persists = false;
    sync_events = 0;
    touch_allowed = true;
    touch_requests = 0;
    rng_failed = false;
    unhex("6bc1bee22e409f96e93d7e117393172a", rng_block);
    fail_write_fid = 0;
}

static void configure(uint8_t alg, const char *key_hex, uint8_t policy) {
    reset_empty();
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

static void management_login(void) {
    uint8_t single[18] = { TAG_AUTH_RESPONSE, 16 };
    unhex("3ad77bb40d7a3660a89ecaf32466ef97", single + 2);
    assert(authenticate(PIV_ALG_AES128, start_single, sizeof(start_single)) == 0x9000);
    assert(authenticate(PIV_ALG_AES128, single, sizeof(single)) == 0x9000);
    assert(piv_mgm_authenticated);
}

static int generate_p256(uint8_t slot) {
    const uint8_t data[] = {
        0xAC, 9, TAG_GEN_ALGORITHM, 1, PIV_ALG_ECCP256,
        TAG_PIN_POLICY, 1, PIV_PIN_POLICY_NEVER,
        TAG_TOUCH_POLICY, 1, PIV_TOUCH_POLICY_NEVER,
    };
    return command(INS_GENERATE_ASYMMETRIC, 0, slot, data, sizeof(data));
}

static int private_operation(uint8_t slot, uint8_t alg, uint8_t tag,
                              const uint8_t *input, size_t input_len) {
    uint8_t data[1024], inner[1020];
    uint8_t *ip = piv_append_tlv(inner, tag, input, input_len);
    uint8_t *end = piv_append_tlv(data, TAG_DYN_AUTH, inner, (size_t)(ip - inner));
    return command(INS_AUTHENTICATE, alg, slot, data, (size_t)(end - data));
}

static void assert_f9_private_operations_denied(void) {
    uint8_t input[512] = { 1 };
    const uint8_t algorithms[] = {
        PIV_ALG_RSA1024, PIV_ALG_RSA2048, PIV_ALG_RSA3072, PIV_ALG_RSA4096,
        PIV_ALG_ECCP256, PIV_ALG_ECCP384, PIV_ALG_ED25519, PIV_ALG_X25519,
    };
    for (size_t i = 0; i < sizeof(algorithms); i++) {
        assert(private_operation(PIV_SLOT_ATTESTATION, algorithms[i],
                                 TAG_AUTH_CHALLENGE, input, sizeof(input)) == 0x6A86);
        assert(apdu.rlen == 0);
        assert(private_operation(PIV_SLOT_ATTESTATION, algorithms[i],
                                 TAG_AUTH_EXPONENTIATION, input, 65) == 0x6A86);
        assert(apdu.rlen == 0);
    }
}

static void test_attestation_role_isolation(void) {
    configure(PIV_ALG_AES128, aes128_key, PIV_TOUCH_POLICY_NEVER);
    uint16_t f9_fid = EF_PIV_KEY_BASE + piv_slot_index(PIV_SLOT_ATTESTATION);
    /* Reject before loading F9, including before its lazy initialization. */
    assert_f9_private_operations_denied();
    assert(file_search(f9_fid) == NULL);
    assert(generate_p256(PIV_SLOT_ATTESTATION) == 0x6982);
    management_login();
    assert(generate_p256(PIV_SLOT_AUTH) == 0x9000);
    assert(command(INS_ATTEST, PIV_SLOT_AUTH, 0, NULL, 0) == 0x9000);

    /* The dedicated ATTEST path still emits a certificate signed by F9. */
    mbedtls_x509_crt leaf, issuer;
    mbedtls_x509_crt_init(&leaf);
    mbedtls_x509_crt_init(&issuer);
    assert(mbedtls_x509_crt_parse_der(&leaf, response, apdu.rlen) == 0);
    uint16_t cert_fid = EF_PIV_OBJ_BASE + piv_object_index(0x5FFF01u);
    file_t *cert_file = file_search(cert_fid);
    assert(file_has_data(cert_file));
    tlv_ctx_t cert_object, cert_value;
    tlv_ctx_init(BYTE_ARRAY(file_get_data(cert_file), file_get_size(cert_file)), &cert_object);
    assert(tlv_find_tag(&cert_object, 0x70, &cert_value));
    assert(mbedtls_x509_crt_parse_der(&issuer, cert_value.data, cert_value.len) == 0);
    uint8_t cert_hash[64];
    assert(mbedtls_md(mbedtls_md_info_from_type(leaf.sig_md), leaf.tbs.p,
                      leaf.tbs.len, cert_hash) == 0);
    assert(mbedtls_pk_verify(&issuer.pk, leaf.sig_md, cert_hash, 0,
                             leaf.sig.p, leaf.sig.len) == 0);
    assert(command(INS_ATTEST, PIV_SLOT_ATTESTATION, 0, NULL, 0) == 0x6A86);

    /* Authentication must not grant access to the attestation signing key. */
    uint8_t pin[8] = { '1', '2', '3', '4', '5', '6', 0xFF, 0xFF };
    assert(command(INS_VERIFY, 0, PIV_PIN_P2, pin, sizeof(pin)) == 0x9000);
    assert(piv_pin_verified && piv_mgm_authenticated);
    assert_f9_private_operations_denied();

    /* Ordinary slots continue signing with the public key just attested. */
    uint8_t digest[32];
    memset(digest, 0x63, sizeof(digest));
    assert(private_operation(PIV_SLOT_AUTH, PIV_ALG_ECCP256,
                             TAG_AUTH_CHALLENGE, digest, sizeof(digest)) == 0x9000);
    tlv_ctx_t outer, dyn, signature;
    tlv_ctx_init(BYTE_ARRAY(response, apdu.rlen), &outer);
    assert(tlv_find_tag(&outer, TAG_DYN_AUTH, &dyn));
    assert(tlv_find_tag(&dyn, TAG_AUTH_RESPONSE, &signature));
    assert(mbedtls_pk_verify(&leaf.pk, MBEDTLS_MD_SHA256, digest, sizeof(digest),
                             signature.data, signature.len) == 0);

    /* Ordinary ECDH is likewise unaffected and agrees with the peer. */
    mbedtls_ecp_keypair peer;
    mbedtls_ecp_keypair_init(&peer);
    assert(mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, &peer,
                               random_fill_iterator, NULL) == 0);
    uint8_t public_point[65], expected_secret[32];
    size_t public_len;
    assert(mbedtls_ecp_point_write_binary(&peer.grp, &peer.Q,
                                          MBEDTLS_ECP_PF_UNCOMPRESSED,
                                          &public_len, public_point, sizeof(public_point)) == 0);
    assert(private_operation(PIV_SLOT_AUTH, PIV_ALG_ECCP256,
                             TAG_AUTH_EXPONENTIATION, public_point, public_len) == 0x9000);
    tlv_ctx_init(BYTE_ARRAY(response, apdu.rlen), &outer);
    assert(tlv_find_tag(&outer, TAG_DYN_AUTH, &dyn));
    assert(tlv_find_tag(&dyn, TAG_AUTH_RESPONSE, &signature));
    mbedtls_mpi shared;
    mbedtls_mpi_init(&shared);
    assert(mbedtls_ecdh_compute_shared(&peer.grp, &shared,
                                       &mbedtls_pk_ec(leaf.pk)->Q, &peer.d,
                                       random_fill_iterator, NULL) == 0);
    assert(mbedtls_mpi_write_binary(&shared, expected_secret, sizeof(expected_secret)) == 0);
    assert(signature.len == sizeof(expected_secret));
    assert(memcmp(signature.data, expected_secret, sizeof(expected_secret)) == 0);
    mbedtls_mpi_free(&shared);
    mbedtls_ecp_keypair_free(&peer);
    mbedtls_x509_crt_free(&leaf);
    mbedtls_x509_crt_free(&issuer);

    /* Prevent relabeling an F9 private key into a usable signing slot, or
     * promoting an ordinary generated key into an attestation issuer. */
    file_t *f9 = file_search(f9_fid);
    uint8_t f9_image[1024];
    size_t f9_size = file_get_size(f9);
    assert(f9_size <= sizeof(f9_image));
    memcpy(f9_image, file_get_data(f9), f9_size);
    assert(command(INS_MOVE_KEY, PIV_SLOT_RETIRED_FIRST, PIV_SLOT_ATTESTATION, NULL, 0) == 0x6A86);
    assert(command(INS_MOVE_KEY, PIV_SLOT_ATTESTATION, PIV_SLOT_AUTH, NULL, 0) == 0x6A86);
    assert(command(INS_MOVE_KEY, 0xFF, PIV_SLOT_ATTESTATION, NULL, 0) == 0x6A86);
    assert(file_get_size(f9) == f9_size);
    assert(memcmp(file_get_data(f9), f9_image, f9_size) == 0);
    assert(command(INS_MOVE_KEY, PIV_SLOT_RETIRED_FIRST, PIV_SLOT_AUTH, NULL, 0) == 0x9000);
    assert(command(INS_MOVE_KEY, PIV_SLOT_AUTH, PIV_SLOT_RETIRED_FIRST, NULL, 0) == 0x9000);

    /* Importing a normal private key does not grant generated-key attestation. */
    uint8_t imported[40] = { 0x06, 32 };
    imported[33] = 1;
    imported[34] = TAG_PIN_POLICY;
    imported[35] = 1;
    imported[36] = PIV_PIN_POLICY_NEVER;
    imported[37] = TAG_TOUCH_POLICY;
    imported[38] = 1;
    imported[39] = PIV_TOUCH_POLICY_NEVER;
    assert(command(INS_IMPORT_KEY, PIV_ALG_ECCP256, PIV_SLOT_CARD_AUTH,
                    imported, sizeof(imported)) == 0x9000);
    assert(command(INS_ATTEST, PIV_SLOT_CARD_AUTH, 0, NULL, 0) == 0x6985);

    /* Explicit management provisioning of F9 remains available. The issuer
     * certificate is separately provisioned by the administrator as before. */
    assert(generate_p256(PIV_SLOT_ATTESTATION) == 0x9000);
    assert(command(INS_IMPORT_KEY, PIV_ALG_ECCP256, PIV_SLOT_ATTESTATION,
                    imported, sizeof(imported)) == 0x9000);
    piv_key_header_t imported_header;
    assert(piv_load_slot_key(PIV_SLOT_ATTESTATION, &imported_header, NULL, NULL) == PICOKEYS_OK);
    assert(imported_header.origin == PIV_ORIGIN_IMPORTED);
    assert_f9_private_operations_denied();
    const uint8_t provision_cert[] = {
        TAG_OBJ_ID, 3, 0x5F, 0xFF, 0x01,
        TAG_OBJ_DATA, 9, 0x70, 2, 0x30, 0, 0x71, 1, 0, 0xFE, 0,
    };
    assert(command(INS_PUT_DATA, 0x3F, 0xFF, provision_cert, sizeof(provision_cert)) == 0x9000);
    cert_file = file_search(cert_fid);
    assert(file_get_size(cert_file) == sizeof(provision_cert) - 7);
    assert(memcmp(file_get_data(cert_file), provision_cert + 7, sizeof(provision_cert) - 7) == 0);
    piv_unload();
    assert(command(INS_IMPORT_KEY, PIV_ALG_ECCP256, PIV_SLOT_ATTESTATION,
                    imported, sizeof(imported)) == 0x6982);
    assert(command(INS_PUT_DATA, 0x3F, 0xFF, provision_cert, sizeof(provision_cert)) == 0x6982);
}

static void default_management_login(void) {
    assert(authenticate(PIV_ALG_3DES, start_single, sizeof(start_single)) == 0x9000);
    assert(apdu.rlen == 12);
    uint8_t finish[10] = { TAG_AUTH_RESPONSE, 8 };
    mbedtls_des3_context ctx;
    mbedtls_des3_init(&ctx);
    assert(mbedtls_des3_set3key_enc(&ctx, piv_default_mgm) == 0);
    assert(mbedtls_des3_crypt_ecb(&ctx, response + 4, finish + 2) == 0);
    mbedtls_des3_free(&ctx);
    assert(authenticate(PIV_ALG_3DES, finish, sizeof(finish)) == 0x9000);
    assert(piv_mgm_authenticated);
}

static void assert_no_cached_grants(void) {
    assert(!piv_pin_verified);
    assert(!piv_pin_verified_once_used);
    assert(!piv_mgm_authenticated);
    assert(piv_mgm_auth_state == PIV_MGM_AUTH_IDLE);
    assert(piv_mgm_challenge_alg == 0);
    assert(piv_mgm_challenge_len == 0);
    for (size_t i = 0; i < sizeof(piv_mgm_challenge); i++) {
        assert(piv_mgm_challenge[i] == 0);
    }
}

static const uint8_t test_piv_object[] = {
    TAG_OBJ_ID, 3, 0x5F, 0xFF, 0x01,
    TAG_OBJ_DATA, 1, 0x42,
};

static void test_corrupt_policy_fails_closed(void) {
    enum { TAMPER, TRUNCATE, OVERSIZE, BAD_MAGIC, BAD_POLICY, MISSING, MISSING_HANDLE, FAULT_COUNT };
    enum { NORMAL_KEY, ATTESTATION_KEY, OBJECT_ONLY, MATERIAL_COUNT };
    for (unsigned material = 0; material < MATERIAL_COUNT; material++) {
        for (unsigned fault = 0; fault < FAULT_COUNT; fault++) {
            configure(PIV_ALG_AES128, aes128_key, PIV_TOUCH_POLICY_NEVER);
            management_login();
            uint16_t protected_fid;
            if (material == OBJECT_ONLY) {
                assert(command(INS_PUT_DATA, 0x3F, 0xFF,
                                test_piv_object, sizeof(test_piv_object)) == 0x9000);
                protected_fid = EF_PIV_OBJ_BASE + piv_object_index(0x5FFF01u);
            }
            else {
                uint8_t slot = material == NORMAL_KEY ? PIV_SLOT_AUTH : PIV_SLOT_ATTESTATION;
                assert(generate_p256(slot) == 0x9000);
                protected_fid = EF_PIV_KEY_BASE + piv_slot_index(slot);
            }
            assert(command(INS_VERIFY, 0, PIV_PIN_P2, piv_default_pin, PIV_PIN_LEN) == 0x9000);
            assert(piv_pin_verified && piv_mgm_authenticated);
            file_t *protected_file = file_search(protected_fid);
            uint8_t original_material[4096];
            size_t material_size = file_get_size(protected_file);
            assert(material_size <= sizeof(original_material));
            memcpy(original_material, file_get_data(protected_file), material_size);

            test_file_t *state_file = test_file(file_search(EF_PIV_STATE));
            if (fault == TAMPER) {
                state_file->bytes[12] ^= 0x80;
            }
            else if (fault == TRUNCATE) {
                state_file->size--;
            }
            else if (fault == OVERSIZE) {
                state_file->bytes[state_file->size++] = 0;
            }
            else if (fault == BAD_MAGIC || fault == BAD_POLICY) {
                piv_state_t state;
                assert(piv_load_state(&state) == PICOKEYS_OK);
                if (fault == BAD_MAGIC) {
                    state.magic ^= 1;
                }
                else {
                    state.pin_retries = state.max_pin_retries + 1;
                }
                /* Authenticated malformed plaintext must fail as well. */
                assert(piv_save_state(&state) == PICOKEYS_OK);
                mbedtls_platform_zeroize(&state, sizeof(state));
            }
            else if (fault == MISSING) {
                state_file->size = 0;
            }
            else {
                state_file->file.fid = 0xFFFF; /* No policy handle at all. */
            }
            uint8_t damaged_policy[sizeof(piv_state_t) + PIV_SECURE_OVERHEAD + 1];
            size_t damaged_size = state_file->size;
            memcpy(damaged_policy, state_file->bytes, damaged_size);

            piv_state_t loaded;
            memset(&loaded, 0xCC, sizeof(loaded));
            assert(piv_load_state(&loaded) == PICOKEYS_EXEC_ERROR);
            const uint8_t *loaded_bytes = (const uint8_t *)&loaded;
            for (size_t i = 0; i < sizeof(loaded); i++) {
                assert(loaded_bytes[i] == 0);
            }
            /* A preexisting grant must not survive a policy-load failure. */
            uint8_t digest[32] = { 1 };
            assert(private_operation(PIV_SLOT_AUTH, PIV_ALG_ECCP256,
                                     TAG_AUTH_CHALLENGE, digest, sizeof(digest)) == 0x6400);
            assert_no_cached_grants();
            assert(command(INS_VERIFY, 0, PIV_PIN_P2, piv_default_pin, PIV_PIN_LEN) == 0x6400);
            assert(authenticate(PIV_ALG_3DES, start_single, sizeof(start_single)) == 0x6400);
            assert(generate_p256(PIV_SLOT_CARD_AUTH) == 0x6400);
            assert(command(INS_RESET, 0, 0, NULL, 0) == 0x6400);
            assert_no_cached_grants();
            assert(file_get_size(protected_file) == material_size);
            assert(memcmp(file_get_data(protected_file), original_material, material_size) == 0);
            assert(state_file->size == damaged_size);
            assert(memcmp(state_file->bytes, damaged_policy, damaged_size) == 0);
        }
    }
}

static void test_fresh_policy_initialization(void) {
    reset_empty();
    /* Match the static EF_PIV_STATE handle on a virgin firmware filesystem. */
    file_new(EF_PIV_STATE);
    assert(command(INS_GET_VERSION, 0, 0, NULL, 0) == 0x9000);
    assert(file_has_data(file_search(EF_PIV_STATE)));
    piv_state_t state, defaults;
    assert(piv_load_state(&state) == PICOKEYS_OK);
    piv_state_init_defaults(&defaults);
    assert(memcmp(&state, &defaults, sizeof(state)) == 0);
    assert(command(INS_VERIFY, 0, PIV_PIN_P2, piv_default_pin, PIV_PIN_LEN) == 0x9000);
    default_management_login();
    assert(generate_p256(PIV_SLOT_AUTH) == 0x9000);
    assert(file_has_data(file_search(EF_PIV_STATE)));

    /* Failure to initialize policy must not create a key or grant access. */
    reset_empty();
    fail_write_fid = EF_PIV_STATE;
    assert(command(INS_VERIFY, 0, PIV_PIN_P2, piv_default_pin, PIV_PIN_LEN) == 0x6581);
    assert_no_cached_grants();
    assert(generate_p256(PIV_SLOT_AUTH) == 0x6400);
    assert(!file_has_data(file_search(EF_PIV_KEY_BASE + piv_slot_index(PIV_SLOT_AUTH))));
    reboot_fixture();
    assert(command(INS_VERIFY, 0, PIV_PIN_P2, piv_default_pin, PIV_PIN_LEN) == 0x9000);
}

static void test_explicit_factory_reset(void) {
    configure(PIV_ALG_AES128, aes128_key, PIV_TOUCH_POLICY_NEVER);
    management_login();
    assert(generate_p256(PIV_SLOT_AUTH) == 0x9000);
    assert(generate_p256(PIV_SLOT_ATTESTATION) == 0x9000);
    assert(command(INS_PUT_DATA, 0x3F, 0xFF, test_piv_object, sizeof(test_piv_object)) == 0x9000);
    assert(command(INS_RESET, 0, 0, NULL, 0) == 0x6985);
    assert(file_has_data(file_search(EF_PIV_KEY_BASE)));
    uint8_t change[16];
    memcpy(change, piv_default_pin, PIV_PIN_LEN);
    memcpy(change + PIV_PIN_LEN, "654321\xFF\xFF", PIV_PIN_LEN);
    assert(command(INS_CHANGE_REFERENCE, 0, PIV_PIN_P2, change, sizeof(change)) == 0x9000);
    for (int retries = 2; retries >= 0; retries--) {
        assert(command(INS_VERIFY, 0, PIV_PIN_P2, piv_default_pin, PIV_PIN_LEN) == (0x63C0 | retries));
    }
    uint8_t reset_pin[16] = { 0 };
    memcpy(reset_pin + PIV_PIN_LEN, piv_default_pin, PIV_PIN_LEN);
    for (int retries = 2; retries >= 0; retries--) {
        assert(command(INS_RESET_RETRY, 0, PIV_PIN_P2, reset_pin, sizeof(reset_pin)) == (0x63C0 | retries));
    }
    assert(command(INS_RESET, 0, 0, NULL, 0) == 0x9000);
    assert_no_cached_grants();
    for (uint16_t i = 0; i < PIV_SLOT_COUNT; i++) {
        assert(!file_has_data(file_search((uint16_t)(EF_PIV_KEY_BASE + i))));
    }
    for (uint16_t i = 0; i < PIV_OBJECT_COUNT; i++) {
        assert(!file_has_data(file_search((uint16_t)(EF_PIV_OBJ_BASE + i))));
    }
    piv_state_t state, defaults;
    assert(piv_load_state(&state) == PICOKEYS_OK);
    piv_state_init_defaults(&defaults);
    assert(memcmp(&state, &defaults, sizeof(state)) == 0);
    assert(command(INS_VERIFY, 0, PIV_PIN_P2, piv_default_pin, PIV_PIN_LEN) == 0x9000);
    default_management_login();
    uint8_t digest[32] = { 1 };
    assert(private_operation(PIV_SLOT_AUTH, PIV_ALG_ECCP256,
                             TAG_AUTH_CHALLENGE, digest, sizeof(digest)) == 0x6A86);
}

enum durable_operation { DURABLE_MOVE, DURABLE_RESET, DURABLE_ATTEST, DURABLE_OPERATION_COUNT };

static void prepare_durable_operation(enum durable_operation operation) {
    configure(PIV_ALG_AES128, aes128_key, PIV_TOUCH_POLICY_NEVER);
    management_login();
    assert(generate_p256(PIV_SLOT_AUTH) == 0x9000);
    if (operation == DURABLE_RESET) {
        assert(generate_p256(PIV_SLOT_ATTESTATION) == 0x9000);
        assert(command(INS_PUT_DATA, 0x3F, 0xFF, test_piv_object, sizeof(test_piv_object)) == 0x9000);
        piv_state_t state;
        assert(piv_load_state(&state) == PICOKEYS_OK);
        state.pin_retries = state.puk_retries = 0;
        assert(piv_save_state(&state) == PICOKEYS_OK);
        mbedtls_platform_zeroize(&state, sizeof(state));
    }
    io_events = 0;
}

static int execute_durable_operation(enum durable_operation operation) {
    switch (operation) {
        case DURABLE_MOVE: return command(INS_MOVE_KEY, PIV_SLOT_RETIRED_FIRST, PIV_SLOT_AUTH, NULL, 0);
        case DURABLE_RESET: return command(INS_RESET, 0, 0, NULL, 0);
        case DURABLE_ATTEST: return command(INS_ATTEST, PIV_SLOT_AUTH, 0, NULL, 0);
        default: assert(!"unknown durable operation"); return 0;
    }
}

static void assert_all_material_erased(void) {
    for (uint16_t i = 0; i < PIV_SLOT_COUNT; i++) {
        assert(!file_has_data(file_search((uint16_t)(EF_PIV_KEY_BASE + i))));
    }
    for (uint16_t i = 0; i < PIV_OBJECT_COUNT; i++) {
        assert(!file_has_data(file_search((uint16_t)(EF_PIV_OBJ_BASE + i))));
    }
}

static void check_reboot_consistency(enum durable_operation operation) {
    reboot_fixture();
    if (!applet_txn_ready(&piv_txn)) {
        uint8_t digest[32] = { 1 };
        assert(private_operation(PIV_SLOT_AUTH, PIV_ALG_ECCP256,
                                 TAG_AUTH_CHALLENGE, digest, sizeof(digest)) == 0x6400);
        assert(command(INS_VERIFY, 0, PIV_PIN_P2, piv_default_pin, PIV_PIN_LEN) == 0x6400);
        assert(authenticate(PIV_ALG_3DES, start_single, sizeof(start_single)) == 0x6400);
        assert(command(INS_RESET, 0, 0, NULL, 0) == 0x6400);
        assert_no_cached_grants();
        /* Recovery is explicitly destructive and cannot skip actual presence. */
        touch_allowed = false;
        size_t writes_before = io_events;
        assert(command(INS_RESET, 0xDE, 0xAD, NULL, 0) == 0x6982);
        assert(io_events == writes_before);
        touch_allowed = true;
        assert(command(INS_RESET, 0xDE, 0xAD, NULL, 0) == 0x9000);
        assert_all_material_erased();
        reboot_fixture();
        assert(applet_txn_ready(&piv_txn));
        assert_all_material_erased();
        assert(command(INS_VERIFY, 0, PIV_PIN_P2, piv_default_pin, PIV_PIN_LEN) == 0x9000);
        default_management_login();
        return;
    }
    /* A clean marker permits only the complete old or complete new state. */
    piv_state_t state;
    assert(piv_load_state(&state) == PICOKEYS_OK);
    bool source = file_has_data(file_search(EF_PIV_KEY_BASE + piv_slot_index(PIV_SLOT_AUTH)));
    if (operation == DURABLE_MOVE) {
        bool target = file_has_data(file_search(EF_PIV_KEY_BASE + piv_slot_index(PIV_SLOT_RETIRED_FIRST)));
        assert(source != target);
    }
    else if (operation == DURABLE_RESET) {
        bool f9 = file_has_data(file_search(EF_PIV_KEY_BASE + piv_slot_index(PIV_SLOT_ATTESTATION)));
        bool object = file_has_data(file_search(EF_PIV_OBJ_BASE + piv_object_index(0x5FFF01u)));
        if (state.mgm_type == PIV_ALG_3DES) {
            assert_all_material_erased();
            assert(state.pin_retries == 3 && state.puk_retries == 3);
        }
        else {
            assert(source && f9 && object);
            assert(state.pin_retries == 0 && state.puk_retries == 0);
        }
    }
    else {
        bool f9 = file_has_data(file_search(EF_PIV_KEY_BASE + piv_slot_index(PIV_SLOT_ATTESTATION)));
        bool certificate = file_has_data(file_search(EF_PIV_OBJ_BASE + piv_object_index(0x5FFF01u)));
        assert(source && f9 == certificate);
    }
    mbedtls_platform_zeroize(&state, sizeof(state));
}

static void test_multi_record_fault_matrix(void) {
    for (enum durable_operation operation = DURABLE_MOVE; operation < DURABLE_OPERATION_COUNT; operation++) {
        prepare_durable_operation(operation);
        assert(execute_durable_operation(operation) == 0x9000);
        size_t operation_events = io_events;
        assert(operation_events >= 6);
        check_reboot_consistency(operation);
        for (unsigned ambiguous_timeout = 0; ambiguous_timeout < 2; ambiguous_timeout++) {
            for (size_t failure = 1; failure <= operation_events; failure++) {
                prepare_durable_operation(operation);
                fail_at_event = failure;
                timeout_persists = ambiguous_timeout != 0;
                assert(execute_durable_operation(operation) == 0x6581);
                assert(fault_tripped && piv_txn.faulted);
                assert_no_cached_grants();
                assert(command(INS_GET_VERSION, 0, 0, NULL, 0) == 0x6400);
                check_reboot_consistency(operation);
            }
        }
    }
}

enum state_operation {
    STATE_VERIFY, STATE_WRONG_PIN, STATE_CHANGE_PIN, STATE_CHANGE_PUK,
    STATE_RESET_PIN, STATE_RETRIES, STATE_MGM, STATE_IMPORT, STATE_PUT,
    STATE_DELETE_OBJECT, STATE_DELETE_KEY, STATE_OPERATION_COUNT
};

static void prepare_state_operation(void) {
    configure(PIV_ALG_AES128, aes128_key, PIV_TOUCH_POLICY_NEVER);
    management_login();
    assert(command(INS_VERIFY, 0, PIV_PIN_P2, piv_default_pin, PIV_PIN_LEN) == 0x9000);
    assert(generate_p256(PIV_SLOT_AUTH) == 0x9000);
    assert(command(INS_PUT_DATA, 0x3F, 0xFF, test_piv_object, sizeof(test_piv_object)) == 0x9000);
    io_events = 0;
}

static int execute_state_operation(enum state_operation operation) {
    uint8_t change[16];
    uint8_t mgm[19] = { PIV_ALG_AES128, PIV_SLOT_CARD_MGM, 16 };
    uint8_t imported[34] = { 0x06, 32 };
    imported[33] = 1;
    memcpy(change, operation == STATE_CHANGE_PUK || operation == STATE_RESET_PIN ? piv_default_puk : piv_default_pin, PIV_PIN_LEN);
    memcpy(change + PIV_PIN_LEN, "654321\xFF\xFF", PIV_PIN_LEN);
    switch (operation) {
        case STATE_VERIFY: return command(INS_VERIFY, 0, PIV_PIN_P2, piv_default_pin, PIV_PIN_LEN);
        case STATE_WRONG_PIN: return command(INS_VERIFY, 0, PIV_PIN_P2, change + PIV_PIN_LEN, PIV_PIN_LEN);
        case STATE_CHANGE_PIN: return command(INS_CHANGE_REFERENCE, 0, PIV_PIN_P2, change, sizeof(change));
        case STATE_CHANGE_PUK: return command(INS_CHANGE_REFERENCE, 0, PIV_PUK_P2, change, sizeof(change));
        case STATE_RESET_PIN: return command(INS_RESET_RETRY, 0, PIV_PIN_P2, change, sizeof(change));
        case STATE_RETRIES: return command(INS_SET_PIN_RETRIES, 4, 5, NULL, 0);
        case STATE_MGM: return command(INS_SET_MGMKEY, 0xFF, 0xFF, mgm, sizeof(mgm));
        case STATE_IMPORT: return command(INS_IMPORT_KEY, PIV_ALG_ECCP256, PIV_SLOT_CARD_AUTH, imported, sizeof(imported));
        case STATE_PUT: return command(INS_PUT_DATA, 0x3F, 0xFF, test_piv_object, sizeof(test_piv_object));
        case STATE_DELETE_OBJECT: {
            const uint8_t object_id[] = { TAG_OBJ_ID, 3, 0x5F, 0xFF, 0x01, TAG_OBJ_DATA, 0 };
            return command(INS_PUT_DATA, 0x3F, 0xFF, object_id, sizeof(object_id));
        }
        case STATE_DELETE_KEY: return command(INS_MOVE_KEY, 0xFF, PIV_SLOT_AUTH, NULL, 0);
        default: assert(!"unknown state operation"); return 0;
    }
}

static void test_single_record_fault_matrix(void) {
    for (enum state_operation operation = STATE_VERIFY; operation < STATE_OPERATION_COUNT; operation++) {
        prepare_state_operation();
        assert(execute_state_operation(operation) == (operation == STATE_WRONG_PIN ? 0x63C2 : 0x9000));
        size_t operation_events = io_events;
        assert(operation_events >= 2 && sync_events > 0);
        for (unsigned ambiguous_timeout = 0; ambiguous_timeout < 2; ambiguous_timeout++) {
            for (size_t failure = 1; failure <= operation_events; failure++) {
                prepare_state_operation();
                fail_at_event = failure;
                timeout_persists = ambiguous_timeout != 0;
                assert(execute_state_operation(operation) == 0x6581);
                assert(fault_tripped && piv_txn.faulted);
                assert_no_cached_grants();
                assert(command(INS_GET_VERSION, 0, 0, NULL, 0) == 0x6400);
                reboot_fixture();
                /* A single encrypted record may resolve to old or new data,
                 * but a failed save never returned a PIN/authentication grant. */
                piv_state_t state;
                assert(piv_load_state(&state) == PICOKEYS_OK);
                assert(state.pin_retries <= state.max_pin_retries);
                assert(state.puk_retries <= state.max_puk_retries);
                assert_no_cached_grants();
            }
        }
    }
}

static void test_shared_transaction_marker_authentication(void) {
    configure(PIV_ALG_AES128, aes128_key, PIV_TOUCH_POLICY_NEVER);
    applet_txn_t txn = APPLET_TXN_INITIALIZER(EF_OPENPGP_TXN);
    assert(applet_txn_ready(&txn));
    assert(applet_txn_begin(&txn));
    assert(applet_txn_ready(&txn));
    assert(!applet_txn_begin(&txn));
    applet_txn_t rebooted = APPLET_TXN_INITIALIZER(EF_OPENPGP_TXN);
    assert(!applet_txn_ready(&rebooted)); /* Durable DIRTY intent. */
    assert(applet_txn_commit(&txn));
    rebooted = (applet_txn_t)APPLET_TXN_INITIALIZER(EF_OPENPGP_TXN);
    assert(applet_txn_ready(&rebooted));
    assert(!applet_txn_commit(&rebooted));
    file_t *marker_file = file_search(EF_OPENPGP_TXN);
    uint8_t encoded[64];
    size_t encoded_len = file_get_size(marker_file);
    assert(encoded_len < sizeof(encoded));
    memcpy(encoded, file_get_data(marker_file), encoded_len);
    /* Copying another applet's clean marker must not authenticate. */
    file_t *other = file_new(EF_HSMAUTH_TXN);
    assert(file_put_data(other, CONST_BYTE_ARRAY(encoded, encoded_len)) == PICOKEYS_OK);
    applet_txn_t other_txn = APPLET_TXN_INITIALIZER(EF_HSMAUTH_TXN);
    assert(!applet_txn_ready(&other_txn));
    test_file(marker_file)->bytes[encoded_len - 1] ^= 1;
    rebooted = (applet_txn_t)APPLET_TXN_INITIALIZER(EF_OPENPGP_TXN);
    assert(!applet_txn_ready(&rebooted));
    /* The explicitly authorized recovery primitive reasserts DIRTY first. */
    assert(applet_txn_recover_begin(&rebooted));
    assert(applet_txn_commit(&rebooted));
    test_file(marker_file)->size--;
    rebooted = (applet_txn_t)APPLET_TXN_INITIALIZER(EF_OPENPGP_TXN);
    assert(!applet_txn_ready(&rebooted));
}

static void test_interrupted_recovery_remains_locked(void) {
    prepare_durable_operation(DURABLE_MOVE);
    assert(applet_txn_begin(&piv_txn));
    reboot_fixture();
    assert(!applet_txn_ready(&piv_txn));
    touch_allowed = true;
    io_events = 0;
    /* Fail the first recovery data deletion after durable intent. */
    fail_write_fid = EF_PIV_STATE;
    assert(command(INS_RESET, 0xDE, 0xAD, NULL, 0) == 0x6581);
    assert(piv_txn.faulted);
    reboot_fixture();
    assert(!applet_txn_ready(&piv_txn));
    assert(command(INS_VERIFY, 0, PIV_PIN_P2, piv_default_pin, PIV_PIN_LEN) == 0x6400);
    assert(command(INS_RESET, 0xDE, 0xAD, NULL, 0) == 0x9000);
    assert_all_material_erased();
}

int main(void) {
    test_valid_handshakes();
    test_mixing_and_touch();
    test_invalid_attempts_consume_challenge();
    test_attestation_role_isolation();
    test_corrupt_policy_fails_closed();
    test_fresh_policy_initialization();
    test_explicit_factory_reset();
    test_shared_transaction_marker_authentication();
    test_multi_record_fault_matrix();
    test_single_record_fault_matrix();
    test_interrupted_recovery_remains_locked();
    puts("PIV security regression tests passed");
    return 0;
}
