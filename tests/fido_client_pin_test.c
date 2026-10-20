/* SPDX-License-Identifier: AGPL-3.0-only */
// Exercise the production ClientPIN parser and crypto entry points on the host.
#include <assert.h>
#include <stdio.h>
#include <stdint.h>

uint32_t board_millis(void);
#include "../src/fido/cbor_client_pin.c"
#include "mbedtls/aes.h"

pinUvAuthToken_t paut;
persistentPinUvAuthToken_t ppaut;
struct apdu apdu;
uint32_t user_present_time_limit;
uint8_t session_pin[32];
bool keydev_unlocked;
static uint8_t pin_record[35], token[32], persistent_token[32], key_record[61];
static file_t pin_file, token_file, persistent_file, key_file;
file_t *ef_pin = &pin_file, *ef_authtoken = &token_file, *ef_keydev = &key_file;
static size_t pin_writes, aes_calls;
static uint8_t peer_x[32], peer_y[32];
static mbedtls_ecp_keypair peer;

uint32_t board_millis(void) { return 123; }
void fido_object_authorization_session_invalidate(void) {}
void flash_commit(void) {}
bool flash_commit_sync(uint32_t timeout_ms) { (void)timeout_ms; return true; }
uint8_t *file_get_data(const file_t *f) { return f ? f->data : NULL; }
bool file_has_data(const file_t *f) { return f && f->data; }
uint32_t file_get_size(const file_t *f) {
    if (f == &pin_file) return sizeof(pin_record);
    if (f == &key_file) return sizeof(key_record);
    return f ? 32 : 0;
}
file_t *file_search_by_fid(uint16_t fid, const file_t *parent, uint8_t mode) {
    (void)parent; (void)mode;
    if (fid == EF_PIN) return ef_pin;
    if (fid == EF_AUTHTOKEN) return &token_file;
    if (fid == EF_PAUTHTOKEN) return &persistent_file;
    return NULL;
}
int file_put_data(file_t *f, const_byte_array_t data) {
    assert(f && data.len <= file_get_size(f));
    if (f == &pin_file) pin_writes++;
    memcpy(f->data, data.data, data.len);
    return PICOKEYS_OK;
}
int file_read_at(const file_t *f, uint32_t offset, byte_array_t data) {
    if (!f || offset > file_get_size(f) || data.len > file_get_size(f) - offset) return PICOKEYS_WRONG_LENGTH;
    memcpy(data.data, f->data + offset, data.len);
    return PICOKEYS_OK;
}
int random_fill_iterator(void *ctx, unsigned char *out, size_t len) {
    (void)ctx;
    static uint32_t state = 0x981237ab;
    while (len--) {
        state ^= state << 13; state ^= state >> 17; state ^= state << 5;
        *out++ = (uint8_t)state;
    }
    return 0;
}
int random_fill_buffer(byte_array_t data) { return random_fill_iterator(NULL, data.data, data.len); }
void pin_derive_verifier(const_byte_array_t pin, uint8_t out[32]) {
    assert(mbedtls_sha256(pin.data, pin.len, out, 0) == 0);
}
void pin_derive_session(const_byte_array_t pin, uint8_t out[32]) { pin_derive_verifier(pin, out); }
void double_hash_pin(const_byte_array_t pin, uint8_t out[32]) { pin_derive_verifier(pin, out); }
void hash_multi(const_byte_array_t pin, uint8_t out[32]) { pin_derive_verifier(pin, out); }
int load_keydev(uint8_t out[32]) { memset(out, 0x42, 32); return PICOKEYS_OK; }
int encrypt_keydev_f1(const uint8_t key[32]) { (void)key; return PICOKEYS_OK; }
int credential_migrate_rp_secure(void) { return PICOKEYS_OK; }
int encrypt_with_aad(const uint8_t key[32], const_byte_array_t in, pin_kdf_version_t version, uint8_t *out) {
    (void)key; (void)in; (void)version; (void)out;
    assert(!"Unexpected device-key migration in ClientPIN boundary tests");
    return PICOKEYS_EXEC_ERROR;
}
static int test_aes(int mode, const_byte_array_t key, const uint8_t *iv, byte_array_t data) {
    mbedtls_aes_context aes;
    uint8_t iv_copy[16] = { 0 };
    if (iv) memcpy(iv_copy, iv, sizeof(iv_copy));
    mbedtls_aes_init(&aes);
    int ret = mode == MBEDTLS_AES_ENCRYPT
        ? mbedtls_aes_setkey_enc(&aes, key.data, (unsigned int)key.len * 8)
        : mbedtls_aes_setkey_dec(&aes, key.data, (unsigned int)key.len * 8);
    if (ret == 0) ret = mbedtls_aes_crypt_cbc(&aes, mode, data.len, iv_copy, data.data, data.data);
    mbedtls_aes_free(&aes);
    return ret;
}
int aes_encrypt(const_byte_array_t key, const uint8_t *iv, int mode, byte_array_t data) {
    assert(mode == PICOKEYS_AES_MODE_CBC);
    return test_aes(MBEDTLS_AES_ENCRYPT, key, iv, data);
}
int aes_decrypt(const_byte_array_t key, const uint8_t *iv, int mode, byte_array_t data) {
    assert(mode == PICOKEYS_AES_MODE_CBC);
    aes_calls++;
    return test_aes(MBEDTLS_AES_DECRYPT, key, iv, data);
}
// Supply a fixed, valid peer key; key parsing itself is outside these tests.
CborError COSE_read_key(CborValue *v, int64_t *kty, int64_t *alg, int64_t *crv,
                        CborByteString *x, CborByteString *y) {
    *kty = 2; *alg = FIDO2_ALG_ECDH_ES_HKDF_256; *crv = FIDO2_CURVE_P256;
    *x = (CborByteString){ .data = peer_x, .len = sizeof(peer_x), .present = true, .nofree = true };
    *y = (CborByteString){ .data = peer_y, .len = sizeof(peer_y), .present = true, .nofree = true };
    return cbor_value_advance(v);
}
CborError COSE_key_shared(mbedtls_ecdh_context *key, CborEncoder *parent, CborEncoder *map) {
    (void)key; (void)parent; (void)map;
    return CborErrorUnknownType;
}

static uint8_t response[USB_BUFFER_SIZE];
static void reset_fixture(void) {
    memset(pin_record, 0, sizeof(pin_record));
    pin_record[0] = MAX_PIN_RETRIES; pin_record[1] = 4; pin_record[2] = 1;
    pin_file.data = pin_record; token_file.data = token;
    persistent_file.data = persistent_token; key_file.data = key_record;
    key_record[0] = 0x03;
    paut = (pinUvAuthToken_t){ .data = token, .len = sizeof(token) };
    ppaut = (persistentPinUvAuthToken_t){ .data = persistent_token, .len = sizeof(persistent_token) };
    memset(response, 0xa5, sizeof(response));
    ctap_resp = (CTAPHID_FRAME *)response;
    pin_writes = aes_calls = 0;
    needs_power_cycle = false; new_pin_mismatches = 0;
}
CTAPHID_FRAME *ctap_req, *ctap_resp;

static size_t encode_request(uint8_t *buf, size_t capacity, uint8_t protocol, uint8_t subcommand,
                              const uint8_t *hash, size_t hash_len) {
    CborEncoder enc, map, key;
    cbor_encoder_init(&enc, buf, capacity, 0);
    assert(cbor_encoder_create_map(&enc, &map, subcommand == 4 ? 6 : subcommand == 9 ? 5 : 4) == CborNoError);
    assert(cbor_encode_uint(&map, 1) == CborNoError);
    assert(cbor_encode_uint(&map, protocol) == CborNoError);
    assert(cbor_encode_uint(&map, 2) == CborNoError);
    assert(cbor_encode_uint(&map, subcommand) == CborNoError);
    assert(cbor_encode_uint(&map, 3) == CborNoError);
    assert(cbor_encoder_create_map(&map, &key, 0) == CborNoError);
    assert(cbor_encoder_close_container(&map, &key) == CborNoError);
    if (subcommand == 4) {
        uint8_t auth[32] = { 0 }, new_pin[80] = { 0 };
        assert(cbor_encode_uint(&map, 4) == CborNoError);
        assert(cbor_encode_byte_string(&map, auth, protocol == 1 ? 16 : 32) == CborNoError);
        assert(cbor_encode_uint(&map, 5) == CborNoError);
        assert(cbor_encode_byte_string(&map, new_pin, protocol == 1 ? 64 : 80) == CborNoError);
    }
    assert(cbor_encode_uint(&map, 6) == CborNoError);
    assert(cbor_encode_byte_string(&map, hash, hash_len) == CborNoError);
    if (subcommand == 9) {
        assert(cbor_encode_uint(&map, 9) == CborNoError);
        assert(cbor_encode_uint(&map, CTAP_PERMISSION_CM) == CborNoError);
    }
    assert(cbor_encoder_close_container(&enc, &map) == CborNoError);
    return cbor_encoder_get_buffer_size(&enc, buf);
}

static void test_malformed_pin_hashes(void) {
    static const size_t lengths[] = { 0, 1, 15, 16, 17, 31, 32, 33, 64, 65, 80, 1024 };
    uint8_t ciphertext[1024] = { 0 }, request[1200];
    for (uint8_t protocol = 1; protocol <= 2; protocol++) {
        for (uint8_t subcommand = 4; subcommand <= 9; subcommand++) {
            if (subcommand != 4 && subcommand != 5 && subcommand != 9) continue;
            for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
                if (lengths[i] == (protocol == 1 ? 16u : 32u)) continue;
                reset_fixture();
                size_t len = encode_request(request, sizeof(request), protocol, subcommand, ciphertext, lengths[i]);
                assert(cbor_client_pin(request, len) == CTAP1_ERR_INVALID_PARAMETER);
                assert(pin_writes == 0 && aes_calls == 0);
                assert(pin_record[0] == MAX_PIN_RETRIES && !paut.in_use);
                for (size_t j = 0; j < sizeof(response); j++) assert(response[j] == 0xa5);
            }
        }
    }
}

static void test_decrypt_bounds(void) {
    uint8_t key[64] = { 0 }, input[96] = { 0 }, guarded[96];
    static const size_t lengths[] = { 0, 1, 15, 16, 17, 31, 32, 33, 64, 65, 80, 96 };
    for (uint8_t protocol = 1; protocol <= 2; protocol++) {
        for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); i++) {
            size_t len = lengths[i], iv = protocol == 2 ? IV_SIZE : 0;
            if (len > iv && (len - iv) % IV_SIZE == 0 && len - iv <= 64) continue;
            memset(guarded, 0xa5, sizeof(guarded));
            aes_calls = 0;
            assert(decrypt(protocol, key, input, len, guarded + 16, 64) != 0);
            assert(aes_calls == 0);
            for (size_t j = 0; j < sizeof(guarded); j++) assert(guarded[j] == 0xa5);
        }
    }
    memset(guarded, 0xa5, sizeof(guarded));
    assert(decrypt(0, key, input, 16, guarded, sizeof(guarded)) != 0);
    assert(decrypt(1, NULL, input, 16, guarded, sizeof(guarded)) != 0);
    assert(decrypt(1, key, NULL, 16, guarded, sizeof(guarded)) != 0);
    assert(decrypt(1, key, input, 16, NULL, sizeof(guarded)) != 0);
    assert(decrypt(1, key, input, SIZE_MAX, guarded, sizeof(guarded)) != 0);
    assert(decrypt(2, key, input, SIZE_MAX, guarded, sizeof(guarded)) != 0);
}

static void test_valid_decryption(void) {
    uint8_t key[64], plain[64], cipher[80], output[80];
    for (size_t i = 0; i < sizeof(key); i++) key[i] = (uint8_t)i;
    for (size_t i = 0; i < sizeof(plain); i++) plain[i] = (uint8_t)(0x80 + i);
    for (uint8_t protocol = 1; protocol <= 2; protocol++) {
        for (size_t len = 16; len <= sizeof(plain); len += 16) {
            size_t iv = protocol == 2 ? IV_SIZE : 0;
            memset(cipher, 0x39, sizeof(cipher));
            memcpy(cipher + iv, plain, len);
            assert(test_aes(MBEDTLS_AES_ENCRYPT, CONST_BYTE_ARRAY(key + (protocol == 2 ? 32 : 0), 32),
                            protocol == 2 ? cipher : NULL, BYTE_ARRAY(cipher + iv, len)) == 0);
            memset(output, 0xa5, sizeof(output));
            assert(decrypt(protocol, key, cipher, len + iv, output, len) == 0);
            assert(memcmp(output, plain, len) == 0 && output[len] == 0xa5);
            assert(decrypt(protocol, key, cipher, len + iv, cipher, len) == 0);
            assert(memcmp(cipher, plain, len) == 0);
        }
    }
}

static void test_valid_pin_token(void) {
    uint8_t hash[32], shared[64], encrypted[32], request[128];
    assert(mbedtls_sha256((const uint8_t *)"1234", 4, hash, 0) == 0);
    mbedtls_mpi z;
    mbedtls_mpi_init(&z);
    assert(mbedtls_ecdh_compute_shared(&peer.grp, &z, &hkey.ctx.mbed_ecdh.Q, &peer.d, random_fill_iterator, NULL) == 0);
    for (uint8_t protocol = 1; protocol <= 2; protocol++) {
        for (uint8_t subcommand = 5; subcommand <= 9; subcommand += 4) {
            reset_fixture();
            pin_derive_verifier(CONST_BYTE_ARRAY(hash, 16), pin_record + 3);
            assert(kdf(protocol, &z, shared) == 0);
            assert(encrypt(protocol, shared, hash, 16, encrypted) == 0);
            size_t len = encode_request(request, sizeof(request), protocol, subcommand, encrypted, protocol == 1 ? 16 : 32);
            assert(cbor_client_pin(request, len) == 0);
            assert(paut.in_use && paut.user_verified && pin_record[0] == MAX_PIN_RETRIES);
            assert(paut.permissions == (subcommand == 5 ? (CTAP_PERMISSION_MC | CTAP_PERMISSION_GA) : CTAP_PERMISSION_CM));
        }
    }
    mbedtls_mpi_free(&z);
}

int main(void) {
    assert(regenerate() == 0);
    mbedtls_ecp_keypair_init(&peer);
    assert(mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, &peer, random_fill_iterator, NULL) == 0);
    assert(mbedtls_mpi_write_binary(&peer.Q.X, peer_x, sizeof(peer_x)) == 0);
    assert(mbedtls_mpi_write_binary(&peer.Q.Y, peer_y, sizeof(peer_y)) == 0);
    test_malformed_pin_hashes();
    test_decrypt_bounds();
    test_valid_decryption();
    test_valid_pin_token();
    mbedtls_ecp_keypair_free(&peer);
    mbedtls_ecdh_free(&hkey);
    puts("ClientPIN input bounds and protocol 1/2 regression tests passed");
    return 0;
}
