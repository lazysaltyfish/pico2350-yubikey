/* SPDX-License-Identifier: AGPL-3.0-only */
#include "picokeys.h"
#include "apdu.h"
#include <assert.h>
#include <stdio.h>
#define _SERIAL_H_
typedef struct { uint8_t id[8]; } picokey_serial_t;
picokey_serial_t pico_serial = {{1, 2, 3, 4, 5, 6, 7, 8}};
#define TIME_H
#include "../src/fido/openpgp.c"

struct apdu apdu;
static uint8_t header[4], response[2048];
static bool touch_allowed, rng_fail, read_fail, write_fail;
static unsigned touches;
static const uint8_t root_key[32] = {0x42};
const uint8_t *otp_key_1 = root_key;
typedef struct { file_t file; size_t len; uint8_t bytes[4096]; } test_file_t;
static test_file_t records[64];
static size_t num_records;

uint16_t set_res_sw(uint8_t sw1, uint8_t sw2) {
    apdu.sw = make_uint16_be(sw1, sw2);
    if (sw1 != 0x90 && sw1 != 0x61) apdu.rlen = 0;
    return apdu.sw;
}
void apdu_clear_response_buffer(void) {}
void apdu_set_response_buffer(const uint8_t *data, uint16_t len) {
    assert(len <= sizeof(response));
    memcpy(response, data, len);
    apdu.rlen = len;
}
int register_app(int (*select)(app_t *, uint8_t), const uint8_t *aid) {
    (void)select; (void)aid; return PICOKEYS_OK;
}
bool cap_supported(uint16_t cap) { return cap == CAP_OPENPGP; }
void derive_kbase(uint8_t key[32]) { memset(key, 0x42, 32); }
bool check_user_presence(void) { touches++; return touch_allowed; }
int wait_button_pressed_timeout(uint32_t timeout) { (void)timeout; return check_user_presence() ? 0 : 1; }
uint32_t button_timeout_seconds(void) { return 15; }
void flash_commit(void) {}
int random_fill_buffer(byte_array_t out) {
    static uint32_t state = 0x12345678;
    if (rng_fail) return PICOKEYS_EXEC_ERROR;
    for (size_t i = 0; i < out.len; i++) {
        state ^= state << 13; state ^= state >> 17; state ^= state << 5;
        out.data[i] = (uint8_t)state;
    }
    return PICOKEYS_OK;
}
int random_fill_iterator(void *ctx, unsigned char *out, size_t len) {
    (void)ctx; return random_fill_buffer(BYTE_ARRAY(out, len));
}
static test_file_t *record(const file_t *f) {
    for (size_t i = 0; i < num_records; i++) if (f == &records[i].file) return &records[i];
    assert(false); return NULL;
}
file_t *file_search(uint16_t fid) {
    for (size_t i = 0; i < num_records; i++) if (records[i].file.fid == fid) return &records[i].file;
    return NULL;
}
file_t *file_new(uint16_t fid) {
    file_t *f = file_search(fid);
    if (f) return f;
    assert(num_records < sizeof(records) / sizeof(records[0]));
    test_file_t *r = &records[num_records++];
    r->file.fid = fid; r->file.data = r->bytes;
    return &r->file;
}
uint32_t file_get_size(const file_t *f) { return (uint32_t)record(f)->len; }
bool file_has_data(const file_t *f) { return f && file_get_size(f) != 0; }
uint8_t *file_get_data(const file_t *f) { (void)f; assert(!"Storage must use bounded file_read_at"); return NULL; }
int file_read_at(const file_t *f, uint32_t offset, byte_array_t out) {
    if (read_fail || !f || offset > record(f)->len || out.len > record(f)->len - offset) return PICOKEYS_EXEC_ERROR;
    memcpy(out.data, record(f)->bytes + offset, out.len);
    return PICOKEYS_OK;
}
int file_put_data(file_t *f, const_byte_array_t in) {
    if (write_fail) return PICOKEYS_EXEC_ERROR;
    test_file_t *r = record(f);
    assert(in.len <= sizeof(r->bytes));
    memcpy(r->bytes, in.data, in.len); r->len = in.len;
    return PICOKEYS_OK;
}
int file_delete_no_commit(file_t *f) { record(f)->len = 0; return PICOKEYS_OK; }
int file_delete(file_t *f) { return file_delete_no_commit(f); }

static int command(uint8_t ins, uint8_t p1, uint8_t p2, const void *data, size_t len) {
    memset(response, 0xA5, sizeof(response));
    header[0] = 0; header[1] = ins; header[2] = p1; header[3] = p2;
    apdu = (struct apdu){.header=header, .data=(uint8_t *)data, .nc=len, .ne=256, .rdata=response};
    return openpgp_process_apdu();
}
static void reset_fixture(void) {
    openpgp_unload();
    memset(records, 0, sizeof(records)); num_records = 0;
    rng_fail = read_fail = write_fail = false;
    touch_allowed = true; touches = 0; otp_key_1 = root_key;
}
static void assert_zero(const void *buf, size_t len) {
    const uint8_t *p = buf;
    for (size_t i = 0; i < len; i++) assert(p[i] == 0);
}
static void test_state_and_envelope_integrity(void) {
    reset_fixture();
    opgp_state_t st;
    assert(opgp_load_state(&st));
    file_t *f = file_search(EF_OPENPGP_STATE);
    test_file_t *r = record(f);
    assert(r->len == sizeof(st) + APPLET_STORAGE_OVERHEAD);
    assert(memcmp(r->bytes + APPLET_STORAGE_OVERHEAD, &st, sizeof(st)) != 0);
    uint8_t pristine[sizeof(st) + APPLET_STORAGE_OVERHEAD];
    memcpy(pristine, r->bytes, sizeof(pristine));
    /* Every byte of version/FID/length, nonce, tag and ciphertext is covered. */
    for (size_t i = 0; i < sizeof(pristine); i++) {
        r->bytes[i] ^= 1;
        assert(!applet_storage_load(EF_OPENPGP_STATE, &st, sizeof(st)));
        assert_zero(&st, sizeof(st));
        r->bytes[i] ^= 1;
    }
    assert(command(OPGP_INS_VERIFY, 0, 0x83, "12345678", 8) == 0x9000);
    assert(pw3_verified);
    r->bytes[APPLET_STORAGE_OVERHEAD + offsetof(opgp_state_t, pw3_retries)] ^= 1;
    assert(command(OPGP_INS_GET_VERSION, 0, 0, NULL, 0) == 0x6400);
    assert(!pw3_verified);
    memcpy(r->bytes, pristine, sizeof(pristine));
    read_fail = true;
    assert(!opgp_load_state(&st));
    read_fail = false;
    static const uint8_t other_root[32] = {0x43};
    otp_key_1 = other_root;
    assert(!opgp_load_state(&st));
    otp_key_1 = NULL;
    assert(!opgp_load_state(&st));
    assert(!opgp_save_state(&st));
    otp_key_1 = root_key;
    rng_fail = true;
    assert(!opgp_save_state(&st));
    assert(memcmp(pristine, r->bytes, sizeof(pristine)) == 0);
    rng_fail = false;
    write_fail = true;
    assert(!opgp_save_state(&st));
    write_fail = false;
}

static void test_authenticated_keys_and_private_objects(void) {
    reset_fixture();
    assert(command(OPGP_INS_VERIFY, 0, 0x83, "12345678", 8) == 0x9000);
    static const uint8_t attr[] = {0x13,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07};
    assert(command(OPGP_INS_PUT_DATA, 0, 0xC1, attr, sizeof(attr)) == 0x9000);
    const uint8_t crt[] = {0xB6, 0};
    assert(command(OPGP_INS_GENERATE_ASYM, 0x80, 0, crt, sizeof(crt)) == 0x9000);
    assert(command(OPGP_INS_VERIFY, 0, 0x81, "123456", 6) == 0x9000);
    uint8_t digest[32]; memset(digest, 0x73, sizeof(digest));
    assert(command(OPGP_INS_PSO, 0x9E, 0x9A, digest, sizeof(digest)) == 0x9000);
    assert(apdu.rlen == 64);
    uint8_t signature[64]; memcpy(signature, response, sizeof(signature));
    opgp_key_hdr_t hdr;
    uint8_t pub[600], priv[1400];
    assert(opgp_load_key_record(OPGP_SLOT_SIG, &hdr, pub, sizeof(pub), priv, sizeof(priv)) == 0);
    mbedtls_ecp_keypair kp;
    mbedtls_ecp_keypair_init(&kp);
    assert(mbedtls_ecp_group_load(&kp.grp, MBEDTLS_ECP_DP_SECP256R1) == 0);
    assert(mbedtls_ecp_point_read_binary(&kp.grp, &kp.Q, pub, hdr.pub_len) == 0);
    mbedtls_mpi r_mpi, s_mpi;
    mbedtls_mpi_init(&r_mpi); mbedtls_mpi_init(&s_mpi);
    assert(mbedtls_mpi_read_binary(&r_mpi, signature, 32) == 0);
    assert(mbedtls_mpi_read_binary(&s_mpi, signature + 32, 32) == 0);
    assert(mbedtls_ecdsa_verify(&kp.grp, digest, sizeof(digest), &kp.Q, &r_mpi, &s_mpi) == 0);
    mbedtls_mpi_free(&r_mpi); mbedtls_mpi_free(&s_mpi); mbedtls_ecp_keypair_free(&kp);

    test_file_t *key = record(file_search(EF_OPENPGP_KEY_BASE));
    uint8_t saved[4096]; size_t saved_len = key->len;
    memcpy(saved, key->bytes, saved_len);
    for (size_t i = 0; i < saved_len; i++) {
        key->bytes[i] ^= 1;
        assert(opgp_load_key_record(OPGP_SLOT_SIG, &hdr, pub, sizeof(pub), NULL, 0) != 0);
        assert(opgp_load_key_record(OPGP_SLOT_SIG, &hdr, NULL, 0, NULL, 0) != 0);
        key->bytes[i] ^= 1;
    }
    file_t *other = file_new(EF_OPENPGP_KEY_BASE + OPGP_SLOT_AUT);
    assert(file_put_data(other, CONST_BYTE_ARRAY(saved, saved_len)) == PICOKEYS_OK);
    assert(opgp_load_key_record(OPGP_SLOT_AUT, &hdr, pub, sizeof(pub), priv, sizeof(priv)) != 0);

    const uint8_t secret[] = "private applet data";
    assert(command(OPGP_INS_PUT_DATA, 1, 4, secret, sizeof(secret)) == 0x9000);
    assert(command(OPGP_INS_GET_DATA, 1, 4, NULL, 0) == 0x9000);
    assert(apdu.rlen == sizeof(secret) && memcmp(response, secret, sizeof(secret)) == 0);
    test_file_t *obj = record(file_search(EF_OPENPGP_PRIV_DO_BASE + 3));
    obj->bytes[obj->len - 1] ^= 1;
    assert(command(OPGP_INS_GET_DATA, 1, 4, NULL, 0) == 0x6400 && apdu.rlen == 0);
}

static void test_reject_legacy_and_explicit_recovery(void) {
    reset_fixture();
    opgp_state_t legacy;
    opgp_default_state(&legacy);
    legacy.pw1_retries = 0;
    assert(file_put_data(file_new(EF_OPENPGP_STATE), CONST_BYTE_ARRAY((uint8_t *)&legacy, sizeof(legacy))) == PICOKEYS_OK);
    const uint8_t material[] = {1, 2, 3};
    for (size_t i = 0; i < OPGP_NUM_SLOTS; i++) {
        assert(file_put_data(file_new(EF_OPENPGP_KEY_BASE + i), CONST_BYTE_ARRAY(material, sizeof(material))) == PICOKEYS_OK);
        assert(file_put_data(file_new(EF_OPENPGP_CERT_BASE + i), CONST_BYTE_ARRAY(material, sizeof(material))) == PICOKEYS_OK);
        assert(file_put_data(file_new(EF_OPENPGP_PRIV_DO_BASE + i), CONST_BYTE_ARRAY(material, sizeof(material))) == PICOKEYS_OK);
    }
    assert(command(OPGP_INS_VERIFY, 0, 0x83, "12345678", 8) == 0x6400);
    touch_allowed = false;
    assert(command(OPGP_INS_ACTIVATE, 0xDE, 0xAD, NULL, 0) == 0x6982);
    assert(file_has_data(file_search(EF_OPENPGP_KEY_BASE)));
    touch_allowed = true;
    assert(command(OPGP_INS_ACTIVATE, 0xDE, 0xAD, NULL, 0) == 0x9000);
    assert(touches == 2);
    for (size_t i = 0; i < OPGP_NUM_SLOTS; i++) {
        assert(!file_has_data(file_search(EF_OPENPGP_KEY_BASE + i)));
        assert(!file_has_data(file_search(EF_OPENPGP_CERT_BASE + i)));
        assert(!file_has_data(file_search(EF_OPENPGP_PRIV_DO_BASE + i)));
    }
    assert(command(OPGP_INS_VERIFY, 0, 0x83, "12345678", 8) == 0x9000);
    file_delete_no_commit(file_search(EF_OPENPGP_STATE));
    assert(file_put_data(file_search(EF_OPENPGP_KEY_BASE), CONST_BYTE_ARRAY(material, sizeof(material))) == PICOKEYS_OK);
    assert(command(OPGP_INS_VERIFY, 0, 0x83, "12345678", 8) == 0x6400);
}

int main(void) {
    test_state_and_envelope_integrity();
    test_authenticated_keys_and_private_objects();
    test_reject_legacy_and_explicit_recovery();
    puts("openpgp_security_test: OK");
    return 0;
}
