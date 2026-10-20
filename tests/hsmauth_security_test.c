/*
 * Pico-YubiKey (RP2350) host regression tests.
 * Copyright (c) 2026 lazysaltyfish
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#include "picokeys.h"
#include "apdu.h"
#include <assert.h>
#include <stdio.h>

#define TIME_H /* No board clock or hardware services run in this fixture. */
#include "../src/fido/hsmauth.c"

struct apdu apdu;
static uint8_t header[4], response[2048];
static bool rng_fail, touch_allowed;
static bool ec_rng;
static unsigned touch_requests;
static file_t files[HSMAUTH_MAX_CREDS + 1];
static uint8_t file_bytes[HSMAUTH_MAX_CREDS + 1][sizeof(hsmauth_cred_t) + APPLET_STORAGE_OVERHEAD];
static size_t file_sizes[HSMAUTH_MAX_CREDS + 1];

uint16_t set_res_sw(uint8_t sw1, uint8_t sw2) {
    apdu.sw = make_uint16_be(sw1, sw2);
    if (sw1 != 0x90 && sw1 != 0x61) apdu.rlen = 0;
    return apdu.sw;
}
bool cap_supported(uint16_t cap) { return cap == CAP_HSMAUTH; }
int register_app(int (*select)(app_t *, uint8_t), const uint8_t *aid) {
    (void)select; (void)aid;
    return PICOKEYS_OK;
}
void apdu_clear_response_buffer(void) {}
void apdu_set_response_buffer(const uint8_t *data, uint16_t len) { (void)data; (void)len; }
static const uint8_t test_otp_root[32] = { 0x42 };
const uint8_t *otp_key_1 = test_otp_root;
void derive_kbase(uint8_t key[32]) { memset(key, 0x42, 32); }
int random_fill_buffer(byte_array_t out) {
    if (rng_fail) return PICOKEYS_EXEC_ERROR;
    if (ec_rng) {
        memset(out.data, 0, out.len);
        if (out.len) out.data[out.len - 1] = 3;
    }
    else for (size_t i = 0; i < out.len; i++) out.data[i] = (uint8_t)i;
    return PICOKEYS_OK;
}
bool check_user_presence(void) { touch_requests++; return touch_allowed; }
int wait_button_pressed_timeout(uint32_t seconds) { (void)seconds; return check_user_presence() ? 0 : 1; }
uint32_t button_timeout_seconds(void) { return 15; }
void flash_commit(void) {}
file_t *file_search(uint16_t fid) {
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) if (files[i].fid == fid) return &files[i];
    return NULL;
}
file_t *file_new(uint16_t fid) {
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
        if (!files[i].fid) {
            files[i].fid = fid;
            files[i].data = file_bytes[i];
            return &files[i];
        }
    }
    return NULL;
}
uint32_t file_get_size(const file_t *f) { return (uint32_t)file_sizes[f - files]; }
bool file_has_data(const file_t *f) { return f && file_get_size(f) != 0; }
uint8_t *file_get_data(const file_t *f) { return f->data; }
int file_put_data(file_t *f, const_byte_array_t bytes) {
    assert(bytes.len <= sizeof(file_bytes[0]));
    memcpy(f->data, bytes.data, bytes.len);
    file_sizes[f - files] = bytes.len;
    return PICOKEYS_OK;
}
int file_read_at(const file_t *f, uint32_t offset, byte_array_t data) {
    if (!f || offset > file_get_size(f) || data.len > file_get_size(f) - offset) return PICOKEYS_WRONG_LENGTH;
    memcpy(data.data, f->data + offset, data.len);
    return PICOKEYS_OK;
}
int file_delete_no_commit(file_t *f) { file_sizes[f - files] = 0; return PICOKEYS_OK; }
int file_delete(file_t *f) { return file_delete_no_commit(f); }

static void unhex(const char *hex, uint8_t *out) {
    while (*hex) {
        unsigned value;
        assert(sscanf(hex, "%2x", &value) == 1);
        *out++ = (uint8_t)value;
        hex += 2;
    }
}
static void assert_consumed(void) {
    const uint8_t *bytes = (const uint8_t *)&challenge;
    for (size_t i = 0; i < sizeof(challenge); i++) assert(bytes[i] == 0);
}
static int command(uint8_t ins, const uint8_t *data, size_t len) {
    memset(response, 0xA5, sizeof(response));
    header[0] = 0; header[1] = ins; header[2] = header[3] = 0;
    apdu = (struct apdu){ .header = header, .data = (uint8_t *)data, .nc = len,
                          .ne = 256, .rdata = response };
    int ret = hsmauth_process_apdu();
    if (ret != 0x9000) {
        assert(apdu.rlen == 0);
        for (size_t i = 0; i < sizeof(response); i++) assert(response[i] == 0xA5);
    }
    return ret;
}
static size_t field(uint8_t *out, uint8_t tag, const uint8_t *value, size_t len) {
    out[0] = tag;
    size_t h = len < 128 ? 2 : 3;
    out[1] = len < 128 ? (uint8_t)len : 0x81;
    if (h == 3) out[2] = (uint8_t)len;
    if (len) memcpy(out + h, value, len);
    return h + len;
}
static size_t request(uint8_t *out, uint8_t label, const uint8_t *ctx, size_t ctx_len,
                       const uint8_t *public_key, const uint8_t *proof, size_t proof_len,
                       const uint8_t pw[16]) {
    size_t n = field(out, HSMAUTH_TAG_LABEL, &label, 1);
    n += field(out + n, HSMAUTH_TAG_CONTEXT, ctx, ctx_len);
    if (public_key) n += field(out + n, HSMAUTH_TAG_PUBLIC_KEY, public_key, 65);
    if (proof) n += field(out + n, HSMAUTH_TAG_RESPONSE, proof, proof_len);
    n += field(out + n, HSMAUTH_TAG_CREDENTIAL_PASSWORD, pw, 16);
    return n;
}
static int calculate(uint8_t label, const uint8_t *ctx, size_t ctx_len,
                       const uint8_t *public_key, const uint8_t *proof, size_t proof_len) {
    uint8_t data[320], pw[16] = {0};
    size_t len = request(data, label, ctx, ctx_len, public_key, proof, proof_len, pw);
    int ret = command(HSMAUTH_INS_CALCULATE, data, len);
    assert_consumed();
    return ret;
}
static void begin(uint8_t label, bool asymmetric) {
    uint8_t data[21] = { HSMAUTH_TAG_LABEL, 1, label,
                         HSMAUTH_TAG_CREDENTIAL_PASSWORD, 16 };
    assert(command(HSMAUTH_INS_GET_CHALLENGE, data, asymmetric ? sizeof(data) : 3) == 0x9000);
    assert(challenge.valid);
    assert(apdu.rlen == (asymmetric ? 65 : 8));
}
static void reset_fixture(void) {
    hsmauth_unload();
    memset(files, 0, sizeof(files));
    memset(file_sizes, 0, sizeof(file_sizes));
    rng_fail = false;
    hsmauth_state_t initial_state;
    hsmauth_default_state(&initial_state);
    assert(hsmauth_save_state(&initial_state));
    rng_fail = ec_rng = false;
    touch_allowed = true;
    touch_requests = 0;
    hsmauth_cred_t cred = { .algo = HSMAUTH_ALG_AES128, .retries = 8, .label_len = 1, .label = {'a'} };
    for (size_t i = 0; i < sizeof(cred.secret); i++) cred.secret[i] = (uint8_t)i;
    assert(hsmauth_save_cred(0, &cred));
    cred.label[0] = 'b';
    assert(hsmauth_save_cred(1, &cred));
    cred.algo = HSMAUTH_ALG_ECP256;
    cred.label[0] = 'e';
    memset(cred.secret, 0, sizeof(cred.secret));
    cred.secret[31] = 1;
    assert(hsmauth_save_cred(2, &cred));
    cred.label[0] = 'f';
    assert(hsmauth_save_cred(3, &cred));
}

/* Known answers were independently generated using Python cryptography
 * AES-CMAC and X963KDF, with EC private scalars OCE=1, SD=2, eOCE=3, eSD=4.
 * Protocol transcript and derivation constants match Yubico's reference:
 * https://developers.yubico.com/python-yubihsm/API_Documentation/_modules/yubihsm/core.html
 * No production derivation helper is used to construct expected results. */
static void aes_vectors(uint8_t ctx[16], uint8_t proof[8], uint8_t expected[48]) {
    for (size_t i = 0; i < 16; i++) ctx[i] = (uint8_t)i;
    unhex("6e3e560916763faa", proof);
    unhex("3619112820d79ff81146e6862151f521e2b6c0d5dc55b27602375d7a983a2b3c35210536e8d79b6574fc6f8b6049630d", expected);
}
static void ec_vectors(uint8_t ctx[130], uint8_t public_key[65], uint8_t proof[16], uint8_t expected[48]) {
    unhex("047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1", public_key);
    unhex("045ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032", ctx);
    unhex("04e2534a3532d08fbba02dde659ee62bd0031fe2db785596ef509302446b030852e0f1575a4c633cc719dfee5fda862d764efc96c3f30ee0055c42c23f184ed8c6", ctx + 65);
    unhex("3fa25c630beb1daa34e46e9d33aa8073", proof);
    unhex("9a6ae9d5d00e275eb43544c8bcde4123f455e6044f7716cf94d984d9f9cf873600559a1f5c1e8d3b4f4fd8ffbc72ca54", expected);
}

static void test_symmetric_peer_proof(void) {
    uint8_t ctx[16], proof[8], expected[48];
    aes_vectors(ctx, proof, expected);
    reset_fixture();
    /* Legacy symmetric callers supply a host challenge themselves. A valid
     * card proof authenticates it but provides no firmware-enforced freshness;
     * requiring GET CHALLENGE would break those existing clients. */
    assert(calculate('a', ctx, 16, NULL, proof, 8) == 0x9000);
    assert(apdu.rlen == 48 && memcmp(response, expected, 48) == 0);
    begin('a', false);
    assert(memcmp(response, ctx, 8) == 0);
    assert(calculate('a', ctx, 16, NULL, proof, 8) == 0x9000);
    assert(apdu.rlen == 48 && memcmp(response, expected, 48) == 0);
    for (size_t i = 0; i < sizeof(proof); i++) {
        begin('a', false);
        proof[i] ^= 1;
        assert(calculate('a', ctx, 16, NULL, proof, 8) == 0x6982);
        proof[i] ^= 1;
    }
    begin('a', false);
    assert(calculate('b', ctx, 16, NULL, proof, 8) == 0x6985);
    begin('a', false);
    ctx[0] ^= 1;
    assert(calculate('a', ctx, 16, NULL, proof, 8) == 0x6700);
    ctx[0] ^= 1;
    begin('a', false);
    assert(calculate('a', ctx, 15, NULL, proof, 8) == 0x6700);
    begin('a', false);
    assert(calculate('a', ctx, 16, NULL, proof, 7) == 0x6700);
    begin('a', false);
    assert(calculate('a', ctx, 16, NULL, NULL, 0) == 0x6700);
}

static void test_asymmetric_receipt_and_binding(void) {
    uint8_t ctx[130], pk[65], proof[16], expected[48];
    ec_vectors(ctx, pk, proof, expected);
    reset_fixture();
    ec_rng = true;
    assert(calculate('e', ctx, sizeof(ctx), pk, proof, sizeof(proof)) == 0x6985);
    begin('e', true);
    assert(memcmp(response, ctx, 65) == 0); /* Generated public key, not injected state. */
    assert(calculate('e', ctx, sizeof(ctx), pk, proof, sizeof(proof)) == 0x9000);
    assert(apdu.rlen == 48 && memcmp(response, expected, 48) == 0);
    assert(calculate('e', ctx, sizeof(ctx), pk, proof, sizeof(proof)) == 0x6985);
    for (size_t i = 0; i < sizeof(proof); i++) {
        begin('e', true);
        proof[i] ^= 1;
        assert(calculate('e', ctx, sizeof(ctx), pk, proof, sizeof(proof)) == 0x6982);
        proof[i] ^= 1;
        assert(calculate('e', ctx, sizeof(ctx), pk, proof, sizeof(proof)) == 0x6985);
    }
    begin('e', true);
    assert(calculate('f', ctx, sizeof(ctx), pk, proof, sizeof(proof)) == 0x6985);
    begin('e', true);
    ctx[1] ^= 1;
    assert(calculate('e', ctx, sizeof(ctx), pk, proof, sizeof(proof)) == 0x6700);
    ctx[1] ^= 1;
    begin('e', true);
    ctx[66] ^= 1;
    assert(calculate('e', ctx, sizeof(ctx), pk, proof, sizeof(proof)) == 0x6982);
    ctx[66] ^= 1;
    begin('e', true);
    pk[1] ^= 1;
    assert(calculate('e', ctx, sizeof(ctx), pk, proof, sizeof(proof)) == 0x6982);
    pk[1] ^= 1;
    begin('e', true);
    assert(calculate('e', ctx, sizeof(ctx), NULL, proof, sizeof(proof)) == 0x6700);
    begin('e', true);
    assert(calculate('e', ctx, sizeof(ctx) - 1, pk, proof, sizeof(proof)) == 0x6700);

    /* Even an out-of-band replacement in the same slot cannot reuse an
     * exchange: binding includes the credential contents as well as its ID. */
    begin('e', true);
    hsmauth_cred_t changed;
    assert(hsmauth_load_cred(2, &changed));
    changed.secret[31] = 5;
    assert(hsmauth_save_cred(2, &changed));
    assert(calculate('e', ctx, sizeof(ctx), pk, proof, sizeof(proof)) == 0x6985);
}

static void test_failure_and_lifecycle_consumption(void) {
    uint8_t ctx[130], pk[65], proof[16], expected[48], pw[16] = {0}, data[400];
    ec_vectors(ctx, pk, proof, expected);
    reset_fixture();
    ec_rng = true;
    begin('e', true);
    pw[0] = 1;
    size_t n = request(data, 'e', ctx, sizeof(ctx), pk, proof, sizeof(proof), pw);
    assert(command(HSMAUTH_INS_CALCULATE, data, n) == 0x63C7);
    assert_consumed();
    pw[0] = 0;
    begin('e', true);
    n = request(data, 'e', ctx, sizeof(ctx), pk, proof, sizeof(proof), pw);
    data[n++] = HSMAUTH_TAG_LABEL; /* Truncated trailing TLV. */
    assert(command(HSMAUTH_INS_CALCULATE, data, n) == 0x6700);
    assert_consumed();
    begin('e', true);
    n = request(data, 'e', ctx, sizeof(ctx), pk, proof, sizeof(proof), pw);
    n += field(data + n, HSMAUTH_TAG_CONTEXT, ctx, sizeof(ctx));
    assert(command(HSMAUTH_INS_CALCULATE, data, n) == 0x6700);
    assert_consumed();
    begin('e', true);
    assert(command(HSMAUTH_INS_GET_CHALLENGE, NULL, 0) == 0x6700);
    assert_consumed();
    begin('e', true);
    assert(command(HSMAUTH_INS_DELETE, NULL, 0) == 0x6700);
    assert_consumed();
    begin('e', true);
    hsmauth_unload();
    assert_consumed();
    assert(calculate('e', ctx, sizeof(ctx), pk, proof, sizeof(proof)) == 0x6985);
    begin('e', true);
    app_t app = {0};
    assert(hsmauth_select(&app, 0) == PICOKEYS_OK);
    assert_consumed();
    begin('e', true);
    rng_fail = true;
    assert(command(HSMAUTH_INS_GET_CHALLENGE, (const uint8_t[]){HSMAUTH_TAG_LABEL, 1, 'a'}, 3) == 0x6400);
    assert_consumed();
    rng_fail = false;

    /* Touch rejection consumes the challenge and never exposes derived keys. */
    hsmauth_cred_t changed;
    assert(hsmauth_load_cred(2, &changed));
    changed.touch_required = 1;
    assert(hsmauth_save_cred(2, &changed));
    begin('e', true);
    touch_allowed = false;
    assert(calculate('e', ctx, sizeof(ctx), pk, proof, sizeof(proof)) == 0x6982);
    assert(touch_requests == 1);
}

static int reset_applet(void) {
    memset(response, 0xA5, sizeof(response));
    header[0] = 0; header[1] = HSMAUTH_INS_RESET; header[2] = 0xDE; header[3] = 0xAD;
    apdu = (struct apdu){.header = header, .rdata = response};
    return hsmauth_process_apdu();
}

static void test_authenticated_storage_and_recovery(void) {
    reset_fixture();
    hsmauth_state_t st;
    assert(hsmauth_load_state(&st));
    file_t *state_file = file_search(EF_HSMAUTH_STATE);
    size_t state_len = file_get_size(state_file);
    assert(state_len == sizeof(st) + APPLET_STORAGE_OVERHEAD);
    assert(memcmp(state_file->data + APPLET_STORAGE_OVERHEAD, &st, sizeof(st)) != 0);
    for (size_t i = 0; i < state_len; i++) {
        state_file->data[i] ^= 1;
        assert(!hsmauth_load_state(&st));
        assert(command(HSMAUTH_INS_GET_VERSION, NULL, 0) == 0x6400);
        state_file->data[i] ^= 1;
    }
    hsmauth_cred_t cred;
    assert(hsmauth_load_cred(0, &cred));
    file_t *cred_file = file_search(EF_HSMAUTH_CRED_BASE);
    size_t cred_len = file_get_size(cred_file);
    assert(cred_len == sizeof(cred) + APPLET_STORAGE_OVERHEAD);
    for (size_t i = 0; i < cred_len; i++) {
        cred_file->data[i] ^= 1;
        memset(&cred, 0xA5, sizeof(cred));
        assert(!hsmauth_load_cred(0, &cred));
        const uint8_t *bytes = (const uint8_t *)&cred;
        for (size_t j = 0; j < sizeof(cred); j++) assert(bytes[j] == 0);
        cred_file->data[i] ^= 1;
    }
    /* Ciphertext cannot move between credential IDs, even with a valid tag. */
    file_t *other = file_search(EF_HSMAUTH_CRED_BASE + 1);
    assert(file_put_data(other, CONST_BYTE_ARRAY(cred_file->data, cred_len)) == PICOKEYS_OK);
    assert(!hsmauth_load_cred(1, &cred));

    /* Legacy plaintext security state is unverifiable; no automatic default
     * or policy migration is allowed while any credential survives. */
    hsmauth_default_state(&st);
    st.mgm_key[0] = 0x77;
    assert(file_put_data(state_file, CONST_BYTE_ARRAY((const uint8_t *)&st, sizeof(st))) == PICOKEYS_OK);
    assert(command(HSMAUTH_INS_GET_MANAGEMENT_KEY_RETRIES, NULL, 0) == 0x6400);
    touch_allowed = false;
    assert(reset_applet() == 0x6982);
    assert(file_has_data(cred_file));
    touch_allowed = true;
    assert(reset_applet() == 0x9000);
    for (size_t i = 0; i < HSMAUTH_MAX_CREDS; i++) {
        assert(!file_has_data(file_search((uint16_t)(EF_HSMAUTH_CRED_BASE + i))));
    }
    assert(hsmauth_load_state(&st));
    assert(st.mgm_key[0] == 0 && st.mgm_retries == HSMAUTH_INITIAL_RETRIES);
    /* Removing state alone cannot recreate default management access. */
    assert(hsmauth_save_cred(0, &(hsmauth_cred_t){.algo=HSMAUTH_ALG_AES128, .label_len=1, .label={'a'}}));
    file_delete_no_commit(state_file);
    assert(command(HSMAUTH_INS_GET_VERSION, NULL, 0) == 0x6400);
}

int main(void) {
    test_symmetric_peer_proof();
    test_asymmetric_receipt_and_binding();
    test_failure_and_lifecycle_consumption();
    test_authenticated_storage_and_recovery();
    puts("hsmauth_security_test: OK");
    return 0;
}
