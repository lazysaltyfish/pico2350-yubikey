/* SPDX-License-Identifier: AGPL-3.0-only */
#include "support/counters/fixture.h"
#include "applet_txn.h"
#include "files.h"

#define cmds oath_cmds
#define challenge oath_challenge
#include "../src/fido/oath.c"
#undef challenge
#undef cmds
#include "../src/fido/otp.c"

static void reboot_all(void) {
    fixture_reboot();
    oath_unload();
    oath_txn = (applet_txn_t)APPLET_TXN_INITIALIZER(EF_OATH_TXN);
    oath_migration_done = false;
    validated = true;
    otp_pin_verified = false;
    otp_unload();
    otp_txn = (applet_txn_t)APPLET_TXN_INITIALIZER(EF_OTP_TXN);
    scanned = false;
    memset(session_counter, 0, sizeof(session_counter));
    config_seq = 1;
    fixture_request(0xa4, 0x04, 0x00, NULL, 0);
}

static void reset_all(void) {
    fixture_reset();
    reboot_all();
}

static int oath_cmd(uint8_t ins, uint8_t p1, uint8_t p2, const uint8_t *data, size_t len) {
    fixture_request(ins, p1, p2, data, len);
    return oath_process_apdu();
}

static int otp_cmd(uint8_t ins, uint8_t p1, uint8_t p2, const uint8_t *data, size_t len) {
    fixture_request(ins, p1, p2, data, len);
    return otp_process_apdu();
}

static void build_otp_slot_config(uint8_t buf[64], uint8_t tkt_flags, uint8_t cfg_flags) {
    memset(buf, 0, 64);
    otp_config_t *cfg = (otp_config_t *)buf;
    memset(cfg->fixed_data, 0x11, 6);
    cfg->fixed_size = 6;
    memset(cfg->uid, 0x22, UID_SIZE);
    memset(cfg->aes_key, 0x33, KEY_SIZE);
    cfg->tkt_flags = tkt_flags;
    cfg->cfg_flags = cfg_flags;
    uint16_t crc = calculate_crc(buf, otp_config_size - sizeof(uint16_t));
    cfg->crc = (uint16_t)~crc;
}

static uint16_t hook_expected_slot_fid;
static uint64_t hook_expected_hotp_imf;
static uint16_t hook_expected_yubico_counter;
static bool hook_check_hotp;

static void verify_durable_before_keyboard_hook(void) {
    uint8_t raw[128] = { 0 };
    size_t len = fixture_durable((uint16_t)(hook_expected_slot_fid + 0x2000u), raw, sizeof(raw));
    assert(len == OTP_SLOT_PLAIN_MAX);
    if (hook_check_hotp) {
        assert(get_uint64_be(raw + otp_config_size) == hook_expected_hotp_imf);
    }
    else {
        assert(get_uint16_be(raw + otp_config_size) == hook_expected_yubico_counter);
    }
}

static void test_oath_hotp_counter_and_overflow(void) {
    reset_all();
    app_t app = { 0 };
    assert(oath_select(&app, 1) == PICOKEYS_OK);

    const uint8_t put_hotp[] = {
        TAG_NAME, 4, 'h', 'o', 't', 'p',
        TAG_KEY, 22, ALG_HMAC_SHA1 | OATH_TYPE_HOTP, 6,
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        TAG_IMF, 4, 0, 0, 0, 5
    };
    assert(oath_cmd(INS_PUT, 0, 0, put_hotp, sizeof(put_hotp)) == 0x9000);

    const uint8_t calc_req[] = { TAG_NAME, 4, 'h', 'o', 't', 'p', TAG_CHALLENGE, 0 };
    assert(oath_cmd(INS_CALCULATE, 0, 1, calc_req, sizeof(calc_req)) == 0x9000);
    assert(apdu.rlen == 7);
    uint8_t first_code[7];
    memcpy(first_code, fixture_response, sizeof(first_code));

    /* If persisting the incremented HOTP counter fails, no OTP may be returned. */
    fixture_fail_sync = fixture_syncs + 2;
    assert(oath_cmd(INS_CALCULATE, 0, 1, calc_req, sizeof(calc_req)) == 0x6581);
    assert(apdu.rlen == 0);
    assert(oath_txn.faulted);

    /* Rebooting after the failed commit requires explicit recovery because
     * the transaction intent marker was already durably written. */
    reboot_all();
    assert(!oath_storage_ready());
    assert(oath_select(&app, 1) == PICOKEYS_ERR_MEMORY_FATAL);
    assert(app.process_apdu == oath_process_apdu);
    assert(oath_cmd(INS_LIST, 0, 0, NULL, 0) == 0x6581);
    fixture_touch = false;
    assert(oath_cmd(INS_RESET, 0xde, 0xad, NULL, 0) == 0x6982);
    fixture_touch = true;
    assert(oath_cmd(INS_RESET, 0xde, 0xad, NULL, 0) == 0x9000);
    reboot_all();
    assert(oath_select(&app, 1) == PICOKEYS_OK);

    /* Counter at UINT64_MAX must be rejected rather than wrapping to zero. */
    const uint8_t max_hotp[] = {
        TAG_NAME, 4, 'h', 'o', 't', 'p',
        TAG_KEY, 22, ALG_HMAC_SHA1 | OATH_TYPE_HOTP, 6,
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        TAG_IMF, 8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe
    };
    assert(oath_cmd(INS_PUT, 0, 0, max_hotp, sizeof(max_hotp)) == 0x9000);
    assert(oath_cmd(INS_CALCULATE, 0, 1, calc_req, sizeof(calc_req)) == 0x9000);
    assert(apdu.rlen == 7);
    assert(oath_cmd(INS_CALCULATE, 0, 1, calc_req, sizeof(calc_req)) == 0x6985);
    assert(apdu.rlen == 0);
}

static void test_oath_pin_and_set_code_persistence(void) {
    reset_all();
    app_t app = { 0 };
    assert(oath_select(&app, 1) == PICOKEYS_OK);

    const uint8_t set_pin[] = { TAG_PASSWORD, 6, '1', '2', '3', '4', '5', '6' };
    assert(oath_cmd(INS_SET_PIN, 0, 0, set_pin, sizeof(set_pin)) == 0x9000);

    /* If persisting the retry decrement fails, verification fails closed. */
    fixture_fail_write = fixture_writes + 2;
    assert(oath_cmd(INS_VERIFY_PIN, 0, 0, set_pin, sizeof(set_pin)) == 0x6581);
    assert(!validated && !otp_pin_verified);
    assert(oath_txn.faulted);

    /* Recover from interrupted PIN retry transaction. */
    reboot_all();
    assert(oath_cmd(INS_RESET, 0xde, 0xad, NULL, 0) == 0x9000);
    assert(oath_cmd(INS_SET_PIN, 0, 0, set_pin, sizeof(set_pin)) == 0x9000);

    /* Wrong PIN decrements durable counter before comparison. */
    const uint8_t wrong_pin[] = { TAG_PASSWORD, 6, '0', '0', '0', '0', '0', '0' };
    assert(oath_cmd(INS_VERIFY_PIN, 0, 0, wrong_pin, sizeof(wrong_pin)) == 0x6982);
    uint8_t pin_durable[64] = { 0 };
    assert(fixture_durable(EF_OTP_PIN, pin_durable, sizeof(pin_durable)) == OTP_PIN_V1_SIZE);
    assert(pin_durable[0] == MAX_OTP_COUNTER - 1);

    /* Correct PIN restores counter to MAX_OTP_COUNTER. */
    assert(oath_cmd(INS_VERIFY_PIN, 0, 0, set_pin, sizeof(set_pin)) == 0x9000);
    assert(validated && otp_pin_verified);
    assert(fixture_durable(EF_OTP_PIN, pin_durable, sizeof(pin_durable)) == OTP_PIN_V1_SIZE);
    assert(pin_durable[0] == MAX_OTP_COUNTER);
}

static void test_otp_core_isolation_and_button_persistence(void) {
    reset_all();
    app_t app = { 0 };

    /* Core 0 callbacks must never scan, migrate, or commit Flash. */
    fixture_core = 0;
    init_otp();
    assert(!scanned && fixture_writes == 0 && fixture_syncs == 0);
    assert(otp_select(&app, 1) == PICOKEYS_OK);
    assert(fixture_writes == 0 && fixture_syncs == 0);
    otp_hid_refresh_status();
    uint8_t snap[8] = { 0 };
    otp_hid_copy_status(snap);
    assert(snap[7] == 0x20);

    /* Core 1 initializes and persists slots. */
    fixture_core = 1;
    assert(otp_select(&app, 1) == PICOKEYS_OK);
    assert(scanned);

    /* Program Yubico OTP in Slot 1 and HOTP in Slot 2. */
    uint8_t slot1_cfg[64], slot2_cfg[64];
    build_otp_slot_config(slot1_cfg, 0, 0);
    build_otp_slot_config(slot2_cfg, OATH_HOTP, 0);
    assert(otp_cmd(INS_OTP, 0x01, 0x00, slot1_cfg, sizeof(slot1_cfg)) == 0x9000);
    assert(otp_cmd(INS_OTP, 0x03, 0x00, slot2_cfg, sizeof(slot2_cfg)) == 0x9000);

    /* Button press must durably persist the counter BEFORE emitting keyboard output. */
    fixture_keyboard_hook = verify_durable_before_keyboard_hook;
    hook_expected_slot_fid = EF_OTP_SLOT1;
    hook_expected_yubico_counter = 1;
    hook_check_hotp = false;
    assert(otp_hid_button(1) == 0);
    assert(fixture_keyboards == 1);

    hook_expected_slot_fid = EF_OTP_SLOT2;
    hook_expected_hotp_imf = (uint64_t)get_uint16_be(((otp_config_t *)slot2_cfg)->uid + 4) * 16u + 1u;
    hook_check_hotp = true;
    assert(otp_hid_button(2) == 0);
    assert(fixture_keyboards == 2);
    fixture_keyboard_hook = NULL;

    /* If counter persistence fails, no keyboard output may be emitted. */
    fixture_keyboards = 0;
    fixture_fail_sync = fixture_syncs + 2;
    assert(otp_hid_button(2) == 1);
    assert(fixture_keyboards == 0);
    assert(otp_txn.faulted);

    /* Reboot and recover from interrupted OTP transaction. */
    reboot_all();
    assert(!applet_txn_ready(&otp_txn));
    assert(otp_select(&app, 1) == PICOKEYS_ERR_MEMORY_FATAL);
    assert(app.process_apdu == otp_process_apdu);
    assert(otp_hid_button(1) == 1);
    fixture_touch = false;
    assert(otp_cmd(0x04, 0xde, 0xad, NULL, 0) == 0x6982);
    fixture_touch = true;
    assert(otp_cmd(0x04, 0xde, 0xad, NULL, 0) == 0x9000);
    reboot_all();
    assert(otp_select(&app, 1) == PICOKEYS_OK);

    /* Verify HOTP UINT64_MAX overflow and Yubico OTP 0x7fff overflow rejection. */
    assert(otp_cmd(INS_OTP, 0x01, 0x00, slot1_cfg, sizeof(slot1_cfg)) == 0x9000);
    assert(otp_cmd(INS_OTP, 0x03, 0x00, slot2_cfg, sizeof(slot2_cfg)) == 0x9000);
    uint8_t maxed[OTP_SLOT_PLAIN_MAX];
    memcpy(maxed, slot1_cfg, otp_config_size);
    put_uint16_be(0x7fff, maxed + otp_config_size);
    assert(otp_slot_store(EF_OTP_SLOT1, maxed, sizeof(maxed)) == PICOKEYS_OK);
    session_counter[0] = UINT8_MAX;
    fixture_keyboards = 0;
    assert(otp_hid_button(1) == 1);
    assert(fixture_keyboards == 0);

    memcpy(maxed, slot2_cfg, otp_config_size);
    put_uint64_be(UINT64_MAX, maxed + otp_config_size);
    assert(otp_slot_store(EF_OTP_SLOT2, maxed, sizeof(maxed)) == PICOKEYS_OK);
    assert(otp_hid_button(2) == 1);
    assert(fixture_keyboards == 0);

    /* Startup counter at 0x7fff must fault init_otp rather than wrapping. */
    reboot_all();
    assert(otp_select(&app, 1) == PICOKEYS_ERR_MEMORY_FATAL);
    assert(!scanned && otp_txn.faulted);
    assert(otp_cmd(0x04, 0xde, 0xad, NULL, 0) == 0x9000);
    reboot_all();
    assert(otp_select(&app, 1) == PICOKEYS_OK);

    /* Slot swap (p1 = 0x06) must be atomic under otp_txn. */
    assert(otp_cmd(INS_OTP, 0x01, 0x00, slot1_cfg, sizeof(slot1_cfg)) == 0x9000);
    assert(otp_cmd(INS_OTP, 0x03, 0x00, slot2_cfg, sizeof(slot2_cfg)) == 0x9000);
    fixture_fail_sync = fixture_syncs + 2;
    assert(otp_cmd(INS_OTP, 0x06, 0x00, NULL, 0) == 0x6581);
    assert(otp_txn.faulted);
    reboot_all();
    assert(!applet_txn_ready(&otp_txn));
    assert(otp_cmd(0x04, 0xde, 0xad, NULL, 0) == 0x9000);
    reboot_all();
    assert(otp_select(&app, 1) == PICOKEYS_OK);
}

int main(void) {
    test_oath_hotp_counter_and_overflow();
    test_oath_pin_and_set_code_persistence();
    test_otp_core_isolation_and_button_persistence();
    puts("oath_otp_persistence_test: OK");
    return 0;
}
