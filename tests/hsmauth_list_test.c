/*
 * Pico-YubiKey (RP2350)
 * Copyright (c) 2026 lazysaltyfish
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Exercise the production HSM Auth command and APDU GET RESPONSE path with
 * encrypted credentials and a guarded, CCID-sized transmit buffer.
 */

#include "picokeys.h"
#include "apdu.h"
#include "usb.h"
#include <assert.h>
#include <stdio.h>

/* Neither the clock nor the card worker runs in this single-threaded test. */
#define TIME_H
struct queue {
    uint32_t items[16];
    unsigned head;
    unsigned tail;
    unsigned count;
};
static bool queue_try_add(queue_t *q, const void *value);
static void queue_remove_blocking(queue_t *q, void *value);
static void queue_add_blocking(queue_t *q, const void *value);

#include "../src/fido/hsmauth.c"
#include "../src/apdu.c"

app_t apps[16];
app_t *current_app;
uint8_t num_apps;
queue_t usb_to_card_q, card_to_usb_q;
volatile uint16_t finished_data_size;
uint8_t ITF_SC_CCID = 0, ITF_SC_WCID = 1;
uint8_t ITF_HID_CTAP = 2;

static file_t test_files[HSMAUTH_MAX_CREDS + 2];
static uint8_t file_bytes[HSMAUTH_MAX_CREDS + 2][sizeof(hsmauth_cred_t) + APPLET_STORAGE_OVERHEAD];
static size_t file_sizes[HSMAUTH_MAX_CREDS + 2];
static struct {
    uint8_t before[16];
    uint8_t usb[USB_BUFFER_SIZE];
    uint8_t after[16];
} transport;
static uint16_t tx_len;
static unsigned tx_count;
static bool inline_response_test;
static uint16_t tx_offset;

int register_app(int (*select)(app_t *, uint8_t), const uint8_t *aid) {
    assert(num_apps < sizeof(apps) / sizeof(apps[0]));
    apps[num_apps].select_aid = select;
    apps[num_apps].aid = aid;
    num_apps++;
    return 1;
}

int select_app(const_byte_array_t aid) {
    assert(aid.len == hsmauth_aid[0]);
    assert(memcmp(aid.data, hsmauth_aid + 1, aid.len) == 0);
    return current_app->select_aid(current_app, 0);
}

bool cap_supported(uint16_t cap) { return cap == CAP_HSMAUTH; }
static const uint8_t test_otp_root[32] = { 0x42 };
const uint8_t *otp_key_1 = test_otp_root;
void derive_kbase(uint8_t out[32]) { memset(out, 0x42, 32); }
int random_fill_buffer(byte_array_t out) {
    memset(out.data, 0x24, out.len);
    return PICOKEYS_OK;
}
int wait_button_pressed_timeout(uint32_t seconds) { (void)seconds; return 0; }
bool check_user_presence(void) { return true; }
uint32_t button_timeout_seconds(void) { return 30; }
void flash_commit(void) {}
bool flash_commit_sync(uint32_t timeout_ms) { (void)timeout_ms; return true; }
void timeout_stop(void) {}
void otp_hid_execute_pending(void) {}
void led_set_mode(uint32_t mode) { (void)mode; }
static unsigned core1_inits;
static void (*on_card_queue_add)(uint32_t event);
void card_init_core1(void) { core1_inits++; }
static bool queue_try_add(queue_t *q, const void *value) {
    assert(q->count < sizeof(q->items) / sizeof(q->items[0]));
    uint32_t v = *(const uint32_t *)value;
    q->items[q->tail] = v;
    q->tail = (q->tail + 1) % (sizeof(q->items) / sizeof(q->items[0]));
    q->count++;
    if (q == &card_to_usb_q && on_card_queue_add) {
        on_card_queue_add(v);
    }
    return true;
}
static void queue_remove_blocking(queue_t *q, void *value) {
    assert(q->count > 0);
    *(uint32_t *)value = q->items[q->head];
    q->head = (q->head + 1) % (sizeof(q->items) / sizeof(q->items[0]));
    q->count--;
}
static void queue_add_blocking(queue_t *q, const void *value) {
    assert(queue_try_add(q, value));
}

file_t *file_search(uint16_t fid) {
    for (size_t i = 0; i < sizeof(test_files) / sizeof(test_files[0]); i++) {
        if (test_files[i].fid == fid) return &test_files[i];
    }
    return NULL;
}

file_t *file_new(uint16_t fid) {
    for (size_t i = 0; i < sizeof(test_files) / sizeof(test_files[0]); i++) {
        if (test_files[i].fid == 0) {
            test_files[i].fid = fid;
            test_files[i].data = file_bytes[i];
            return &test_files[i];
        }
    }
    return NULL;
}

uint32_t file_get_size(const file_t *f) { return (uint32_t)file_sizes[f - test_files]; }
bool file_has_data(const file_t *f) { return f && file_get_size(f) != 0; }
uint8_t *file_get_data(const file_t *f) { return f->data; }
int file_put_data(file_t *f, const_byte_array_t data) {
    assert(data.len <= sizeof(file_bytes[0]));
    memcpy(f->data, data.data, data.len);
    file_sizes[f - test_files] = data.len;
    return PICOKEYS_OK;
}
int file_read_at(const file_t *f, uint32_t offset, byte_array_t data) {
    if (!f || offset > file_get_size(f) || data.len > file_get_size(f) - offset) return PICOKEYS_WRONG_LENGTH;
    memcpy(data.data, f->data + offset, data.len);
    return PICOKEYS_OK;
}
int file_delete_no_commit(file_t *f) { file_sizes[f - test_files] = 0; return PICOKEYS_OK; }
int file_delete(file_t *f) { return file_delete_no_commit(f); }

static void check_canaries(void) {
    for (size_t i = 0; i < sizeof(transport.before); i++) assert(transport.before[i] == 0xA5);
    for (size_t i = 0; i < sizeof(transport.after); i++) assert(transport.after[i] == 0xA5);
    for (size_t i = 0; i < 10; i++) assert(transport.usb[i] == 0xA5);
    assert(tx_len >= 2 && tx_len <= 258);
    for (size_t i = 10 + tx_len; i < sizeof(transport.usb); i++) assert(transport.usb[i] == 0xA5);
}

void driver_exec_finished_cont_ccid(uint8_t itf, uint16_t size, uint16_t offset) {
    assert(itf == ITF_SC_CCID);
    if (!inline_response_test) {
        assert(offset == 0);
        assert(apdu_limit_response(size, USB_BUFFER_SIZE - 10) == size);
    }
    tx_offset = offset;
    tx_len = size;
    tx_count++;
}

void driver_exec_finished_cont_hid(uint8_t itf, uint16_t size, uint16_t offset) {
    assert(itf == ITF_HID_CTAP);
    assert(offset == 7);
    tx_len = size;
    tx_count++;
}

static uint16_t exchange_on(uint8_t itf, const uint8_t *request, size_t len) {
    memset(&transport, 0xA5, sizeof(transport));
    apdu.rdata = transport.usb + 10;
    tx_len = 0;
    unsigned count = tx_count;
    if (apdu_process(itf, CONST_BYTE_ARRAY(request, len))) {
        process_apdu();
        apdu_finish();
        uint16_t size = apdu_next();
        if (itf == ITF_SC_CCID) driver_exec_finished_cont_ccid(itf, size, 0);
        else driver_exec_finished_cont_hid(itf, size, 7);
    }
    assert(tx_count == count + 1);
    check_canaries();
    return get_uint16_be(res_APDU + tx_len - 2);
}

static uint16_t exchange(const uint8_t *request, size_t len) {
    return exchange_on(ITF_SC_CCID, request, len);
}

static void reset_fixture(void) {
    apdu_clear_response_buffer();
    memset(&apdu, 0, sizeof(apdu));
    response_pending = false;
    memset(test_files, 0, sizeof(test_files));
    memset(file_sizes, 0, sizeof(file_sizes));
    hsmauth_state_t initial_state;
    hsmauth_default_state(&initial_state);
    assert(hsmauth_save_state(&initial_state));
    current_app = &apps[0];
    current_app->process_apdu = hsmauth_process_apdu;
    current_app->unload = hsmauth_unload;
}

static size_t seed_credentials(unsigned count, uint8_t label_len, uint8_t *expected) {
    size_t off = 0;
    for (unsigned i = 0; i < count; i++) {
        hsmauth_cred_t c;
        memset(&c, 0, sizeof(c));
        c.algo = HSMAUTH_ALG_AES128;
        c.label_len = label_len;
        c.touch_required = i % 2;
        c.retries = (uint8_t)(i % HSMAUTH_INITIAL_RETRIES + 1);
        memset(c.label, (int)('A' + i % 26), label_len);
        c.label[0] = (uint8_t)i;
        memset(c.cred_pw, 0x7B, sizeof(c.cred_pw));
        memset(c.secret, 0x7C, sizeof(c.secret));
        assert(hsmauth_save_cred((uint8_t)i, &c));
        expected[off++] = HSMAUTH_TAG_LABEL_LIST;
        expected[off++] = (uint8_t)(3 + label_len);
        expected[off++] = c.algo;
        expected[off++] = c.touch_required;
        memcpy(expected + off, c.label, label_len);
        off += label_len;
        expected[off++] = c.retries;
    }
    return off;
}

static void verify_list(unsigned count, uint8_t label_len, uint8_t short_le, bool extended, uint8_t itf) {
    reset_fixture();
    uint8_t expected[HSMAUTH_MAX_CREDS * 69];
    uint8_t actual[sizeof(expected)];
    size_t expected_len = seed_credentials(count, label_len, expected);
    uint8_t list[] = {0, HSMAUTH_INS_LIST, 0, 0, short_le, 0, 0};
    uint8_t get_response[] = {0, 0xC0, 0, 0, short_le, 0, 0};
    size_t request_len = extended ? 7 : 5;
    if (extended) list[4] = get_response[4] = 0;
    size_t received = 0;
    uint16_t sw = exchange_on(itf, list, request_len);
    unsigned chunks = 0;
    for (;;) {
        size_t size = tx_len - 2;
        assert(size <= (extended || short_le == 0 ? 256 : short_le));
        assert(size <= expected_len - received);
        memcpy(actual + received, res_APDU, size);
        received += size;
        chunks++;
        if (received == expected_len) {
            assert(sw == 0x9000);
            break;
        }
        size_t left = expected_len - received;
        assert(sw == (0x6100 | (left >= 256 ? 0 : left)));
        assert(size != 0);
        sw = exchange_on(itf, get_response, request_len);
    }
    assert(received == expected_len);
    assert(memcmp(expected, actual, received) == 0);
    if (expected_len > 256) assert(chunks > 1);
    assert(exchange_on(itf, get_response, request_len) == 0x6D00);
}

static void test_pending_response_invalidation(void) {
    uint8_t expected[HSMAUTH_MAX_CREDS * 69];
    const uint8_t list[] = {0, HSMAUTH_INS_LIST, 0, 0, 1};
    const uint8_t next[] = {0, 0xC0, 0, 0, 0};
    const uint8_t version[] = {0, HSMAUTH_INS_GET_VERSION, 0, 0, 0};
    uint8_t select[13] = {0, 0xA4, 4, 0, 8};
    memcpy(select + 5, hsmauth_aid + 1, 8);
    reset_fixture();
    seed_credentials(32, 64, expected);
    assert(exchange(list, sizeof(list)) == 0x6100);
    assert(exchange(version, sizeof(version)) == 0x9000);
    assert(exchange(next, sizeof(next)) == 0x6D00);
    assert(exchange(list, sizeof(list)) == 0x6100);
    assert(exchange(select, sizeof(select)) == 0x9000);
    assert(exchange(next, sizeof(next)) == 0x6D00);
    assert(exchange(list, sizeof(list)) == 0x6100);
    hsmauth_unload();
    assert(exchange(next, sizeof(next)) == 0x6D00);

    /* A malformed continuation cannot leave an old snapshot available. */
    assert(exchange(list, sizeof(list)) == 0x6100);
    const uint8_t invalid_next[] = {0, 0xC0, 1, 0, 0};
    assert(exchange(invalid_next, sizeof(invalid_next)) == 0x6D00);
    assert(exchange(next, sizeof(next)) == 0x6D00);

    assert(exchange(list, sizeof(list)) == 0x6100);
    const uint8_t malformed[] = {0, 0xC0, 0};
    assert(apdu_process(ITF_SC_CCID, CONST_BYTE_ARRAY(malformed, sizeof(malformed))) == 0);
    assert(exchange(next, sizeof(next)) == 0x6D00);

    assert(exchange(list, sizeof(list)) == 0x6100);
    app_t other_app = *current_app;
    current_app = &other_app;
    assert(exchange(next, sizeof(next)) == 0x6D00);
    current_app = &apps[0];

    /* The pending bytes are a stable snapshot, even if storage changes. */
    assert(exchange(list, sizeof(list)) == 0x6100);
    for (size_t i = 0; i < sizeof(test_files) / sizeof(test_files[0]); i++) {
        if (test_files[i].fid != EF_HSMAUTH_STATE) file_sizes[i] = 0;
    }
    assert(exchange(next, sizeof(next)) == 0x6100);
    assert(memcmp(res_APDU, expected + 1, tx_len - 2) == 0);
    assert(exchange(list, sizeof(list)) == 0x9000);
    assert(tx_len == 2);
}

static void test_inline_response_compatibility(void) {
    reset_fixture();
    memset(&transport, 0xA5, sizeof(transport));
    apdu.rdata = transport.usb + 10;
    const uint8_t request[] = {0, 0x7F, 0, 0, 7};
    const uint8_t next[] = {0, 0xC0, 0, 0, 7};
    uint8_t expected[20];
    for (size_t i = 0; i < sizeof(expected); i++) expected[i] = (uint8_t)i;
    assert(apdu_process(ITF_SC_CCID, CONST_BYTE_ARRAY(request, sizeof(request))) == 1);
    memcpy(res_APDU, expected, sizeof(expected));
    res_APDU_size = sizeof(expected);
    SW_OK();
    apdu_finish();
    assert(apdu_next() == 9);
    assert(memcmp(res_APDU, expected, 7) == 0);
    assert(get_uint16_be(res_APDU + 7) == 0x610D);

    inline_response_test = true;
    assert(apdu_process(ITF_SC_CCID, CONST_BYTE_ARRAY(next, sizeof(next))) == 0);
    assert(tx_len == 9 && tx_offset == 7);
    assert(memcmp(res_APDU + tx_offset, expected + 7, 7) == 0);
    assert(get_uint16_be(res_APDU + tx_offset + 7) == 0x6106);
    assert(apdu_process(ITF_SC_CCID, CONST_BYTE_ARRAY(next, sizeof(next))) == 0);
    assert(tx_len == 8 && tx_offset == 14);
    assert(memcmp(res_APDU + tx_offset, expected + 14, 6) == 0);
    assert(get_uint16_be(res_APDU + tx_offset + 6) == 0x9000);
    inline_response_test = false;
}

static void test_invalid_stored_labels(void) {
    uint8_t expected[69];
    const uint8_t list[] = {0, HSMAUTH_INS_LIST, 0, 0, 0};
    reset_fixture();
    seed_credentials(1, 64, expected);
    hsmauth_cred_t invalid;
    assert(hsmauth_load_cred(0, &invalid));
    invalid.label_len = 65;
    assert(applet_storage_save(EF_HSMAUTH_CRED_BASE, &invalid, sizeof(invalid)));
    assert(exchange(list, sizeof(list)) == 0x9000);
    assert(tx_len == 2);
    invalid.label_len = 0;
    assert(applet_storage_save(EF_HSMAUTH_CRED_BASE, &invalid, sizeof(invalid)));
    assert(exchange(list, sizeof(list)) == 0x9000);
    assert(tx_len == 2);
}

static unsigned button_cmd_calls;
static unsigned exit_unload_calls;
static bool exit_ack_saw_unload;

static int button_abort_process_apdu(void) {
    button_cmd_calls++;
    uint32_t val = EV_PRESS_BUTTON_WITH_TIMEOUT(15);
    queue_try_add(&card_to_usb_q, &val);
    do {
        queue_remove_blocking(&usb_to_card_q, &val);
    } while (val != EV_BUTTON_PRESSED && val != EV_BUTTON_TIMEOUT &&
             val != EV_BUTTON_CANCELLED && val != EV_EXIT);
    if (val == EV_EXIT) {
        queue_try_add(&usb_to_card_q, &val);
        return SW_CONDITIONS_NOT_SATISFIED();
    }
    return SW_OK();
}

static int button_abort_unload(void) {
    exit_unload_calls++;
    apdu_clear_response_buffer();
    return PICOKEYS_OK;
}

static void check_exit_ack_order(uint32_t event) {
    if (event == EV_EXIT + 1) {
        exit_ack_saw_unload = (exit_unload_calls == 1 && current_app == NULL && !response_pending);
    }
}

static void test_apdu_thread_exit_during_button_wait(void) {
    reset_fixture();
    memset(&usb_to_card_q, 0, sizeof(usb_to_card_q));
    memset(&card_to_usb_q, 0, sizeof(card_to_usb_q));
    core1_inits = button_cmd_calls = exit_unload_calls = 0;
    exit_ack_saw_unload = false;
    on_card_queue_add = check_exit_ack_order;

    uint8_t dummy_hdr[4] = { 0x00, 0x01, 0x00, 0x00 };
    memset(&transport, 0xA5, sizeof(transport));
    apdu.header = dummy_hdr;
    apdu.rdata = transport.usb + 10;
    apdu.ne = 256;
    current_app = &apps[0];
    current_app->process_apdu = button_abort_process_apdu;
    current_app->unload = button_abort_unload;

    /* Queue a command that blocks in a button wait, followed by a stale button
     * event and EV_EXIT from Core 0 card_exit(). */
    uint32_t ev_cmd = EV_CMD_AVAILABLE;
    uint32_t ev_exit = EV_EXIT;
    uint32_t ev_stale_btn = EV_BUTTON_CANCELLED;
    queue_add_blocking(&usb_to_card_q, &ev_cmd);
    queue_add_blocking(&usb_to_card_q, &ev_exit);
    queue_add_blocking(&usb_to_card_q, &ev_stale_btn);

    apdu_thread(NULL);

    assert(core1_inits == 1);
    assert(button_cmd_calls == 1);
    assert(exit_unload_calls == 1);
    assert(exit_ack_saw_unload);
    assert(current_app == NULL);
    assert(usb_to_card_q.count == 0);
    assert(card_to_usb_q.count == 3);
    uint32_t out = 0;
    queue_remove_blocking(&card_to_usb_q, &out);
    assert((out & 0xffu) == EV_PRESS_BUTTON);
    queue_remove_blocking(&card_to_usb_q, &out);
    assert(out == EV_EXEC_FINISHED);
    queue_remove_blocking(&card_to_usb_q, &out);
    assert(out == EV_EXIT + 1);
    on_card_queue_add = NULL;
}

int main(void) {
    verify_list(0, 1, 0, false, ITF_SC_CCID);
    verify_list(1, 1, 0, false, ITF_SC_CCID);
    verify_list(29, 64, 0, false, ITF_SC_CCID);
    verify_list(30, 64, 0, false, ITF_SC_CCID);
    verify_list(32, 64, 0, false, ITF_SC_CCID);
    verify_list(32, 64, 1, false, ITF_SC_CCID);
    verify_list(32, 64, 17, false, ITF_SC_CCID);
    verify_list(32, 64, 0, true, ITF_SC_CCID);
    verify_list(32, 64, 0, true, ITF_HID_CTAP);
    test_pending_response_invalidation();
    test_invalid_stored_labels();
    test_inline_response_compatibility();
    test_apdu_thread_exit_during_button_wait();
    puts("hsmauth_list_test: OK");
    return 0;
}
