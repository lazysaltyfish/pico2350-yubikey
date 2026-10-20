/*
 * Host-only regression tests for production USB HID callback arbitration.
 * Copyright (c) 2026 lazysaltyfish
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* No Pico SDK or physical USB stack is linked into this executable. */
#define _SERIAL_H_
typedef struct { uint8_t id[8]; } picokey_serial_t;
picokey_serial_t pico_serial;
#define TIME_H
static uint32_t now_ms = 1000;
static uint32_t board_millis(void) { return now_ms; }
static void sleep_ms(uint32_t ms) { (void)ms; }
#include "../src/usb/hid/hid.c"
#include "../src/usb/ccid/ccid.c"

uint8_t ITF_HID_CTAP = 0, ITF_HID_KB = 1;
uint8_t ITF_HID = 4, ITF_KEYBOARD = 5, ITF_HID_TOTAL = 2, ITF_TOTAL = 6;
uint8_t ITF_SC_CCID = 0, ITF_SC_WCID = ITF_INVALID, ITF_SC_TOTAL = 1;
uint8_t ITF_CCID = 6, ITF_WCID = ITF_INVALID;
const uint8_t *ccid_atr;
struct apdu apdu;
volatile bool cancel_button;
volatile uint16_t finished_data_size;
const uint8_t fido_aid[] = { 1, 0xA0 };
const uint8_t u2f_aid[] = { 1, 0xA1 };
const uint8_t oath_aid[] = { 1, 0xA2 };
static bool worker_busy;
static uint8_t worker_interface;
static bool report_accepted;
static unsigned reports_submitted, worker_starts, events_submitted, apdus_parsed, apps_selected;
static CTAPHID_FRAME submitted_report;

bool is_busy(void) { return worker_busy; }
uint8_t card_active_interface(void) { return worker_interface; }
bool tud_init(uint8_t rhport) { assert(rhport == 0); return true; }
bool tud_hid_ready(void) { return true; }
bool tud_hid_n_report(uint8_t instance, uint8_t id, const void *report, uint16_t len) {
    assert(instance == ITF_HID_CTAP && id == 0 && len == sizeof(submitted_report));
    if (!report_accepted) return false;
    memcpy(&submitted_report, report, sizeof(submitted_report));
    reports_submitted++;
    return true;
}
bool tud_hid_n_keyboard_report(uint8_t instance, uint8_t id, uint8_t modifier, const uint8_t keycode[6]) {
    (void)instance; (void)id; (void)modifier; (void)keycode;
    return true;
}
bool tud_suspended(void) { return false; }
bool tud_remote_wakeup(void) { return true; }
void usb_set_timeout_counter(uint8_t itf, uint32_t value) { (void)itf; (void)value; }
void timeout_stop(void) { worker_busy = false; }
void init_fido(void) {}
bool is_req_button_pending(void) { return false; }
int select_app(const_byte_array_t aid) { (void)aid; apps_selected++; return PICOKEYS_OK; }
uint16_t apdu_process(uint8_t itf, const_byte_array_t request) {
    (void)itf; (void)request; apdus_parsed++; return 1;
}
int cbor_process(uint8_t cmd, const uint8_t *data, size_t len) {
    (void)cmd; (void)data; (void)len; apdus_parsed++; return 2;
}
void *apdu_thread(void *arg) { return arg; }
void *cbor_thread(void *arg) { return arg; }
void card_start(uint8_t itf, void *(*entry)(void *)) {
    (void)entry; worker_starts++; worker_busy = true; worker_interface = itf;
}
void card_exit(void) { worker_busy = false; }
void usb_send_event(uint32_t event) { (void)event; events_submitted++; }
int card_status(uint8_t itf) { (void)itf; return PICOKEYS_ERR_FILE_NOT_FOUND; }

static uint8_t vendor_fifo[256];
static uint32_t vendor_available;
static unsigned vendor_reads;
uint32_t tud_vendor_n_available(uint8_t itf) { assert(itf == ITF_SC_CCID); return vendor_available; }
uint32_t tud_vendor_n_read(uint8_t itf, void *out, uint32_t size) {
    assert(itf == ITF_SC_CCID && size <= vendor_available);
    memcpy(out, vendor_fifo, size);
    memmove(vendor_fifo, vendor_fifo + size, vendor_available - size);
    vendor_available -= size;
    vendor_reads++;
    return size;
}
uint32_t tud_vendor_n_write(uint8_t itf, const void *data, uint32_t size) {
    (void)itf; (void)data; return size;
}
uint32_t tud_vendor_n_write_flush(uint8_t itf) { (void)itf; return 0; }
void vendord_init(void) {}
void vendord_reset(uint8_t rhport) { (void)rhport; }
uint16_t vendord_open(uint8_t rhport, const tusb_desc_interface_t *descriptor, uint16_t size) {
    (void)rhport; (void)descriptor; return size;
}
bool vendord_xfer_cb(uint8_t rhport, uint8_t endpoint, xfer_result_t result, uint32_t size) {
    (void)rhport; (void)endpoint; (void)result; (void)size; return true;
}
bool usbd_edpt_open(uint8_t rhport, const tusb_desc_endpoint_t *endpoint) {
    (void)rhport; (void)endpoint; return true;
}
bool usbd_edpt_xfer(uint8_t rhport, uint8_t endpoint, uint8_t *data, uint16_t size) {
    (void)rhport; (void)endpoint; (void)data; (void)size; return true;
}
void led_set_mode(uint32_t mode) { (void)mode; }
uint16_t apdu_limit_response(uint16_t next, uint16_t maximum) { return next < maximum ? next : maximum; }

static uint8_t active_header[4] = { 0, 0x87, 0x11, 0x9A };
static uint8_t active_payload[80];
static struct apdu active_apdu;
static usb_buffer_t active_rx, active_tx;
static CTAPHID_FRAME *active_request, *active_response;
static msg_packet_t active_message;
static uint16_t active_send_size;

static void snapshot_active(void) {
    active_apdu = apdu;
    active_rx = hid_rx[ITF_HID_CTAP];
    active_tx = hid_tx[ITF_HID_CTAP];
    active_request = ctap_req;
    active_response = ctap_resp;
    active_message = msg_packet;
    active_send_size = send_buffer_size[ITF_HID_CTAP];
}

static void assert_active_preserved(void) {
    assert(memcmp(&apdu, &active_apdu, sizeof(apdu)) == 0);
    assert(memcmp(&hid_rx[ITF_HID_CTAP], &active_rx, sizeof(active_rx)) == 0);
    assert(memcmp(&hid_tx[ITF_HID_CTAP], &active_tx, sizeof(active_tx)) == 0);
    assert(memcmp(&msg_packet, &active_message, sizeof(active_message)) == 0);
    assert(ctap_req == active_request && ctap_resp == active_response);
    assert(send_buffer_size[ITF_HID_CTAP] == active_send_size);
    assert(worker_starts == 0 && events_submitted == 0 && apdus_parsed == 0 && apps_selected == 0);
}

static void reset_active(uint8_t owner) {
    hid_init();
    memset(hid_rx, 0x53, ITF_HID_TOTAL * sizeof(*hid_rx));
    memset(hid_tx, 0x64, ITF_HID_TOTAL * sizeof(*hid_tx));
    hid_rx[ITF_HID_CTAP].r_ptr = 16;
    hid_rx[ITF_HID_CTAP].w_ptr = 80;
    hid_tx[ITF_HID_CTAP].r_ptr = 7;
    hid_tx[ITF_HID_CTAP].w_ptr = 187;
    ctap_req = (CTAPHID_FRAME *)(hid_rx[ITF_HID_CTAP].buffer + 16);
    memset(ctap_req, 0, sizeof(*ctap_req));
    ctap_req->cid = 0x11223344;
    ctap_req->init.cmd = CTAPHID_CBOR;
    ctap_req->init.bcntl = 17;
    ctap_resp = (CTAPHID_FRAME *)hid_tx[ITF_HID_CTAP].buffer;
    send_buffer_size[ITF_HID_CTAP] = 180;
    last_write_result[ITF_HID_CTAP] = WRITE_SUCCESS;
    memset(&msg_packet, 0x75, sizeof(msg_packet));
    msg_packet.len = 123;
    msg_packet.current_len = 57;
    apdu = (struct apdu){ .header = active_header, .data = active_payload, .nc = 80,
                          .rdata = ctap_resp->init.data, .rlen = 41, .sw = 0x9000 };
    worker_busy = true;
    worker_interface = owner;
    cancel_button = false;
    report_accepted = true;
    reports_submitted = worker_starts = events_submitted = apdus_parsed = apps_selected = 0;
    busy_reply_pending = false;
    hid_set_report_cb = NULL;
    hid_get_report_cb = NULL;
    last_packet_time = 1;
    snapshot_active();
}

static CTAPHID_FRAME incoming(uint32_t cid, uint8_t command, uint16_t len) {
    CTAPHID_FRAME request = { 0 };
    request.cid = cid;
    request.init.cmd = command;
    request.init.bcnth = len >> 8;
    request.init.bcntl = len;
    return request;
}

static void receive(CTAPHID_FRAME *frame) {
    tud_hid_set_report_cb(ITF_HID_CTAP, 0, HID_REPORT_TYPE_OUTPUT,
                          (const uint8_t *)frame, sizeof(*frame));
}

static void test_busy_reply_completion_preserves_active_buffers(void) {
    reset_active(ITF_HID);
    CTAPHID_FRAME request = incoming(0x99887766, CTAPHID_CBOR, 1);
    receive(&request);
    assert(reports_submitted == 1 && busy_reply_pending);
    assert(submitted_report.cid == request.cid);
    assert(submitted_report.init.cmd == CTAPHID_ERROR);
    assert(MSG_LEN(&submitted_report) == 1);
    assert(submitted_report.init.data[0] == CTAP1_ERR_CHANNEL_BUSY);
    assert_active_preserved();
    tud_hid_report_complete_cb(ITF_HID_CTAP, (const uint8_t *)&submitted_report, sizeof(submitted_report));
    assert(!busy_reply_pending);
    assert(last_write_result[ITF_HID_CTAP] == WRITE_SUCCESS);
    assert_active_preserved();

    /* Busy-response completion may arrive after the worker has finished. */
    receive(&request);
    worker_busy = false;
    tud_hid_report_complete_cb(ITF_HID_CTAP, (const uint8_t *)&submitted_report, sizeof(submitted_report));
    assert_active_preserved();
}

static void test_busy_submission_failure_does_not_consume_an_active_report(void) {
    reset_active(ITF_HID);
    CTAPHID_FRAME request = incoming(0x99887766, CTAPHID_MSG, 1);
    report_accepted = false;
    receive(&request);
    assert(reports_submitted == 0 && !busy_reply_pending);
    assert(last_write_result[ITF_HID_CTAP] == WRITE_FAILED);
    assert_active_preserved();

    reset_active(ITF_HID);
    last_write_result[ITF_HID_CTAP] = WRITE_PENDING; /* Active keepalive in flight. */
    receive(&request);
    assert(reports_submitted == 0 && !busy_reply_pending);
    CTAPHID_FRAME keepalive = incoming(ctap_req->cid, CTAPHID_KEEPALIVE, 1);
    tud_hid_report_complete_cb(ITF_HID_CTAP, (const uint8_t *)&keepalive, sizeof(keepalive));
    assert_active_preserved();

    /* Completing a real active response must still advance it normally. */
    last_write_result[ITF_HID_CTAP] = WRITE_PENDING;
    CTAPHID_FRAME response = incoming(ctap_req->cid, CTAPHID_CBOR, active_send_size);
    tud_hid_report_complete_cb(ITF_HID_CTAP, (const uint8_t *)&response, sizeof(response));
    assert(send_buffer_size[ITF_HID_CTAP] == active_send_size - 57);
    assert(hid_tx[ITF_HID_CTAP].r_ptr == active_tx.r_ptr + 59);
    assert(ctap_resp == (CTAPHID_FRAME *)((uint8_t *)active_response + 59));
}

static void test_cancel_only_changes_the_active_cancellation_flag(void) {
    reset_active(ITF_HID);
    CTAPHID_FRAME cancel = incoming(ctap_req->cid, CTAPHID_CANCEL, 0);
    receive(&cancel);
    assert(cancel_button && reports_submitted == 0);
    assert_active_preserved();
    const uint8_t owners[] = { ITF_HID, ITF_KEYBOARD, ITF_CCID };
    for (size_t i = 0; i < sizeof(owners); i++) {
        reset_active(owners[i]);
        cancel = incoming(i == 0 ? ctap_req->cid + 1 : ctap_req->cid, CTAPHID_CANCEL, 0);
        receive(&cancel);
        assert(!cancel_button && reports_submitted == 1);
        assert_active_preserved();
    }
    reset_active(ITF_HID);
    cancel = incoming(ctap_req->cid, CTAPHID_CANCEL, 1);
    receive(&cancel);
    assert(!cancel_button && reports_submitted == 1);
    assert_active_preserved();
    reset_active(ITF_HID);
    cancel = incoming(ctap_req->cid, 0, 0); /* Continuation frame. */
    receive(&cancel);
    assert(!cancel_button && reports_submitted == 1);
    assert_active_preserved();
}

static void test_incomplete_packet_timeout_waits_for_worker(void) {
    reset_active(ITF_HID);
    assert(driver_process_usb_nopacket_hid() == 0);
    assert(last_packet_time == 1);
    assert_active_preserved();
    uint8_t short_report[63] = { 0 };
    tud_hid_set_report_cb(ITF_HID_CTAP, 0, HID_REPORT_TYPE_OUTPUT,
                          short_report, sizeof(short_report));
    assert(reports_submitted == 0);
    assert_active_preserved();
}

static uint16_t short_get_report(uint8_t itf, uint8_t id, hid_report_type_t type,
                                uint8_t *buffer, uint16_t size) {
    (void)itf; (void)id; (void)type;
    assert(size == 8);
    buffer[0] = 0x42;
    return 3;
}
static void test_get_report_propagates_actual_length(void) {
    reset_active(ITF_KEYBOARD);
    uint8_t report[8];
    hid_get_report_cb = short_get_report;
    assert(tud_hid_get_report_cb(ITF_HID_KB, 0, HID_REPORT_TYPE_FEATURE, report, sizeof(report)) == 3);
    assert(report[0] == 0x42);
    assert_active_preserved();
}

static void queue_ccid_command(uint8_t seq) {
    uint8_t frame[15] = { CCID_XFR_BLOCK, 5, 0, 0, 0, 0, seq, 0, 0, 0,
                          0, 0xFD, 0, 0, 0 };
    assert(vendor_available + sizeof(frame) <= sizeof(vendor_fifo));
    memcpy(vendor_fifo + vendor_available, frame, sizeof(frame));
    vendor_available += sizeof(frame);
}

static void test_ccid_fifo_waits_for_the_active_worker(void) {
    reset_active(ITF_HID);
    ccid_init();
    memset(ccid_rx, 0, ITF_SC_TOTAL * sizeof(*ccid_rx));
    memset(ccid_tx, 0, ITF_SC_TOTAL * sizeof(*ccid_tx));
    vendor_available = vendor_reads = 0;
    queue_ccid_command(7);
    tud_vendor_rx_cb(ITF_SC_CCID, NULL, 0);
    assert(vendor_reads == 0 && vendor_available == 15);
    assert(ccid_rx[ITF_SC_CCID].w_ptr == 0);
    assert_active_preserved();
    worker_busy = false;
    now_ms++;
    ccid_task();
    assert(vendor_reads == 1 && vendor_available == 0);
    assert(apdus_parsed == 1 && worker_starts == 1 && events_submitted == 1);
    assert(worker_interface == ITF_CCID && worker_busy);

    /* A second request can already be buffered from the same USB read.
     * It must wait in RAM until the first command and its response finish. */
    reset_active(ITF_HID);
    memset(ccid_rx, 0, ITF_SC_TOTAL * sizeof(*ccid_rx));
    memset(ccid_tx, 0, ITF_SC_TOTAL * sizeof(*ccid_tx));
    vendor_available = vendor_reads = 0;
    queue_ccid_command(8);
    queue_ccid_command(9);
    worker_busy = false;
    tud_vendor_rx_cb(ITF_SC_CCID, NULL, 0);
    assert(apdus_parsed == 1 && worker_starts == 1 && worker_busy);
    assert(ccid_rx[ITF_SC_CCID].w_ptr - ccid_rx[ITF_SC_CCID].r_ptr == 15);
    struct apdu executing = apdu;
    usb_buffer_t buffered = ccid_rx[ITF_SC_CCID];
    now_ms++;
    ccid_task();
    assert(apdus_parsed == 1 && worker_starts == 1);
    assert(memcmp(&apdu, &executing, sizeof(apdu)) == 0);
    assert(memcmp(&ccid_rx[ITF_SC_CCID], &buffered, sizeof(buffered)) == 0);
    worker_busy = false;
    now_ms++;
    ccid_task();
    assert(apdus_parsed == 2 && worker_starts == 2 && events_submitted == 2);
    assert(ccid_rx[ITF_SC_CCID].r_ptr == 0 && ccid_rx[ITF_SC_CCID].w_ptr == 0);
}

int main(void) {
    test_busy_reply_completion_preserves_active_buffers();
    test_busy_submission_failure_does_not_consume_an_active_report();
    test_cancel_only_changes_the_active_cancellation_flag();
    test_incomplete_packet_timeout_waits_for_worker();
    test_get_report_propagates_actual_length();
    test_ccid_fifo_waits_for_the_active_worker();
    puts("USB HID/CCID arbitration regression tests passed");
    return 0;
}
