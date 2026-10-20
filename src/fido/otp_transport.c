/* SPDX-License-Identifier: AGPL-3.0-only */
#include "picokeys.h"
#include "apdu.h"
#include "usb.h"
#include "otp_transport.h"

static uint8_t rx[70], job[70], tx[70], status_report[8];
static size_t tx_remaining, tx_offset, result_len;
static uint8_t tx_sequence, button_slot, rx_sequence;
static bool pending, inflight, refresh_only, discard_result, status_valid, terminal_frame;

static uint16_t frame_crc(const uint8_t *data, size_t len) {
    uint16_t crc = 0xffff;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (unsigned bit = 0; bit < 8; bit++) crc = (crc >> 1) ^ ((crc & 1) ? 0x8408 : 0);
    }
    return crc;
}

void otp_hid_copy_status(uint8_t out[8]) { memcpy(out, status_report, 8); }

void otp_hid_update_status(const uint8_t status[8]) {
    memcpy(status_report, status, sizeof(status_report));
    status_valid = true;
}

int otp_hid_set_report_cb(uint8_t itf, uint8_t id, hid_report_type_t type, const uint8_t *data, uint16_t len) {
    if (itf != ITF_HID_KB || type != HID_REPORT_TYPE_FEATURE) return 0;
    if (id != 0 || !data || len != 8) return 1;
    if (data[7] == 0xff) {
        pending = false;
        discard_result = inflight;
        tx_remaining = tx_offset = 0;
        tx_sequence = 0;
        terminal_frame = false;
        rx_sequence = 0;
        memset(rx, 0, sizeof(rx));
        return 1;
    }
    if (pending || inflight || !(data[7] & 0x80)) return 1;
    uint8_t seq = data[7] & 0x1f;
    if (seq >= 10) return 1;
    if (seq == 0) {
        memset(rx, 0, sizeof(rx));
        rx_sequence = 0;
    }
    if (seq != rx_sequence) {
        rx_sequence = 0;
        return 1;
    }
    rx_sequence++;
    memcpy(rx + seq * 7, data, 7);
    if (seq == 9 && frame_crc(rx, 64) == get_uint16_le(rx + 65)) {
        memcpy(job, rx, sizeof(job));
        pending = true;
        refresh_only = false;
        button_slot = 0;
    }
    if (seq == 9) rx_sequence = 0;
    return 1;
}

uint16_t otp_hid_get_report_cb(uint8_t itf, uint8_t id, hid_report_type_t type, uint8_t *out, uint16_t len) {
    if (itf != ITF_HID_KB || id != 0 || type != HID_REPORT_TYPE_FEATURE || !out || len < 8) return 0;
    memset(out, 0, 8);
    if (!inflight && !pending && tx_remaining) {
        size_t n = MIN(7u, tx_remaining);
        memcpy(out, tx + tx_offset, n);
        out[7] = 0x40 | tx_sequence++;
        tx_offset += n;
        tx_remaining -= n;
        terminal_frame = true;
    }
    else if (!inflight && !pending && terminal_frame) {
        out[7] = 0x40;
        terminal_frame = false;
    }
    else {
        bool worker_busy = inflight || is_busy();
        if (!worker_busy && !pending && !status_valid) {
            pending = true;
            refresh_only = true;
            button_slot = 0;
        }
        /* While the worker runs, even its status snapshot is off limits. */
        if (!worker_busy) memcpy(out, status_report, 8);
        if (pending || worker_busy) out[7] |= 0x20;
    }
    return 8;
}

int otp_hid_queue_button(uint8_t slot) {
    if (pending || inflight || tx_remaining || slot == 0 || slot > 4) return 1;
    button_slot = slot;
    pending = true;
    refresh_only = false;
    return 0;
}

void otp_hid_execute_pending(void) {
    /* Called only by the APDU worker, never from a USB callback. */
    result_len = 0;
    if (button_slot) {
        otp_hid_button(button_slot);
    }
    else if (!refresh_only) {
        if (otp_hid_command(job[64], job, tx, &result_len) != 0x9000 || result_len > sizeof(tx) - 2) {
            result_len = 0;
        }
    }
    otp_hid_refresh_status();
}

void otp_hid_task(void) {
    if (inflight) {
        if (card_status(ITF_KEYBOARD) != PICOKEYS_OK) return;
        inflight = false;
        button_slot = 0;
        tx_remaining = tx_offset = 0;
        tx_sequence = 0;
        if (!discard_result && result_len) {
            put_uint16_le((uint16_t)~frame_crc(tx, result_len), tx + result_len);
            tx_remaining = result_len + 2;
        }
        discard_result = false;
    }
    if (pending && !is_busy()) {
        pending = false;
        inflight = true;
        discard_result = false;
        card_start(ITF_KEYBOARD, apdu_thread);
        usb_send_event(EV_OTP_CMD_AVAILABLE);
    }
}
