/* SPDX-License-Identifier: AGPL-3.0-only */
#pragma once
#include "tusb.h"
#include <stddef.h>
#include <stdint.h>

int otp_hid_set_report_cb(uint8_t, uint8_t, hid_report_type_t, const uint8_t *, uint16_t);
uint16_t otp_hid_get_report_cb(uint8_t, uint8_t, hid_report_type_t, uint8_t *, uint16_t);
void otp_hid_task(void);
int otp_hid_queue_button(uint8_t slot);
int otp_hid_button(uint8_t slot);
void otp_hid_execute_pending(void);
void otp_hid_copy_status(uint8_t out[8]);
void otp_hid_update_status(const uint8_t status[8]);
int otp_hid_command(uint8_t command, const uint8_t request[64], uint8_t response[70], size_t *response_len);
void otp_hid_refresh_status(void);
