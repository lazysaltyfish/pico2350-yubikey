#pragma once
#include <stdint.h>
typedef enum { HID_REPORT_TYPE_INVALID, HID_REPORT_TYPE_INPUT, HID_REPORT_TYPE_OUTPUT, HID_REPORT_TYPE_FEATURE } hid_report_type_t;

/* Host-only TinyUSB surface used by production HID callback regressions. */
#include <stdbool.h>
#ifndef BOARD_TUD_RHPORT
#define BOARD_TUD_RHPORT 0
#endif
#ifndef HID_ASCII_TO_KEYCODE
#define HID_ASCII_TO_KEYCODE { 0, 0 }
#endif
#ifndef KEYBOARD_MODIFIER_LEFTSHIFT
#define KEYBOARD_MODIFIER_LEFTSHIFT 0x02
#endif
bool tud_init(uint8_t rhport);
bool tud_hid_ready(void);
bool tud_hid_n_report(uint8_t instance, uint8_t report_id, const void *report, uint16_t len);
bool tud_hid_n_keyboard_report(uint8_t instance, uint8_t report_id, uint8_t modifier, const uint8_t keycode[6]);
bool tud_suspended(void);
bool tud_remote_wakeup(void);
