/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef COUNTER_FIXTURE_H
#define COUNTER_FIXTURE_H
#include "picokeys.h"
#include "apdu.h"
#include <assert.h>
#include <stdio.h>
extern unsigned fixture_core, fixture_syncs, fixture_writes, fixture_deletes;
extern unsigned fixture_fail_sync, fixture_fail_write;
extern int fixture_fail_fid, fixture_fail_delete;
extern bool fixture_touch;
extern unsigned fixture_touch_calls, fixture_keyboards;
extern uint8_t fixture_keyboard[128], fixture_response[2048];
extern size_t fixture_keyboard_size;
extern void (*fixture_keyboard_hook)(void);
void fixture_reset(void);
void fixture_reboot(void);
void fixture_persist(void);
void fixture_request(uint8_t ins, uint8_t p1, uint8_t p2, const uint8_t *data, size_t len);
void fixture_seed(uint16_t fid, const uint8_t *data, size_t len);
size_t fixture_durable(uint16_t fid, uint8_t *data, size_t cap);
#endif
