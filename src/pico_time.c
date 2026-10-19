/*
 * This file is part of the Pico Keys SDK distribution (https://github.com/polhenarejos/pico-keys-sdk).
 * Copyright (c) 2022 Pol Henarejos.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "picokeys.h"
#include "pico_time.h"
struct tm *gmtime_utc(const time_t *timep, struct tm *result) {
    return gmtime_r(timep, result);
}

bool set_rtc = false;

bool has_set_rtc(void) {
    return set_rtc;
}

void set_rtc_time(time_t t) {
    struct timespec tv = {.tv_sec = t, .tv_nsec = 0};
    aon_timer_set_time(&tv);
    set_rtc = true;
}

time_t get_rtc_time(void) {
    struct timespec tv;
    aon_timer_get_time(&tv);
    return tv.tv_sec;
}

void init_rtc(void) {
    struct timespec tv = {0};
    tv.tv_sec = 1577836800; // 2020-01-01
    aon_timer_start(&tv);
}
