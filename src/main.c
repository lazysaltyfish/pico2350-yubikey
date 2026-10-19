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
#include "button.h"
#include <stdio.h>
#include "tusb.h"
#include "bsp/board.h"
#include "hardware/structs/ioqspi.h"
#include "pico/stdio.h"

#include "random.h"
#include "hwrng.h"
#include "apdu.h"
#include "usb.h"
#include "flash.h"
#include "otp.h"
#include "led/led.h"
#include "pico_time.h"
#include "serial.h"
#include "mbedtls/sha256.h"

extern int rescue_migrate_keydev(void);

app_t apps[16];
uint8_t num_apps = 0;

app_t *current_app = NULL;

const uint8_t *ccid_atr = NULL;

bool app_exists(const_byte_array_t aid) {
    for (int a = 0; a < num_apps; a++) {
        if (aid.len >= apps[a].aid[0] && !memcmp(apps[a].aid + 1, aid.data, apps[a].aid[0])) {
            return true;
        }
    }
    return false;
}

int register_app(int (*select_aid)(app_t *, uint8_t), const uint8_t *aid) {
    if (app_exists(CONST_BYTE_ARRAY(aid + 1, aid[0]))) {
        return 1;
    }
    if (num_apps < sizeof(apps) / sizeof(app_t)) {
        apps[num_apps].select_aid = select_aid;
        apps[num_apps].aid = aid;
        num_apps++;
        return 1;
    }
    return 0;
}

int select_app(const_byte_array_t aid) {
    if (current_app && current_app->aid && (current_app->aid + 1 == aid.data || (aid.len >= current_app->aid[0] && !memcmp(current_app->aid + 1, aid.data, current_app->aid[0])))) {
        current_app->select_aid(current_app, 0);
        return PICOKEYS_OK;
    }
    for (int a = 0; a < num_apps; a++) {
        if (aid.len >= apps[a].aid[0] && !memcmp(apps[a].aid + 1, aid.data, apps[a].aid[0])) {
            if (current_app) {
                if (current_app->aid && aid.len >= current_app->aid[0] && !memcmp(current_app->aid + 1, aid.data, current_app->aid[0])) {
                    current_app->select_aid(current_app, 1);
                    return PICOKEYS_OK;
                }
                if (current_app->unload) {
                    current_app->unload();
                }
            }
            current_app = &apps[a];
            if (current_app->select_aid(current_app, 1) == PICOKEYS_OK) {
                return PICOKEYS_OK;
            }
        }
    }
    return PICOKEYS_ERR_FILE_NOT_FOUND;
}


WEAK int picokey_init(void) {
    return 0;
}

void execute_tasks(void);
void execute_tasks(void) {
    tud_task(); // tinyusb device task
    usb_task();
    led_blinking_task();
#ifdef ENABLE_LVGL_UI
    platform_ui_task();
#endif
}

static void core0_loop(void *arg) {
    (void)arg;
    while (1) {
        execute_tasks();
        hwrng_task();
        flash_task();
        button_task();
        // Avoid a pure busy loop on core0; gives the system a scheduling hint.
        tight_loop_contents();
    }
}

int main(void) {
    serial_init();
    board_init();
    stdio_init_all();
    random_init();
    otp_init();
    low_flash_init();
    file_scan_flash();

    if (rescue_migrate_keydev() != PICOKEYS_OK) {
        printf("Device attestation key migration failed\n");
    }

    init_rtc();
    phy_init();
    led_init();
    usb_init();
    tusb_init();
    picokey_init();
    core0_loop(NULL);

    return 0;
}
