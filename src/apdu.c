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
#include "apdu.h"
#include "led/led.h"
#include "usb.h"
#ifdef ENABLE_OTP_APP
#include "fido/otp_transport.h"
#endif
#include <stdio.h>

uint8_t *rdata_gr = NULL;
uint16_t rdata_bk = 0x0;
static bool response_pending = false;
static const uint8_t *response_buffer = NULL;
static uint16_t response_buffer_len = 0;
static app_t *response_buffer_app = NULL;
static uint8_t response_buffer_cla = 0;
extern uint32_t timeout;
bool is_chaining = false;
uint8_t chain_buf[2038];
uint8_t *chain_ptr = NULL;
static uint8_t chain_header[4];

struct apdu apdu;

void apdu_clear_response_buffer(void) {
    response_buffer = NULL;
    response_buffer_len = 0;
    response_buffer_app = NULL;
    response_pending = false;
    rdata_gr = NULL;
    rdata_bk = 0;
}

void apdu_set_response_buffer(const uint8_t *data, uint16_t len) {
    response_buffer = data;
    response_buffer_len = len;
    response_buffer_app = current_app;
    response_buffer_cla = CLA(apdu) & (uint8_t)~0x10;
    res_APDU_size = 0;
}

static void apdu_copy_response_buffer(void) {
    /* A short-APDU sized chunk also leaves room for every transport's header
     * and status word, even if the caller requests an extended-length reply. */
    if (apdu.ne == 0) apdu.ne = 256;
    uint16_t chunk_limit = (uint16_t)MIN(apdu.ne, 256u);
    uint16_t size = MIN(response_buffer_len, chunk_limit);
    memcpy(apdu.rdata, response_buffer, size);
    response_buffer += size;
    response_buffer_len -= size;
    apdu.rlen = size;
    apdu.sw = response_buffer_len ? make_uint16_be(0x61, response_buffer_len >= 256 ? 0 : (uint8_t)response_buffer_len) : 0x9000;
    if (!response_buffer_len) apdu_clear_response_buffer();
}

int process_apdu(void) {
    bool is_select = INS(apdu) == 0xA4 && P1(apdu) == 0x04 && (P2(apdu) == 0x00 || P2(apdu) == 0x04);
    led_set_mode(MODE_PROCESSING);
    if (CLA(apdu) & 0x10) {
        size_t chain_used = 0;
        if (!is_chaining) {
            chain_ptr = chain_buf;
            chain_header[0] = CLA(apdu) & (uint8_t)~0x10;
            chain_header[1] = INS(apdu);
            chain_header[2] = P1(apdu);
            chain_header[3] = P2(apdu);
        }
        else if ((CLA(apdu) & (uint8_t)~0x10) != chain_header[0] || INS(apdu) != chain_header[1] || P1(apdu) != chain_header[2] || P2(apdu) != chain_header[3]) {
            memset(chain_buf, 0, sizeof(chain_buf));
            chain_ptr = NULL;
            is_chaining = false;
            return SW_LAST_CHAIN_EXPECTED();
        }
        chain_used = (size_t)(chain_ptr - chain_buf);
        if (chain_used + apdu.nc >= sizeof(chain_buf)) {
            memset(chain_buf, 0, sizeof(chain_buf));
            chain_ptr = NULL;
            is_chaining = false;
            return SW_WRONG_LENGTH();
        }
        memcpy(chain_ptr, apdu.data, apdu.nc);
        chain_ptr += apdu.nc;
        is_chaining = true;
        return SW_OK();
    }
    else {
        if (is_chaining) {
            if (is_select || (CLA(apdu) & (uint8_t)~0x10) != chain_header[0] || INS(apdu) != chain_header[1] || P1(apdu) != chain_header[2] || P2(apdu) != chain_header[3]) {
                memset(chain_buf, 0, sizeof(chain_buf));
                chain_ptr = NULL;
                is_chaining = false;
                if (!is_select) {
                    return SW_LAST_CHAIN_EXPECTED();
                }
            }
        }
        if (is_chaining) {
            size_t chain_used = (size_t)(chain_ptr - chain_buf);
            if (chain_used + apdu.nc >= sizeof(chain_buf)) {
                memset(chain_buf, 0, sizeof(chain_buf));
                chain_ptr = NULL;
                is_chaining = false;
                return SW_WRONG_LENGTH();
            }
            memmove(apdu.data + chain_used, apdu.data, apdu.nc);
            memcpy(apdu.data, chain_buf, chain_used);
            apdu.nc += (uint16_t)chain_used;
            memset(chain_buf, 0, sizeof(chain_buf));
            chain_ptr = NULL;
            is_chaining = false;
        }
    }
    if (!(CLA(apdu) & 0x10) && (CLA(apdu) & 0x0C) && (!current_app || !current_app->supports_secure_messaging)) {
        return SW_CLA_NOT_SUPPORTED();
    }
    if (INS(apdu) == 0xA4 && P1(apdu) == 0x04 && (P2(apdu) == 0x00 || P2(apdu) == 0x4)) { //select by AID
        if (select_app(CONST_BYTE_ARRAY(apdu.data, apdu.nc)) == PICOKEYS_OK) {
            return SW_OK();
        }
        return SW_FILE_NOT_FOUND();
    }
    if (current_app && current_app->process_apdu) {
        return current_app->process_apdu();
    }
    return SW_FILE_NOT_FOUND();
}

uint16_t apdu_process(uint8_t itf, const_byte_array_t buffer) {
    uint32_t expected_size;
    uint16_t buffer_size = 0;

    if (buffer.len < 4 || buffer.len > UINT16_MAX || buffer.data == NULL) {
        apdu_clear_response_buffer();
        return 0;
    }
    buffer_size = (uint16_t)buffer.len;
    apdu.header = (uint8_t *)buffer.data;
    apdu.nc = apdu.ne = 0;
    if (buffer_size == 4) {
        apdu.nc = apdu.ne = 0;
        if (apdu.ne == 0) {
            apdu.ne = 256;
        }
    }
    else if (buffer_size == 5) {
        apdu.nc = 0;
        apdu.ne = apdu.header[4];
        if (apdu.ne == 0) {
            apdu.ne = 256;
        }
    }
    else if (apdu.header[4] == 0x0 && buffer_size >= 7) {
        if (buffer_size == 7) {
            apdu.ne = get_uint16_be(apdu.header + 5);
            if (apdu.ne == 0) {
                apdu.ne = 65536;
            }
        }
        else {
            apdu.ne = 0;
            apdu.nc = get_uint16_be(apdu.header + 5);
            apdu.data = apdu.header + 7;
            expected_size = apdu.nc + 7;
            if (buffer_size != expected_size && buffer_size != expected_size + 2) {
                apdu_clear_response_buffer();
                return 0;
            }
            if (buffer_size == expected_size + 2) {
                apdu.ne = get_uint16_be(apdu.header + buffer_size - 2);
                if (apdu.ne == 0) {
                    apdu.ne = 65536;
                }
            }
        }
    }
    else {
        apdu.nc = apdu.header[4];
        apdu.data = apdu.header + 5;
        apdu.ne = 0;
        expected_size = apdu.nc + 5;
        if (buffer_size != expected_size && buffer_size != expected_size + 1) {
            apdu_clear_response_buffer();
            return 0;
        }
        if (buffer_size == expected_size + 1) {
            apdu.ne = apdu.header[buffer_size - 1];
            if (apdu.ne == 0) {
                apdu.ne = 256;
            }
        }
    }
    //printf("apdu.nc %u, apdu.ne %u\n",apdu.nc,apdu.ne);
    if (response_buffer && INS(apdu) == 0xC0) {
        bool valid = current_app == response_buffer_app && CLA(apdu) == response_buffer_cla &&
                     P1(apdu) == 0 && P2(apdu) == 0 && apdu.nc == 0;
        if (valid) {
            timeout_stop();
            apdu.sw = 0x9000;
            apdu_finish();
            uint16_t size = apdu_next();
#ifdef USB_ITF_HID
            if (itf == ITF_HID_CTAP) {
                driver_exec_finished_cont_hid(itf, size, 7);
            }
#endif
#ifdef USB_ITF_CCID
            if (itf == ITF_SC_CCID || itf == ITF_SC_WCID) {
                driver_exec_finished_cont_ccid(itf, size, 0);
            }
#endif
            return 0;
        }
        apdu_clear_response_buffer();
    }
    else if (INS(apdu) != 0xC0) {
        apdu_clear_response_buffer();
    }
    if (apdu.header[1] == 0xc0) {
        //printf("apdu.ne %u, apdu.rlen %d, bk %x\n",apdu.ne,apdu.rlen,rdata_bk);
        if (!response_pending || !rdata_gr) {
            rdata_gr = apdu.rdata;
            return 1;
        }
        timeout_stop();
        rdata_gr[0] = rdata_bk >> 8;
        rdata_gr[1] = rdata_bk & 0xff;
        if (apdu.rlen <= apdu.ne) {
#ifdef USB_ITF_HID
            if (itf == ITF_HID_CTAP) {
                driver_exec_finished_cont_hid(itf, apdu.rlen + 2, (uint16_t)(rdata_gr - apdu.rdata));
            }
#endif
#ifdef USB_ITF_CCID
            if (itf == ITF_SC_CCID || itf == ITF_SC_WCID) {
                driver_exec_finished_cont_ccid(itf, apdu.rlen + 2, (uint16_t)(rdata_gr - apdu.rdata));
            }
#endif
            //Prepare next RAPDU
            apdu.sw = 0;
            apdu.rlen = 0;
            rdata_gr = apdu.rdata;
            response_pending = false;
        }
        else {
            rdata_gr += apdu.ne;
            rdata_bk = (rdata_gr[0] << 8) | rdata_gr[1];
            rdata_gr[0] = 0x61;
            if (apdu.rlen - apdu.ne >= 256) {
                rdata_gr[1] = 0;
            }
            else {
                rdata_gr[1] = (uint8_t)(apdu.rlen - apdu.ne);
            }
#ifdef USB_ITF_HID
            if (itf == ITF_HID_CTAP) {
                driver_exec_finished_cont_hid(itf, (uint16_t)(apdu.ne + 2), (uint16_t)(rdata_gr - apdu.ne - apdu.rdata));
            }
#endif
#ifdef USB_ITF_CCID
            if (itf == ITF_SC_CCID || itf == ITF_SC_WCID) {
                driver_exec_finished_cont_ccid(itf, (uint16_t)(apdu.ne + 2), (uint16_t)(rdata_gr - apdu.ne - apdu.rdata));
            }
#endif
            apdu.rlen -= (uint16_t)apdu.ne;
            response_pending = true;
        }
    }
    else {
        apdu.sw = 0;
        apdu.rlen = 0;
        rdata_gr = apdu.rdata;
        response_pending = false;
        return 1;
    }
    return 0;
}

uint16_t set_res_sw(uint8_t sw1, uint8_t sw2) {
    apdu.sw = make_uint16_be(sw1, sw2);
    if (sw1 != 0x90 && sw1 != 0x61) {
        res_APDU_size = 0;
    }
    return make_uint16_be(sw1, sw2);
}

void *apdu_thread(void *arg) {
    (void)arg;
    card_init_core1();
    while (1) {
        uint32_t m = 0;
        queue_remove_blocking(&usb_to_card_q, &m);
        uint32_t flag = m + 1;
        if (m != EV_CMD_AVAILABLE) {
            queue_add_blocking(&card_to_usb_q, &flag);
        }

        if (m == EV_VERIFY_CMD_AVAILABLE || m == EV_MODIFY_CMD_AVAILABLE) {
            set_res_sw(0x6f, 0x00);
            goto done;
        }
        else if (m == EV_EXIT) {
            break;
        }

#ifdef ENABLE_OTP_APP
        if (m == EV_OTP_CMD_AVAILABLE) {
            apdu_clear_response_buffer();
            otp_hid_execute_pending();
            finished_data_size = 0;
            flag = EV_EXEC_FINISHED;
            queue_add_blocking(&card_to_usb_q, &flag);
            continue;
        }
#endif
        process_apdu();

done:   ;
        apdu_finish();

        finished_data_size = apdu_next();
        flag = EV_EXEC_FINISHED;
        queue_add_blocking(&card_to_usb_q, &flag);
    }
    //printf("EXIT !!!!!!\n");
    if (current_app && current_app->unload) {
        current_app->unload();
        current_app = NULL;
    }
    apdu_clear_response_buffer();
    return NULL;
}

void apdu_finish(void) {
    if (response_buffer) {
        if (apdu.sw == 0x9000) apdu_copy_response_buffer();
        else apdu_clear_response_buffer();
    }
    put_uint16_be(apdu.sw, apdu.rdata + apdu.rlen);
    // timeout_stop();
}

uint16_t apdu_next(void) {
    if (apdu.sw != 0) {
        if (apdu.rlen <= apdu.ne) {
            response_pending = false;
            return apdu.rlen + 2;
        }
        else {
            rdata_gr = apdu.rdata + apdu.ne;
            rdata_bk = (rdata_gr[0] << 8) | rdata_gr[1];
            rdata_gr[0] = 0x61;
            if (apdu.rlen - apdu.ne >= 256) {
                rdata_gr[1] = 0;
            }
            else {
                rdata_gr[1] = (uint8_t)(apdu.rlen - apdu.ne);
            }
            apdu.rlen -= (uint16_t)apdu.ne;
            response_pending = true;
        }
        return (uint16_t)(apdu.ne + 2);
    }
    response_pending = false;
    return 0;
}

uint16_t apdu_limit_response(uint16_t size_next, uint16_t max_size) {
    if (apdu.sw == 0 || max_size < 2 || size_next <= max_size) {
        return size_next;
    }

    uint16_t ne = (uint16_t)(max_size - 2);
    if (apdu.rlen <= ne) {
        return size_next;
    }

    rdata_gr = apdu.rdata + ne;
    rdata_bk = (rdata_gr[0] << 8) | rdata_gr[1];
    rdata_gr[0] = 0x61;
    if (apdu.rlen - ne >= 256) {
        rdata_gr[1] = 0;
    }
    else {
        rdata_gr[1] = (uint8_t)(apdu.rlen - ne);
    }
    apdu.rlen -= ne;
    response_pending = true;
    return max_size;
}

int bulk_cmd(int (*cmd)(void)) {
    uint8_t *p = apdu.data;
    uint8_t *rapdu = apdu.rdata;
    uint16_t rapdu_size = 0;
    uint8_t *top = apdu.data + apdu.nc;
    while (p < top) {
        P1(apdu) = p[0];
        P2(apdu) = p[1];
        apdu.nc = p[2];
        apdu.data = p + 3;
        *apdu.rdata++ = p[0];
        *apdu.rdata++ = p[1];
        *apdu.rdata++ = 0;
        *apdu.rdata++ = 0;
        apdu.rlen = 0;
        cmd();
        put_uint16_be(apdu.rlen, apdu.rdata - 2);
        put_uint16_be(apdu.sw, apdu.rdata + apdu.rlen);
        rapdu_size += 4 + apdu.rlen + 2;
        apdu.rdata += apdu.rlen + 2;
        p += 3 + apdu.nc;
    }
    apdu.rlen = rapdu_size;
    apdu.rdata = rapdu;
    return SW_OK();
}
