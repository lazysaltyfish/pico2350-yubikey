/* SPDX-License-Identifier: AGPL-3.0-only */
#include "picokeys.h"
#include "apdu.h"
#include "files.h"
#include <assert.h>
#include <stdio.h>

static int (*registered_select)(app_t *, uint8_t);
static const uint8_t *registered_aid;
struct apdu apdu;
int register_app(int (*select)(app_t *, uint8_t), const uint8_t *aid) {
    registered_select = select;
    registered_aid = aid;
    return PICOKEYS_OK;
}
uint16_t set_res_sw(uint8_t sw1, uint8_t sw2) {
    apdu.sw = make_uint16_be(sw1, sw2);
    if (sw1 != 0x90 && sw1 != 0x61) apdu.rlen = 0;
    return apdu.sw;
}

/* A future accidental write/reset fails even when no device is connected. */
file_t *file_new(uint16_t fid) { (void)fid; assert(!"Unexpected storage creation"); return NULL; }
int file_put_data(file_t *file, const_byte_array_t data) {
    (void)file; (void)data; assert(!"Unexpected storage write"); return PICOKEYS_EXEC_ERROR;
}
int file_delete_no_commit(file_t *file) {
    (void)file; assert(!"Unexpected storage deletion"); return PICOKEYS_EXEC_ERROR;
}
void flash_commit(void) { assert(!"Unexpected flash commit"); }

#include "../src/fido/securitydomain.c"

int main(void) {
    const uint8_t expected_aid[] = {8, 0xa0, 0, 0, 1, 0x51, 0, 0, 0};
    assert(registered_select && registered_aid);
    assert(memcmp(registered_aid, expected_aid, sizeof(expected_aid)) == 0);
    app_t app = {0};
    assert(registered_select(&app, 0) == PICOKEYS_ERR_FILE_NOT_FOUND);
    assert(registered_select(&app, 1) == PICOKEYS_ERR_FILE_NOT_FOUND);
    assert(!app.process_apdu && !app.unload);
    uint8_t header[4] = {0}, request[32] = {0}, response[64];
    memset(response, 0xa5, sizeof(response));
    for (unsigned ins = 0; ins <= UINT8_MAX; ins++) {
        header[1] = (uint8_t)ins;
        apdu = (struct apdu){.header=header, .data=request, .nc=sizeof(request),
                             .rdata=response, .rlen=sizeof(response)};
        assert(sd_process_apdu() == 0x6d00);
        assert(apdu.rlen == 0);
        for (size_t i = 0; i < sizeof(response); i++) assert(response[i] == 0xa5);
    }
    puts("Security Domain unsupported commands never mutate storage");
    return 0;
}
