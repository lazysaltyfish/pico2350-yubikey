/* SPDX-License-Identifier: AGPL-3.0-only */
#include "picokeys.h"
#include "apdu.h"
#include "usb.h"
#include "otp_transport.h"
#include <assert.h>
#include <stdio.h>

uint8_t ITF_HID_KB=1, ITF_KEYBOARD=1;
static bool busy, completed;
static unsigned submitted, executed, buttons;
static size_t reply_size = 3;
static bool fail_command;
int otp_hid_button(uint8_t slot) { assert(busy && slot==2);buttons++;return 0; }
struct apdu apdu;
bool is_busy(void) { return busy; }
void *apdu_thread(void *arg) { return arg; }
void card_start(uint8_t itf, void *(*func)(void *)) {
    assert(!busy && itf==ITF_KEYBOARD && func==apdu_thread); busy=true;
}
void usb_send_event(uint32_t flag) { assert(flag==EV_OTP_CMD_AVAILABLE); submitted++; }
int card_status(uint8_t itf) {
    assert(itf==ITF_KEYBOARD);
    if (!completed) return PICOKEYS_ERR_FILE_NOT_FOUND;
    completed=false;busy=false;return PICOKEYS_OK;
}
void otp_hid_refresh_status(void) {
    const uint8_t status[]={0,8,2,1,9,3,0,0};otp_hid_update_status(status);
}
int otp_hid_command(uint8_t cmd,const uint8_t req[64],uint8_t response[70],size_t *len) {
    assert(busy && cmd==0x10 && req[0]==0x55);executed++;
    memset(response, 0x5a, MIN(reply_size, 70u));
    if (reply_size == 3) memcpy(response,"abc",3);
    *len=reply_size;return fail_command ? 0x6f00 : 0x9000;
}
static void finish(void) { otp_hid_execute_pending();completed=true;otp_hid_task(); }
static uint16_t crc(const uint8_t *p,size_t len) {
    uint16_t c=0xffff;
    for(size_t i=0;i<len;i++) { c^=p[i];for(unsigned b=0;b<8;b++) c=(c>>1)^((c&1)?0x8408:0); }
    return c;
}
static void submit(void) {
    uint8_t frame[70]={0x55},report[8];frame[64]=0x10;put_uint16_le(crc(frame,64),frame+65);
    for(unsigned seq=0;seq<10;seq++) {
        memcpy(report,frame+seq*7,7);report[7]=(uint8_t)(0x80|seq);
        assert(otp_hid_set_report_cb(1,0,HID_REPORT_TYPE_FEATURE,report,8)==1);
    }
}
int main(void) {
    uint8_t header[4]={0,0x87,0x11,0x9a},request[64]={1},response[128]={2};
    apdu=(struct apdu){.header=header,.data=request,.nc=64,.rdata=response,.rlen=37,.sw=0x9000};
    struct apdu before=apdu;
    uint8_t out[8];
    busy=true; /* A FIDO/PIV request owns the APDU worker. */
    submit();
    otp_hid_task();assert(submitted==0 && executed==0);
    assert(otp_hid_get_report_cb(1,0,HID_REPORT_TYPE_FEATURE,out,8)==8 && out[7]&0x20);
    assert(memcmp(&apdu,&before,sizeof(apdu))==0);
    busy=false;otp_hid_task();assert(submitted==1 && executed==0);
    /* Arriving reports cannot replace the already submitted request. */
    submit();
    assert(otp_hid_get_report_cb(1,0,HID_REPORT_TYPE_FEATURE,out,7)==0);
    assert(memcmp(&apdu,&before,sizeof(apdu))==0);
    finish();assert(executed==1);
    assert(otp_hid_get_report_cb(1,0,HID_REPORT_TYPE_FEATURE,out,8)==8);
    assert(memcmp(out,"abc",3)==0 && out[7]==0x40);
    assert(otp_hid_get_report_cb(1,0,HID_REPORT_TYPE_FEATURE,out,8)==8 && out[7]==0x40);
    assert(otp_hid_get_report_cb(1,0,HID_REPORT_TYPE_FEATURE,out,8)==8 && out[4]==9);
    submit();otp_hid_task();
    uint8_t reset[8]={0};reset[7]=0xff;
    assert(otp_hid_set_report_cb(1,0,HID_REPORT_TYPE_FEATURE,reset,8)==1);
    finish();
    assert(otp_hid_get_report_cb(1,0,HID_REPORT_TYPE_FEATURE,out,8)==8 && out[7]==0);
    assert(memcmp(&apdu,&before,sizeof(apdu))==0);
    assert(otp_hid_queue_button(2)==0);
    otp_hid_task();assert(buttons==0);
    finish();assert(buttons==1);
    assert(memcmp(&apdu,&before,sizeof(apdu))==0);

    unsigned previous = submitted;
    uint8_t report[8] = {0}, guarded[10];
    memset(guarded, 0xa5, sizeof(guarded));
    assert(otp_hid_get_report_cb(1,0,HID_REPORT_TYPE_FEATURE,guarded+1,7)==0);
    for (size_t i=0;i<sizeof(guarded);i++) assert(guarded[i]==0xa5);
    for (unsigned len=0;len<=9;len++) {
        if (len==8) continue;
        assert(otp_hid_set_report_cb(1,0,HID_REPORT_TYPE_FEATURE,report,(uint16_t)len)==1);
    }
    assert(otp_hid_set_report_cb(99,0,HID_REPORT_TYPE_FEATURE,report,8)==0);
    assert(otp_hid_set_report_cb(1,0,HID_REPORT_TYPE_INPUT,report,8)==0);
    /* A lone final frame must not replay the previous receive buffer. */
    uint8_t previous_frame[64] = {0x55};
    report[1]=0x10;
    put_uint16_le(crc(previous_frame,sizeof(previous_frame)),report+2);
    report[7]=0x89;
    assert(otp_hid_set_report_cb(1,0,HID_REPORT_TYPE_FEATURE,report,8)==1);
    otp_hid_task();assert(submitted==previous);

    /* yubikit skips all-zero intermediate reports (seq 1..8) between seq 0 and seq 9. */
    memset(report, 0, sizeof(report));
    report[0]=0x55;
    report[7]=0x80;
    assert(otp_hid_set_report_cb(1,0,HID_REPORT_TYPE_FEATURE,report,8)==1);
    memset(report, 0, sizeof(report));
    report[1]=0x10;
    put_uint16_le(crc(previous_frame,sizeof(previous_frame)),report+2);
    report[7]=0x89;
    assert(otp_hid_set_report_cb(1,0,HID_REPORT_TYPE_FEATURE,report,8)==1);
    otp_hid_task();assert(submitted==previous+1);
    finish();
    reply_size=68;
    submit();otp_hid_task();finish();
    for (unsigned seq=0;seq<10;seq++) {
        assert(otp_hid_get_report_cb(1,0,HID_REPORT_TYPE_FEATURE,guarded+1,8)==8);
        assert(guarded[0]==0xa5 && guarded[9]==0xa5 && guarded[8]==(0x40|seq));
    }
    assert(otp_hid_get_report_cb(1,0,HID_REPORT_TYPE_FEATURE,out,8)==8 && out[7]==0x40);
    /* Oversized or failed applet results must never escape as OTP replies. */
    reply_size=70;
    submit();otp_hid_task();finish();
    assert(otp_hid_get_report_cb(1,0,HID_REPORT_TYPE_FEATURE,out,8)==8 && out[7]==0);
    reply_size=3;fail_command=true;
    submit();otp_hid_task();finish();
    assert(otp_hid_get_report_cb(1,0,HID_REPORT_TYPE_FEATURE,out,8)==8 && out[7]==0);
    puts("otp_transport_test: OK");return 0;
}
