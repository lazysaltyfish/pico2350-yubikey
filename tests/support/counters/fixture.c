/* SPDX-License-Identifier: AGPL-3.0-only */
#include "fixture.h"
#include "serial.h"
#include "files.h"
#include "button.h"
#include "fido.h"
#include "management.h"
#include "oath_container.h"
#include "otp_container.h"
#include "otp_transport.h"
#include "mbedtls/sha256.h"

#define FILE_COUNT 64
#define FILE_CAPACITY 2048
typedef struct { file_t file; uint8_t bytes[FILE_CAPACITY]; size_t size; } fixture_file_t;
typedef struct { uint16_t fid; uint8_t bytes[FILE_CAPACITY]; size_t size; } fixture_image_t;
static fixture_file_t cache[FILE_COUNT];
static fixture_image_t durable[FILE_COUNT];
static uint8_t header[4], status_snapshot[8];
struct apdu apdu;
unsigned fixture_core = 1, fixture_syncs, fixture_writes, fixture_deletes;
unsigned fixture_fail_sync, fixture_fail_write;
int fixture_fail_fid = -1, fixture_fail_delete = -1;
bool fixture_touch = true;
unsigned fixture_touch_calls, fixture_keyboards;
uint8_t fixture_keyboard[128], fixture_response[2048];
size_t fixture_keyboard_size;
void (*fixture_keyboard_hook)(void);
static const uint8_t root[32] = { 0x42 };
const uint8_t *otp_key_1 = root;
uint8_t pico_serial_hash[32];
char pico_serial_str[17] = "0123456789abcdef";
picokey_serial_t pico_serial;
bool is_nk;
volatile bool force_button_wait;
volatile uint32_t button_pressed_duration;
int (*button_pressed_cb)(uint8_t);
int (*hid_set_report_cb)(uint8_t, uint8_t, hid_report_type_t, uint8_t const *, uint16_t);
uint16_t (*hid_get_report_cb)(uint8_t, uint8_t, hid_report_type_t, uint8_t *, uint16_t);
unsigned get_core_num(void) { return fixture_core; }
uint32_t board_millis(void) { return 10000; }
bool check_user_presence(void) { return fixture_touch; }
uint32_t button_timeout_seconds(void) { return 0; }
int wait_button_pressed_timeout(uint32_t seconds) {
    assert(seconds == 15 && force_button_wait);
    fixture_touch_calls++;
    return fixture_touch ? 0 : 1;
}
int wait_button_pressed(void) { return fixture_touch ? 0 : 1; }
bool cap_supported(uint16_t cap) { return cap == CAP_OATH || cap == CAP_OTP; }
int register_app(int (*select)(app_t *, uint8_t), const uint8_t *aid) { (void)select; (void)aid; return 0; }
void scan_all(void) { assert(fixture_core == 1); }
int random_fill_buffer(byte_array_t out) {
    static uint8_t entropy = 1;
    for (size_t i = 0; i < out.len; i++) out.data[i] = entropy++;
    return PICOKEYS_OK;
}
uint16_t set_res_sw(uint8_t a, uint8_t b) {
    apdu.sw = ((uint16_t)a << 8) | b;
    if (a != 0x90 && a != 0x61) apdu.rlen = 0;
    return apdu.sw;
}
file_t *file_search(uint16_t fid) {
    for (size_t i = 0; i < FILE_COUNT; i++) if (cache[i].file.fid == fid) return &cache[i].file;
    return NULL;
}
file_t *file_new(uint16_t fid) {
    file_t *file = file_search(fid);
    if (file) return file;
    for (size_t i = 0; i < FILE_COUNT; i++) if (!cache[i].file.fid) {
        cache[i].file.fid = fid;
        return &cache[i].file;
    }
    return NULL;
}
file_t *file_search_by_fid(uint16_t fid, const file_t *parent, uint8_t type) {
    (void)parent; (void)type;
    return file_search(fid);
}
static fixture_file_t *entry(const file_t *file) {
    for (size_t i = 0; i < FILE_COUNT; i++) if (&cache[i].file == file) return &cache[i];
    return NULL;
}
bool file_has_data(const file_t *file) { fixture_file_t *f = entry(file); return f && f->size != 0; }
uint32_t file_get_size(const file_t *file) { fixture_file_t *f = entry(file); return f ? f->size : 0; }
uint8_t *file_get_data(const file_t *file) { fixture_file_t *f = entry(file); return f && f->size ? f->bytes : NULL; }
int file_read_at(const file_t *file, uint32_t offset, byte_array_t out) {
    fixture_file_t *f = entry(file);
    if (!f || offset > f->size || out.len > f->size - offset) return PICOKEYS_WRONG_LENGTH;
    memcpy(out.data, f->bytes + offset, out.len);
    return PICOKEYS_OK;
}
int file_put_data(file_t *file, const_byte_array_t bytes) {
    assert(fixture_core == 1);
    fixture_file_t *f = entry(file);
    fixture_writes++;
    if (!f || fixture_writes == fixture_fail_write || file->fid == fixture_fail_fid) return PICOKEYS_EXEC_ERROR;
    assert(bytes.len <= sizeof(f->bytes));
    memmove(f->bytes, bytes.data, bytes.len);
    f->size = bytes.len;
    file->data = f->size ? f->bytes : NULL;
    return PICOKEYS_OK;
}
int file_delete_no_commit(file_t *file) {
    assert(fixture_core == 1);
    if (!file) return PICOKEYS_OK;
    fixture_deletes++;
    if (file->fid == fixture_fail_delete) return PICOKEYS_EXEC_ERROR;
    fixture_file_t *f = entry(file);
    assert(f);
    f->size = 0;
    file->data = NULL;
    file->fid = 0;
    return PICOKEYS_OK;
}
int file_delete(file_t *file) { return file_delete_no_commit(file); }
int flash_clear_file(file_t *file) {
    if (!file) return PICOKEYS_OK;
    if (file->fid == fixture_fail_delete) return PICOKEYS_EXEC_ERROR;
    fixture_file_t *f = entry(file);
    assert(f);
    f->size = 0;
    file->data = NULL;
    return PICOKEYS_OK;
}
void file_for_each_dynamic(file_iter_cb callback, void *context) {
    for (size_t i = 0; i < FILE_COUNT; i++) if (cache[i].file.fid && cache[i].size && !callback(&cache[i].file, context)) break;
}
void flash_commit(void) { assert(fixture_core == 1); }
void fixture_persist(void) {
    for (size_t i = 0; i < FILE_COUNT; i++) {
        durable[i].fid = cache[i].file.fid;
        durable[i].size = cache[i].size;
        memcpy(durable[i].bytes, cache[i].bytes, sizeof(cache[i].bytes));
    }
}
bool flash_commit_sync(uint32_t timeout) {
    (void)timeout;
    assert(fixture_core == 1);
    fixture_syncs++;
    if (fixture_syncs == fixture_fail_sync) return false;
    fixture_persist();
    return true;
}
void fixture_reboot(void) {
    for (size_t i = 0; i < FILE_COUNT; i++) {
        cache[i].file.fid = durable[i].fid;
        cache[i].size = durable[i].size;
        memcpy(cache[i].bytes, durable[i].bytes, sizeof(cache[i].bytes));
        cache[i].file.data = cache[i].size ? cache[i].bytes : NULL;
    }
    fixture_syncs = fixture_writes = fixture_deletes = 0;
    fixture_fail_sync = fixture_fail_write = 0;
    fixture_fail_fid = fixture_fail_delete = -1;
    fixture_touch = true;
    fixture_touch_calls = fixture_keyboards = 0;
    fixture_keyboard_size = 0;
    fixture_keyboard_hook = NULL;
}
void fixture_reset(void) {
    memset(cache, 0, sizeof(cache));
    memset(durable, 0, sizeof(durable));
    durable[0].fid = EF_OTP_PIN;
    fixture_core = 1;
    force_button_wait = false;
    fixture_reboot();
}
void fixture_request(uint8_t ins, uint8_t p1, uint8_t p2, const uint8_t *data, size_t len) {
    header[0] = 0; header[1] = ins; header[2] = p1; header[3] = p2;
    memset(fixture_response, 0xa5, sizeof(fixture_response));
    apdu = (struct apdu){ .header = header, .data = (uint8_t *)data, .nc = len, .rdata = fixture_response, .ne = 256 };
}
void fixture_seed(uint16_t fid, const uint8_t *data, size_t len) {
    assert(file_put_data(file_new(fid), CONST_BYTE_ARRAY(data, len)) == 0);
    fixture_persist();
    fixture_syncs = fixture_writes = fixture_deletes = 0;
}
size_t fixture_durable(uint16_t fid, uint8_t *data, size_t capacity) {
    for (size_t i = 0; i < FILE_COUNT; i++) if (durable[i].fid == fid) {
        assert(durable[i].size <= capacity);
        memcpy(data, durable[i].bytes, durable[i].size);
        return durable[i].size;
    }
    return 0;
}
void add_keyboard_buffer(const_byte_array_t text, bool encode) {
    (void)encode;
    if (fixture_keyboard_hook) fixture_keyboard_hook();
    assert(text.len <= sizeof(fixture_keyboard));
    memcpy(fixture_keyboard, text.data, text.len);
    fixture_keyboard_size = text.len;
    fixture_keyboards++;
}
void append_keyboard_buffer(const_byte_array_t text) { (void)text; }
void otp_hid_update_status(const uint8_t status[8]) { memcpy(status_snapshot, status, 8); }
void otp_hid_copy_status(uint8_t status[8]) { memcpy(status, status_snapshot, 8); }
int otp_hid_queue_button(uint8_t slot) { (void)slot; return 0; }
int otp_hid_set_report_cb(uint8_t a, uint8_t b, hid_report_type_t c, const uint8_t *d, uint16_t e) { (void)a;(void)b;(void)c;(void)d;(void)e;return 0; }
uint16_t otp_hid_get_report_cb(uint8_t a, uint8_t b, hid_report_type_t c, uint8_t *d, uint16_t e) { (void)a;(void)b;(void)c;(void)d;(void)e;return 0; }
int man_set_mode(const uint8_t *data, uint16_t len) { (void)data;(void)len;return SW_OK(); }
int man_write_config(const uint8_t *data, uint16_t len) { (void)data;(void)len;return SW_OK(); }
int man_get_config(void) { return SW_OK(); }

/* Container interfaces are storage fixtures, not replicas of crypto or counter
 * algorithms. Existing container suites exercise their real persistence layer. */
static uint16_t payload_fid(uint16_t logical) { return logical + 0x2000u; }
static int container_write(uint16_t logical, const uint8_t *data, size_t size) {
    int ret = file_put_data(file_new(payload_fid(logical)), CONST_BYTE_ARRAY(data, size));
    if (ret != 0) return ret;
    static const uint8_t marker[] = { 'C', 'N', 'T', 1 };
    return file_put_data(file_new(logical), CONST_BYTE_ARRAY(marker, sizeof(marker)));
}
static bool container_marker(const file_t *file) { return file_has_data(file) && file_get_size(file) == 4 && !memcmp(file_get_data(file), "CNT\1", 4); }
static int container_delete(uint16_t logical) {
    int ret = file_delete_no_commit(file_search(payload_fid(logical)));
    return ret == 0 ? file_delete_no_commit(file_search(logical)) : ret;
}
bool oath_container_is_marker(const file_t *file) { return container_marker(file); }
bool oath_container_can_create(uint8_t slot) { return !file_has_data(file_search(EF_OATH_CRED + slot)); }
int oath_container_create(uint8_t slot, const uint8_t *data, size_t size, const uint8_t *metadata, size_t metadata_size) { (void)metadata;(void)metadata_size;return container_write(EF_OATH_CRED + slot,data,size); }
int oath_container_update(uint8_t slot, const uint8_t *data, size_t size, const uint8_t *metadata, size_t metadata_size) { return oath_container_create(slot,data,size,metadata,metadata_size); }
int oath_container_object_size(uint8_t slot, uint16_t type, uint32_t *size) { (void)type;*size=file_get_size(file_search(payload_fid(EF_OATH_CRED + slot)));return *size?0:PICOKEYS_ERR_FILE_NOT_FOUND; }
int oath_container_read(uint8_t slot, uint16_t type, byte_buffer_t *out) { (void)type;file_t*f=file_search(payload_fid(EF_OATH_CRED+slot));size_t n=file_get_size(f);if(!n||n>out->capacity)return PICOKEYS_ERR_FILE_NOT_FOUND;memcpy(out->data,file_get_data(f),n);out->len=n;return 0; }
int oath_container_delete(uint8_t slot) { return container_delete(EF_OATH_CRED+slot); }
int oath_container_purge(uint8_t slot) { return container_delete(EF_OATH_CRED+slot); }
bool otp_container_is_marker(const file_t *file) { return container_marker(file); }
bool otp_container_has_slot(uint8_t slot) { return file_has_data(file_search(payload_fid(EF_OTP_SLOT1+slot))); }
int otp_container_has_slot_status(uint8_t slot, bool *present) { *present=otp_container_has_slot(slot);return 0; }
int otp_container_read_slot(uint8_t slot, byte_buffer_t *out) { file_t*f=file_search(payload_fid(EF_OTP_SLOT1+slot));size_t n=file_get_size(f);if(!n||n>out->capacity)return PICOKEYS_ERR_FILE_NOT_FOUND;memcpy(out->data,file_get_data(f),n);out->len=n;return 0; }
int otp_container_write_slot(uint8_t slot,const uint8_t *data,size_t n,const uint8_t *m,size_t mn) { (void)m;(void)mn;return container_write(EF_OTP_SLOT1+slot,data,n); }
int otp_container_delete_slot(uint8_t slot) { return container_delete(EF_OTP_SLOT1+slot); }
int otp_container_purge(void) { for(unsigned i=0;i<4;i++){int r=container_delete(EF_OTP_SLOT1+i);if(r)return r;}return 0; }
int otp_container_swap_slots(uint8_t a,bool pa,const uint8_t*da,size_t na,const uint8_t*ma,size_t nma,uint8_t b,bool pb,const uint8_t*db,size_t nb,const uint8_t*mb,size_t nmb) {int r=pb?otp_container_write_slot(a,db,nb,mb,nmb):otp_container_delete_slot(a);if(r)return r;return pa?otp_container_write_slot(b,da,na,ma,nma):otp_container_delete_slot(b);}
