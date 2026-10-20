/* SPDX-License-Identifier: AGPL-3.0-only */
#include <assert.h>
#include <stdio.h>
#include "../src/fido/sign_counter.c"

static file_t counter_file;
file_t *ef_counter = &counter_file;
static uint8_t cached[4], persisted[4];
static uint32_t stored_size;
static bool read_failure, write_failure, sync_failure, partial_write, ambiguous_commit;
static unsigned reads, writes, commits;
bool file_has_data(const file_t *file) { return file && stored_size != 0; }
uint32_t file_get_size(const file_t *file) { assert(file == &counter_file); return stored_size; }
int file_read_at(const file_t *file, uint32_t offset, byte_array_t bytes) {
    assert(file == &counter_file && offset == 0 && bytes.len == 4);
    reads++;
    if (read_failure) return PICOKEYS_EXEC_ERROR;
    memcpy(bytes.data, cached, bytes.len);
    return PICOKEYS_OK;
}
int file_put_data(file_t *file, const_byte_array_t bytes) {
    assert(file == &counter_file && bytes.len == 4);
    writes++;
    if (partial_write) memcpy(cached, bytes.data, 2);
    if (write_failure) return PICOKEYS_EXEC_ERROR;
    memcpy(cached, bytes.data, bytes.len);
    return PICOKEYS_OK;
}
bool flash_commit_sync(uint32_t timeout_ms) {
    assert(timeout_ms > 0);
    commits++;
    if (!sync_failure || ambiguous_commit) memcpy(persisted, cached, sizeof(persisted));
    return !sync_failure;
}
static void power_cycle(void) {
    memcpy(cached, persisted, sizeof(cached));
    counter_storage_fault = false;
    read_failure = write_failure = sync_failure = partial_write = ambiguous_commit = false;
}
static void reset(uint32_t value) {
    put_uint32_le(value, persisted);
    stored_size = sizeof(persisted);
    ef_counter = &counter_file;
    reads = writes = commits = 0;
    power_cycle();
}
int main(void) {
    reset(7);
    uint32_t result = 999;
    assert(bump_sign_counter(&result) == PICOKEYS_OK && result == 8);
    assert(get_uint32_le(persisted) == 8 && writes == 1 && commits == 1);
    power_cycle();
    assert(get_sign_counter() == 8);
    assert(bump_sign_counter(&result) == PICOKEYS_OK && result == 9);
    for (unsigned failure = 0; failure < 4; failure++) {
        reset(7);
        write_failure = failure < 2;
        partial_write = failure == 1;
        sync_failure = failure >= 2;
        ambiguous_commit = failure == 3;
        result = 999;
        assert(bump_sign_counter(&result) != PICOKEYS_OK && result == 999);
        assert(counter_storage_fault);
        unsigned attempted_writes = writes;
        write_failure = sync_failure = false;
        assert(bump_sign_counter(&result) != PICOKEYS_OK && result == 999);
        assert(writes == attempted_writes);
        power_cycle();
        assert(bump_sign_counter(&result) == PICOKEYS_OK);
        assert(result == (failure == 3 ? 9u : 8u));
        assert(get_uint32_le(persisted) == result);
    }
    reset(UINT32_MAX);
    result = 999;
    assert(bump_sign_counter(&result) != PICOKEYS_OK && result == 999);
    assert(writes == 0 && commits == 0);
    reset(7);
    assert(bump_sign_counter(NULL) != PICOKEYS_OK && !counter_storage_fault);
    read_failure = true;
    assert(bump_sign_counter(&result) != PICOKEYS_OK && result == 999);
    assert(writes == 0 && commits == 0);
    read_failure = false;
    for (unsigned size = 0; size <= 5; size++) {
        if (size == 4) continue;
        stored_size = size;
        assert(bump_sign_counter(&result) != PICOKEYS_OK && result == 999);
    }
    ef_counter = NULL;
    assert(bump_sign_counter(&result) != PICOKEYS_OK && result == 999);
    puts("Signature counters are durable before release and never wrap");
    return 0;
}
