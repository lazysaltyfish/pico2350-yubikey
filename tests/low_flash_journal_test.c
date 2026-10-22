/* SPDX-License-Identifier: AGPL-3.0-only */
#include "picokeys.h"
#include <assert.h>
#include <stdio.h>

#define FLASH_SECTOR_SIZE 4096u
#include "fs/low_flash_journal.h"

/* RP2350 bounds from flash_set_bounds(): a 2 MiB storage partition with
 * two trailing sectors reserved, 8-byte pool headers and 16 KiB persistent data. */
static const uintptr_t data_start = 0x10200000u;
static const uintptr_t rom_end = 0x103fdff4u;
static const uintptr_t rom_start = 0x103f9ff4u;
static const uintptr_t data_end = 0x103f9fecu;

static bool valid_header(const flash_journal_t *entry) {
    return journal_entry_header_valid(entry, data_start, data_end, rom_start, rom_end);
}

static void test_persistent_and_mixed_targets(void) {
    const uintptr_t targets[] = {
        data_start, 0x103f9000u, /* first and last data sectors */
        0x103fa000u, 0x103fb000u, 0x103fc000u,
        0x103fd000u             /* end_rom_pool / ef_phy sector */
    };
    flash_journal_t entry;
    memset(&entry, 0xff, sizeof(entry));
    entry.magic = JOURNAL_MAGIC;
    entry.status = JOURNAL_STATUS_PENDING;
    for (size_t i = 0; i < sizeof(targets) / sizeof(targets[0]); i++) {
        entry.target_addr[i] = targets[i];
        assert(valid_header(&entry));
    }
    /* Persistent data may also occupy the sector containing rom_start. */
    assert(journal_target_valid(0x103f9000u, data_start, data_end, rom_start, rom_end));
    /* Exercise the persistent lower bound independently of the data range,
     * including a sector-aligned pool header at data_end. */
    assert(journal_target_valid(0x103f9000u, data_start, 0x103f9000u, rom_start, rom_end));
    entry.status = JOURNAL_STATUS_DONE;
    assert(valid_header(&entry));
}

static void test_reject_invalid_targets(void) {
    const uintptr_t invalid[] = {
        0x101ff000u, /* firmware, below the data pool */
        0x103fe000u, 0x103ff000u, /* reserved trailing sectors */
        0x10400000u, /* beyond flash */
        0x10200001u, 0x103fa001u, rom_start, rom_end /* unaligned */
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        for (size_t slot = 0; slot < TOTAL_FLASH_PAGES; slot++) {
            flash_journal_t entry;
            memset(&entry, 0xff, sizeof(entry));
            entry.magic = JOURNAL_MAGIC;
            entry.target_addr[0] = 0x103fd000u;
            entry.target_addr[slot] = invalid[i];
            assert(!valid_header(&entry));
        }
    }
    /* Distinct regions must not turn an intervening sector into a target. */
    assert(!journal_target_valid(0x10300000u, data_start, 0x10210000u,
                                 rom_start, rom_end));
}

static void test_empty_and_bad_magic(void) {
    flash_journal_t entry;
    memset(&entry, 0xff, sizeof(entry));
    entry.magic = JOURNAL_MAGIC;
    assert(!valid_header(&entry));
    memset(entry.target_addr, 0, sizeof(entry.target_addr));
    assert(!valid_header(&entry));
    entry.target_addr[5] = 0x103fd000u;
    assert(valid_header(&entry));
    entry.magic = 0;
    assert(!valid_header(&entry));
}

int main(void) {
    test_persistent_and_mixed_targets();
    test_reject_invalid_targets();
    test_empty_and_bad_magic();
    puts("Flash journal accepts persistent and mixed targets while rejecting invalid sectors");
    return 0;
}
