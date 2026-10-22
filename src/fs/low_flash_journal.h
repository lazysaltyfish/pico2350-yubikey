/* Copyright (c) 2022 Pol Henarejos.
 * SPDX-License-Identifier: AGPL-3.0-only */
#ifndef LOW_FLASH_JOURNAL_H
#define LOW_FLASH_JOURNAL_H

#define TOTAL_FLASH_PAGES 6
#define JOURNAL_MAGIC 0x504A524Eu
#define JOURNAL_STATUS_EMPTY    0xFF
#define JOURNAL_STATUS_PENDING  0xFE
#define JOURNAL_STATUS_DONE     0xFC

PACK(
typedef struct {
    uint32_t magic;
    uintptr_t target_addr[TOTAL_FLASH_PAGES];
    uint8_t status;
    uint8_t reserved[3];
}) flash_journal_t;

static inline bool journal_target_valid(uintptr_t addr, uintptr_t data_start,
                                       uintptr_t data_end, uintptr_t rom_start,
                                       uintptr_t rom_end) {
    if (addr % FLASH_SECTOR_SIZE != 0) {
        return false;
    }
    /* Targets name whole sectors, including the sectors containing the
     * unaligned persistent-region bounds and its end-of-pool header. */
    uintptr_t rom_first_sector = rom_start & ~(uintptr_t)(FLASH_SECTOR_SIZE - 1);
    uintptr_t rom_last_sector = rom_end & ~(uintptr_t)(FLASH_SECTOR_SIZE - 1);
    return (addr >= data_start && addr < data_end) ||
           (addr >= rom_first_sector && addr <= rom_last_sector);
}

static inline bool journal_entry_header_valid(const flash_journal_t *entry,
                                             uintptr_t data_start, uintptr_t data_end,
                                             uintptr_t rom_start, uintptr_t rom_end) {
    if (entry->magic != JOURNAL_MAGIC) {
        return false;
    }
    bool has_target = false;
    for (int i = 0; i < TOTAL_FLASH_PAGES; i++) {
        uintptr_t addr = entry->target_addr[i];
        if (addr == 0 || addr == UINTPTR_MAX) {
            continue;
        }
        has_target = true;
        if (!journal_target_valid(addr, data_start, data_end, rom_start, rom_end)) {
            return false;
        }
    }
    return has_target;
}

#endif
