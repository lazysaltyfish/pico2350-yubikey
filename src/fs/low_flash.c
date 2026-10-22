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
#include "serial.h"
#include "crypto_utils.h"
#include "pico_time.h"
#include <stdio.h>
#include "hardware/flash.h"
#include "hardware/sync.h"
#include "pico/mutex.h"
#include "pico/sem.h"
#include "pico/multicore.h"
#include "pico/bootrom.h"
#include "boot/picobin.h"
#include "low_flash_journal.h"

extern uint32_t FLASH_SIZE_BYTES;

#define FLASH_CACHE_FLUSH_TIMEOUT_MS 5000u

extern const uintptr_t start_data_pool;
extern const uintptr_t end_data_pool;
extern const uintptr_t start_rom_pool;
extern const uintptr_t end_rom_pool;

PACK(
typedef struct page_flash {
    uint8_t page[FLASH_SECTOR_SIZE];
    uintptr_t address;
    bool ready;
    bool erase;
    size_t page_size; //this param is for easy erase. It allows to erase with a single call. IT DOES NOT APPLY TO WRITE
}) page_flash_t;

static page_flash_t flash_pages[TOTAL_FLASH_PAGES];

static mutex_t mtx_flash;

static volatile bool locked_out = false;

static uint8_t ready_pages = 0;

bool flash_available = false;

//this function has to be called from the core 0
void low_flash_task(void);
void low_flash_commit(void);
bool low_flash_commit_sync(uint32_t timeout_ms);
extern uintptr_t last_base;

static uint8_t data_page[FLASH_PAGE_SIZE];

static uint16_t journal_slot = 0;
static uintptr_t last_journal_sector = 0x0;
_Static_assert(sizeof(flash_journal_t) == 32, "flash_journal_t must be 32 bytes");
_Static_assert(JOURNAL_STATUS_EMPTY == 0xFF, "");
_Static_assert((JOURNAL_STATUS_PENDING & JOURNAL_STATUS_EMPTY) == JOURNAL_STATUS_PENDING, "");
_Static_assert((JOURNAL_STATUS_DONE & JOURNAL_STATUS_PENDING) == JOURNAL_STATUS_DONE, "");
static bool journal_pending = false, journal_finalize_pending = false;
static uintptr_t pending_journal_addr;

#define FLASH_SECTOR(x) ((x) & -FLASH_SECTOR_SIZE)
#define FLASH_LOCKOUT_TIMEOUT_US 50000u

static int do_flash_op_erase(uintptr_t addr) {
    if (locked_out && multicore_lockout_start_timeout_us(FLASH_LOCKOUT_TIMEOUT_US) == false) {
        printf("WARN: FLASH LOCKOUT START TIMEOUT\n");
        return PICOKEYS_ERR_NO_MEMORY;
    }
    uint32_t ints = save_and_disable_interrupts();
    flash_range_erase(addr - XIP_BASE, FLASH_SECTOR_SIZE);
    restore_interrupts(ints);
    if (locked_out && multicore_lockout_end_timeout_us(FLASH_LOCKOUT_TIMEOUT_US) == false) {
        printf("WARN: FLASH LOCKOUT END TIMEOUT\n");
        return PICOKEYS_EXEC_ERROR;
    }
    return PICOKEYS_OK;
}

static int do_flash_op_program(uintptr_t addr, const uint8_t *data, size_t size) {
    if (locked_out && multicore_lockout_start_timeout_us(FLASH_LOCKOUT_TIMEOUT_US) == false) {
        printf("WARN: FLASH LOCKOUT START TIMEOUT\n");
        return PICOKEYS_ERR_NO_MEMORY;
    }
    uint32_t ints = save_and_disable_interrupts();
    flash_range_program(addr - XIP_BASE, data, size);
    restore_interrupts(ints);
    if (locked_out && multicore_lockout_end_timeout_us(FLASH_LOCKOUT_TIMEOUT_US) == false) {
        printf("WARN: FLASH LOCKOUT END TIMEOUT\n");
        return PICOKEYS_EXEC_ERROR;
    }
    return PICOKEYS_OK;
}

static int do_flash_op_erase_program(uintptr_t addr, const uint8_t *data, size_t size) {
    if (locked_out && multicore_lockout_start_timeout_us(FLASH_LOCKOUT_TIMEOUT_US) == false) {
        printf("WARN: FLASH LOCKOUT START TIMEOUT\n");
        return PICOKEYS_ERR_NO_MEMORY;
    }
    uint32_t ints = save_and_disable_interrupts();
    flash_range_erase(addr - XIP_BASE, FLASH_SECTOR_SIZE);
    flash_range_program(addr - XIP_BASE, data, size);
    restore_interrupts(ints);
    if (locked_out && multicore_lockout_end_timeout_us(FLASH_LOCKOUT_TIMEOUT_US) == false) {
        printf("WARN: FLASH LOCKOUT END TIMEOUT\n");
        return PICOKEYS_EXEC_ERROR;
    }
    return PICOKEYS_OK;
}

static int journal_mark_done(void) {
    uint8_t *journal_data = data_page;
    memset(journal_data, 0xFF, sizeof(data_page));
    size_t entry_offset = (journal_slot * sizeof(flash_journal_t)) % FLASH_PAGE_SIZE;
    flash_journal_t *journal_entry = (flash_journal_t *)(journal_data + entry_offset);
    journal_entry->status = JOURNAL_STATUS_DONE;
    int ret = do_flash_op_program(pending_journal_addr, journal_data, FLASH_PAGE_SIZE);
    if (ret == PICOKEYS_ERR_NO_MEMORY) {
        return ret;
    }
    journal_pending = false;
    journal_finalize_pending = false;
    journal_slot = (journal_slot + 1) % (FLASH_SECTOR_SIZE / sizeof(flash_journal_t));
    return ret;
}

void low_flash_task(void) {
    if (mutex_try_enter(&mtx_flash, NULL) == true) {
        if (journal_finalize_pending) {
            int ret = journal_mark_done();
            if (ret == PICOKEYS_ERR_NO_MEMORY) {
                printf("WARN: FLASH JOURNAL DONE WRITE FAILED\n");
                goto out;
            }
            if (ret != PICOKEYS_OK) {
                printf("WARN: FLASH LOCKOUT END TIMEOUT AFTER JOURNAL DONE\n");
            }
        }
        if (flash_available == true && ready_pages > 0) {
            //printf(" DO_FLASH AVAILABLE\n");
            uintptr_t journal_sector = FLASH_SECTOR(last_base) - FLASH_SECTOR_SIZE;
            if (!journal_pending) {
                if (journal_sector < start_data_pool + FLASH_SECTOR_SIZE) {
                    printf("WARN: FLASH JOURNAL SECTOR OUT OF RANGE\n");
                    goto out;
                }
                uintptr_t redo_sector = journal_sector - FLASH_SECTOR_SIZE;
                if (journal_sector != last_journal_sector || journal_slot == 0) {
                    int ret = do_flash_op_erase(journal_sector);
                    if (ret == PICOKEYS_ERR_NO_MEMORY) {
                        printf("WARN: FLASH JOURNAL ERASE FAILED\n");
                        goto out;
                    }
                    if (ret != PICOKEYS_OK) {
                        printf("WARN: FLASH LOCKOUT END TIMEOUT AFTER JOURNAL ERASE\n");
                    }
                    last_journal_sector = journal_sector;
                    journal_slot = 0;
                }
                uintptr_t addr_journal = journal_sector + (journal_slot * sizeof(flash_journal_t) / FLASH_PAGE_SIZE) * FLASH_PAGE_SIZE;
                uint8_t *journal_data = data_page;
                memset(journal_data, 0xFF, sizeof(data_page));
                flash_journal_t *journal_entry = (flash_journal_t *)(journal_data + journal_slot * sizeof(flash_journal_t) % FLASH_PAGE_SIZE);
                journal_entry->magic = JOURNAL_MAGIC;
                for (int i = 0; i < TOTAL_FLASH_PAGES; i++) {
                    if (flash_pages[i].ready == true) {
                        uintptr_t redo_offset = i * FLASH_SECTOR_SIZE;
                        if (redo_sector < start_data_pool + redo_offset) {
                            printf("WARN: FLASH REDO SECTOR OUT OF RANGE\n");
                            goto out;
                        }
                        uintptr_t redo_addr = redo_sector - redo_offset;
                        int ret = do_flash_op_erase_program(redo_addr, flash_pages[i].page, FLASH_SECTOR_SIZE);
                        if (ret == PICOKEYS_ERR_NO_MEMORY) {
                            printf("WARN: FLASH JOURNAL WRITE FAILED\n");
                            goto out;
                        }
                        if (ret != PICOKEYS_OK) {
                            printf("WARN: FLASH LOCKOUT END TIMEOUT AFTER JOURNAL WRITE\n");
                        }
                        journal_entry->target_addr[i] = flash_pages[i].address;
                    }
                }
                // Two-step write to ensure that the journal entry is not marked as pending until the journal is complete
                journal_entry->status = JOURNAL_STATUS_EMPTY;
                int ret = do_flash_op_program(addr_journal, journal_data, FLASH_PAGE_SIZE);
                if (ret == PICOKEYS_ERR_NO_MEMORY) {
                    printf("WARN: FLASH JOURNAL WRITE FAILED\n");
                    goto out;
                }
                if (ret != PICOKEYS_OK) {
                    printf("WARN: FLASH JOURNAL WRITE FAILED\n");
                }
                memset(journal_data, 0xFF, sizeof(data_page));
                journal_entry->status = JOURNAL_STATUS_PENDING;
                ret = do_flash_op_program(addr_journal, journal_data, FLASH_PAGE_SIZE);
                if (ret == PICOKEYS_ERR_NO_MEMORY) {
                    printf("WARN: FLASH JOURNAL WRITE FAILED\n");
                    goto out;
                }
                journal_pending = true;
                pending_journal_addr = addr_journal;
                if (ret != PICOKEYS_OK) {
                    printf("WARN: FLASH JOURNAL WRITE FAILED\n");
                }
            }
            bool transaction_ok = true;
            for (int r = 0; r < TOTAL_FLASH_PAGES; r++) {
                if (flash_pages[r].ready == true) {
                    int ret = do_flash_op_erase_program(flash_pages[r].address, flash_pages[r].page, FLASH_SECTOR_SIZE);
                    if (ret == PICOKEYS_ERR_NO_MEMORY) {
                        printf("WARN: FLASH WRITE FAILED\n");
                        transaction_ok = false;
                        break;
                    }
                    if (ret != PICOKEYS_OK) {
                        printf("WARN: FLASH LOCKOUT END TIMEOUT AFTER FLASH WRITE\n");
                    }
                    flash_pages[r].ready = false;
                    ready_pages--;
                }
                else if (flash_pages[r].erase == true) {
                    int ret = do_flash_op_erase(flash_pages[r].address);
                    if (ret == PICOKEYS_ERR_NO_MEMORY) {
                        printf("WARN: FLASH ERASE FAILED\n");
                        continue;
                    }
                    if (ret != PICOKEYS_OK) {
                        printf("WARN: FLASH LOCKOUT END TIMEOUT AFTER FLASH ERASE\n");
                    }
                    flash_pages[r].erase = false;
                    ready_pages--;
                }
            }
            if (transaction_ok == true && ready_pages == 0) {
                journal_finalize_pending = true;
                int ret = journal_mark_done();
                if (ret == PICOKEYS_ERR_NO_MEMORY) {
                    printf("WARN: FLASH JOURNAL DONE WRITE FAILED\n");
                    goto out;
                }
                if (ret != PICOKEYS_OK) {
                    printf("WARN: FLASH LOCKOUT END TIMEOUT AFTER JOURNAL DONE\n");
                }
            }
            if (ready_pages != 0) {
                printf("ERROR: DO FLASH DOES NOT HAVE ZERO PAGES\n");
            }

        }
        if (ready_pages == 0) {
            flash_available = false;
        }
        out:
        mutex_exit(&mtx_flash);
    }
}

static bool journal_entry_is_erased(const flash_journal_t *entry) {
    const uint8_t *p = (const uint8_t *) entry;
    for (size_t i = 0; i < sizeof(*entry); i++) {
        if (p[i] != 0xFF) {
            return false;
        }
    }
    return true;
}

static bool journal_entry_valid_at(const flash_journal_t *entry, uintptr_t journal_sector) {
    if (!journal_entry_header_valid(entry, start_data_pool, end_data_pool,
                                   start_rom_pool, end_rom_pool)) {
        return false;
    }
    if (entry->status != JOURNAL_STATUS_PENDING && entry->status != JOURNAL_STATUS_DONE) {
        return false;
    }
    for (int i = 0; i < TOTAL_FLASH_PAGES; i++) {
        uintptr_t target = entry->target_addr[i];
        if (target == 0 || target == UINTPTR_MAX) {
            continue;
        }
        uintptr_t redo_offset = (i + 1) * FLASH_SECTOR_SIZE;
        if (journal_sector < start_data_pool + redo_offset) {
            return false;
        }
    }
    return true;
}

int low_flash_recover_journal(bool force) {
    uintptr_t journal_sector = FLASH_SECTOR(last_base) - FLASH_SECTOR_SIZE;
    if (journal_sector < start_data_pool) {
        printf("WARN: FLASH JOURNAL SECTOR OUT OF RANGE\n");
        return PICOKEYS_ERR_MEMORY_FATAL;
    }
    bool journal_found = false;
    while (journal_sector >= start_data_pool) {
        uint8_t *sector_data = flash_read(journal_sector);
        flash_journal_t *candidate = NULL;
        uint16_t candidate_pos = 0;
        for (uint16_t pos = 0; pos + sizeof(flash_journal_t) <= FLASH_SECTOR_SIZE; pos += sizeof(flash_journal_t)) {
            flash_journal_t *entry = (flash_journal_t *)&sector_data[pos];
            if (journal_entry_is_erased(entry)) {
                break;
            }
            if (!journal_entry_valid_at(entry, journal_sector)) {
                continue;
            }
            journal_found = true;
            if (force) {
                candidate = entry;
                candidate_pos = pos;
                continue;
            }
            if (entry->status != JOURNAL_STATUS_PENDING) {
                continue;
            }
            candidate = entry;
            candidate_pos = pos;
            break;
        }
        if (candidate == NULL) {
            if (journal_sector < start_data_pool + FLASH_SECTOR_SIZE) {
                break;
            }
            if (journal_found == true) {
                printf("INFO: FLASH JOURNAL FOUND BUT IS DONE\n");
                return PICOKEYS_ERR_NO_MEMORY;
            }
            journal_sector -= FLASH_SECTOR_SIZE;
            continue;
        }

        for (int i = 0; i < TOTAL_FLASH_PAGES; i++) {
            uintptr_t target = candidate->target_addr[i];
            if (target == UINTPTR_MAX || target == 0x00000000) {
                continue;
            }
            if (!journal_target_valid(target, start_data_pool, end_data_pool,
                                      start_rom_pool, end_rom_pool)) {
                printf("WARN: FLASH JOURNAL TARGET ADDRESS OUT OF RANGE\n");
                return PICOKEYS_ERR_MEMORY_FATAL;
            }

            uintptr_t redo_offset = (i + 1) * FLASH_SECTOR_SIZE;
            if (journal_sector < start_data_pool + redo_offset) {
                printf("WARN: FLASH REDO SECTOR OUT OF RANGE\n");
                return PICOKEYS_ERR_MEMORY_FATAL;
            }
            uintptr_t redo = journal_sector - redo_offset;
            // We reuse the buffer. This function is called at the beginning, so no cache alive yet.
            // For first initialization, journal is found done.
            uint8_t *data_internal = flash_pages[i].page;
            memset(data_internal, 0xFF, sizeof(flash_pages[i].page));
            memcpy(data_internal, (const uint8_t *)redo, FLASH_SECTOR_SIZE);
            int ret = do_flash_op_erase_program(target, (const uint8_t *)data_internal, FLASH_SECTOR_SIZE);
            if (ret == PICOKEYS_ERR_NO_MEMORY) {
                printf("WARN: FLASH RESTORE FAILED\n");
                return PICOKEYS_EXEC_ERROR;
            }
            if (ret != PICOKEYS_OK) {
                printf("WARN: FLASH LOCKOUT END TIMEOUT DURING RESTORE\n");
            }
        }

        uint8_t *journal_data = data_page;
        memset(journal_data, 0xFF, sizeof(data_page));
        size_t entry_offset_in_page = candidate_pos % FLASH_PAGE_SIZE;
        flash_journal_t *new_entry = (flash_journal_t *)&journal_data[entry_offset_in_page];
        new_entry->status = JOURNAL_STATUS_DONE;
        uintptr_t page_addr = journal_sector + (candidate_pos / FLASH_PAGE_SIZE) * FLASH_PAGE_SIZE;
        int ret = do_flash_op_program(page_addr, journal_data, FLASH_PAGE_SIZE);
        if (ret == PICOKEYS_ERR_NO_MEMORY) {
            printf("WARN: FLASH JOURNAL WRITE FAILED\n");
            return PICOKEYS_EXEC_ERROR;
        }
        if (ret != PICOKEYS_OK) {
            printf("WARN: FLASH LOCKOUT END TIMEOUT AFTER JOURNAL DONE\n");
        }
        return PICOKEYS_OK;
    }
    return PICOKEYS_ERR_MEMORY_FATAL;
}

int low_flash_first_init(void) {
    uint8_t empty[sizeof(uintptr_t) + sizeof(uint32_t)];
    memset(empty, 0, sizeof(empty));

    flash_program_block(end_data_pool, CONST_BYTE_ARRAY(empty, sizeof(empty)));
    flash_program_block(end_rom_pool, CONST_BYTE_ARRAY(empty, sizeof(empty)));

    uintptr_t journal_sector = FLASH_SECTOR(end_data_pool) - FLASH_SECTOR_SIZE;
    if (journal_sector < start_data_pool) {
        return PICOKEYS_ERR_MEMORY_FATAL;
    }
    uint8_t journal_data[sizeof(flash_journal_t)];
    memset(journal_data, 0xFF, sizeof(journal_data));
    flash_journal_t *entry = (flash_journal_t *)journal_data;
    entry->magic = JOURNAL_MAGIC;
    entry->status = JOURNAL_STATUS_DONE;
    entry->target_addr[0] = FLASH_SECTOR(end_data_pool);
    flash_program_block(journal_sector, CONST_BYTE_ARRAY(journal_data, sizeof(journal_data)));
    last_journal_sector = journal_sector;
    journal_slot = 1;

    return PICOKEYS_OK;
}

//this function has to be called from the core 0
void low_flash_init(void) {
    memset(flash_pages, 0, sizeof(page_flash_t) * TOTAL_FLASH_PAGES);
    mutex_init(&mtx_flash);

    uint32_t data_start_addr;
    uint32_t data_end_addr;
    uint8_t txbuf[6] = {0x9f};
    uint8_t rxbuf[6] = {0};
    flash_do_cmd(txbuf, rxbuf, 4);

    FLASH_SIZE_BYTES = (1 << rxbuf[3]);
    __attribute__((aligned(4))) uint32_t workarea[1024];
    int rc = rom_load_partition_table((uint8_t *)workarea, sizeof(workarea), false);
    if (rc) {
        reset_usb_boot(0, 0);
    }

    uint8_t boot_partition = 1;
    rc = rom_get_partition_table_info(workarea, 0x8, PT_INFO_PARTITION_LOCATION_AND_FLAGS | PT_INFO_SINGLE_PARTITION | (boot_partition << 24));

    if (rc != 3) {
        data_start_addr = (FLASH_SIZE_BYTES >> 1);
        data_end_addr = FLASH_SIZE_BYTES;
    } else {
        uint16_t first_sector_number = (workarea[1] & PICOBIN_PARTITION_LOCATION_FIRST_SECTOR_BITS) >> PICOBIN_PARTITION_LOCATION_FIRST_SECTOR_LSB;
        uint16_t last_sector_number = (workarea[1] & PICOBIN_PARTITION_LOCATION_LAST_SECTOR_BITS) >> PICOBIN_PARTITION_LOCATION_LAST_SECTOR_LSB;
        data_start_addr = first_sector_number * FLASH_SECTOR_SIZE;
        data_end_addr = (last_sector_number + 1) * FLASH_SECTOR_SIZE;
        if (data_end_addr > FLASH_SIZE_BYTES) {
            data_end_addr = FLASH_SIZE_BYTES;
        }
    }
    data_end_addr -= 2 * FLASH_SECTOR_SIZE;

    data_start_addr += XIP_BASE;
    data_end_addr += XIP_BASE;
    flash_set_bounds(data_start_addr, data_end_addr);
}

void low_flash_init_core1(void) {
    mutex_enter_blocking(&mtx_flash);
    multicore_lockout_victim_init();
    locked_out = true;
    mutex_exit(&mtx_flash);
}

bool low_flash_is_core1_locked_out(void) {
    mutex_enter_blocking(&mtx_flash);
    bool active = locked_out;
    mutex_exit(&mtx_flash);
    return active;
}

void low_flash_wait_core1(void) {
    while (!low_flash_is_core1_locked_out()) {
        tight_loop_contents();
    }
}

void low_flash_stop_core1(void) {
    mutex_enter_blocking(&mtx_flash);
    multicore_reset_core1();
    locked_out = false;
    mutex_exit(&mtx_flash);
    low_flash_task();
}

void low_flash_commit(void) {
    mutex_enter_blocking(&mtx_flash);
    flash_available = true;
    mutex_exit(&mtx_flash);
}

static bool low_flash_available(void) {
    mutex_enter_blocking(&mtx_flash);
    bool available = flash_available;
    mutex_exit(&mtx_flash);
    return available;
}

bool low_flash_commit_sync(uint32_t timeout_ms) {
    // Core 0 owns low_flash_task(). Waiting for it from core 0 would prevent
    // the queued flash operation from ever being serviced.
    if (get_core_num() != 1) {
        return false;
    }
    low_flash_commit();

    uint32_t start = board_millis();
    while (low_flash_available()) {
        if (board_millis() - start >= timeout_ms) {
            return false;
        }
        tight_loop_contents();
    }
    return true;
}

static page_flash_t *find_free_page(uintptr_t addr) {
    uintptr_t addr_alg = FLASH_SECTOR(addr);

    /* Reuse an existing cached sector before taking an empty slot. */
    for (int r = 0; r < TOTAL_FLASH_PAGES; r++) {
        if ((flash_pages[r].ready || flash_pages[r].erase) && flash_pages[r].address == addr_alg) {
            if (flash_pages[r].erase) {
                flash_pages[r].erase = false;
                flash_pages[r].ready = true;
                flash_pages[r].page_size = 0;
            }
            return &flash_pages[r];
        }
    }

    for (int r = 0; r < TOTAL_FLASH_PAGES; r++) {
        if (!flash_pages[r].ready && !flash_pages[r].erase) {
            page_flash_t *p = &flash_pages[r];
            bool new_data_sector = addr_alg <= end_data_pool && addr_alg + FLASH_SECTOR_SIZE >= start_data_pool && addr_alg < FLASH_SECTOR(last_base) && addr_alg != FLASH_SECTOR(end_data_pool - 1);
            if (new_data_sector) {
                memset(p->page, 0xFF, FLASH_SECTOR_SIZE);
            }
            else {
                memcpy(p->page, (uint8_t *)addr_alg, FLASH_SECTOR_SIZE);
            }
            ready_pages++;
            p->address = addr_alg;
            p->ready = true;
            p->erase = false;
            p->page_size = 0;
            return p;
        }
    }
    return NULL;
}

int flash_program_block(uintptr_t addr, const_byte_array_t data) {
    if (!data.data || data.len == 0) {
        return PICOKEYS_ERR_NULL_PARAM;
    }

    while (data.len > 0) {
        size_t page_offset = addr & (FLASH_SECTOR_SIZE - 1);
        size_t chunk = MIN(data.len, FLASH_SECTOR_SIZE - page_offset);
        page_flash_t *p = NULL;

        mutex_enter_blocking(&mtx_flash);
        p = find_free_page(addr);
        if (p) {
            memcpy(&p->page[page_offset], data.data, chunk);
            mutex_exit(&mtx_flash);
            addr += chunk;
            data.data += chunk;
            data.len -= chunk;
            continue;
        }
        mutex_exit(&mtx_flash);

        /* Core 0 drains the six dirty sectors, then they can be reused. */
        if (!low_flash_commit_sync(FLASH_CACHE_FLUSH_TIMEOUT_MS)) {
            printf("ERROR: FLASH CACHE CANNOT BE DRAINED\n");
            return PICOKEYS_ERR_NO_MEMORY;
        }
    }
    return PICOKEYS_OK;
}

int flash_program_halfword(uintptr_t addr, uint16_t data) {
    return flash_program_block(addr, CONST_BYTE_ARRAY((const uint8_t *)&data, sizeof(uint16_t)));
}

int flash_program_word(uintptr_t addr, uint32_t data) {
    return flash_program_block(addr, CONST_BYTE_ARRAY((const uint8_t *)&data, sizeof(uint32_t)));
}

int flash_program_uintptr(uintptr_t addr, uintptr_t data) {
    return flash_program_block(addr, CONST_BYTE_ARRAY((const uint8_t *)&data, sizeof(uintptr_t)));
}

uint8_t *flash_read(uintptr_t addr) {
    uintptr_t addr_alg = FLASH_SECTOR(addr);
    mutex_enter_blocking(&mtx_flash);
    if (ready_pages > 0) {
        for (int r = 0; r < TOTAL_FLASH_PAGES; r++) {
            if (flash_pages[r].ready && flash_pages[r].address == addr_alg) {
                uint8_t *v = &flash_pages[r].page[addr & (FLASH_SECTOR_SIZE - 1)];
                mutex_exit(&mtx_flash);
                return v;
            }
        }
    }
    uint8_t *v = (uint8_t *) addr;
    mutex_exit(&mtx_flash);
    return v;
}

int flash_read_block(uintptr_t addr, byte_array_t data) {
    if (!data.data || data.len == 0) {
        return PICOKEYS_ERR_NULL_PARAM;
    }

    while (data.len > 0) {
        uintptr_t addr_alg = FLASH_SECTOR(addr);
        size_t page_offset = addr & (FLASH_SECTOR_SIZE - 1);
        size_t chunk = MIN(data.len, FLASH_SECTOR_SIZE - page_offset);
        const uint8_t *source = NULL;

        mutex_enter_blocking(&mtx_flash);
        for (int r = 0; r < TOTAL_FLASH_PAGES; r++) {
            if (flash_pages[r].ready && flash_pages[r].address == addr_alg) {
                source = &flash_pages[r].page[page_offset];
                break;
            }
        }
        if (!source) {
            source = (const uint8_t *)addr;
        }
        memcpy(data.data, source, chunk);
        mutex_exit(&mtx_flash);

        addr += chunk;
        data.data += chunk;
        data.len -= chunk;
    }
    return PICOKEYS_OK;
}

uintptr_t flash_read_uintptr(uintptr_t addr) {
    uint8_t p[sizeof(uintptr_t)];
    uintptr_t v = 0x0;

    flash_read_block(addr, BYTE_ARRAY(p, sizeof(p)));
    for (size_t i = 0; i < sizeof(uintptr_t); i++) {
        v |= (uintptr_t) p[i] << (8 * i);
    }
    return v;
}

uint16_t flash_read_uint16(uintptr_t addr) {
    uint8_t p[sizeof(uint16_t)];
    uint16_t v = 0x0;

    flash_read_block(addr, BYTE_ARRAY(p, sizeof(p)));
    for (size_t i = 0; i < sizeof(uint16_t); i++) {
        v |= p[i] << (8 * i);
    }
    return v;
}

uint32_t flash_read_uint32(uintptr_t addr) {
    uint8_t p[sizeof(uint32_t)];
    uint32_t v = 0x0;

    flash_read_block(addr, BYTE_ARRAY(p, sizeof(p)));
    for (size_t i = 0; i < sizeof(uint32_t); i++) {
        v |= (uint32_t)p[i] << (8 * i);
    }
    return v;
}

uint8_t flash_read_uint8(uintptr_t addr) {
    return *flash_read(addr);
}

int flash_erase_page(uintptr_t addr, size_t page_size) {
    page_flash_t *p = NULL;

    mutex_enter_blocking(&mtx_flash);
    if (ready_pages == TOTAL_FLASH_PAGES) {
        mutex_exit(&mtx_flash);
        printf("ERROR: ALL FLASH PAGES CACHED\n");
        return PICOKEYS_ERR_NO_MEMORY;
    }
    if (!(p = find_free_page(addr))) {
        printf("ERROR: FLASH CANNOT FIND A PAGE (rare error)\n");
        mutex_exit(&mtx_flash);
        return PICOKEYS_ERR_MEMORY_FATAL;
    }
    p->erase = true;
    p->ready = false;
    p->page_size = page_size;
    mutex_exit(&mtx_flash);

    return PICOKEYS_OK;
}

bool flash_check_blank(const_byte_array_t data) {
    const uint8_t *p_start = data.data;
    size_t size = data.len;
    const uint8_t *p;

    for (p = p_start; p < p_start + size; p++) {
        if (*p != 0xff) {
            return false;
        }
    }
    return true;
}

