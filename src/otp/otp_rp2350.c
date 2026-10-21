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

#include <stdio.h>
#include <stdalign.h>
#include "picokeys.h"
#include "otp.h"
#include "otp_platform.h"
#include "secure_boot_key.h"

#include "pico/bootrom.h"
#include "hardware/structs/otp.h"
#include "hardware/regs/otp_data.h"

#include "random.h"
#include "mbedtls/ecdsa.h"

#define OTP_OLD_MKEK_ROW 0xEF0
#define OTP_OLD_DEVK_ROW 0xED0
#define OTP_MKEK_ROW     0xE90
#define OTP_DEVK_ROW     0xE80

#define OTP_KEY_1    OTP_MKEK_ROW
#define OTP_KEY_2    OTP_DEVK_ROW


static bool is_empty_buffer(const_byte_array_t buffer) {
    for (size_t i = 0; i < buffer.len; i++) {
        if (buffer.data[i] != 0x00) {
            return false;
        }
    }
    return true;
}

static int otp_write_data_mode(uint16_t row, const_byte_array_t data, bool is_ecc) {
    if (data.len > UINT16_MAX) {
        return BOOTROM_ERROR_INVALID_STATE;
    }
    otp_cmd_t cmd = { .flags = row | (is_ecc ? OTP_CMD_ECC_BITS : 0) | OTP_CMD_WRITE_BITS };
    uint32_t ret = rom_func_otp_access((uint8_t *)data.data, (uint16_t)data.len, cmd);
    if (ret) {
        printf("OTP Write failed with error: %lu\n", ret);
    }
    return ret;
}

static int otp_write_data(uint16_t row, const_byte_array_t data) {
    return otp_write_data_mode(row, data, true);
}

static int otp_write_data_raw(uint16_t row, const_byte_array_t data) {
    return otp_write_data_mode(row, data, false);
}

static const uint8_t* otp_buffer(uint16_t row) {
    volatile uint32_t *p = ((uint32_t *)(OTP_DATA_BASE + (row*2)));
    return (const uint8_t *)p;
}

static const uint8_t* otp_buffer_raw(uint16_t row) {
    volatile uint32_t *p = ((uint32_t *)(OTP_DATA_RAW_BASE + (row*4)));
    return (const uint8_t *)p;
}

static bool is_empty_otp_buffer(uint16_t row, uint16_t len) {
    return is_empty_buffer(CONST_BYTE_ARRAY(otp_buffer_raw(row), len * 2));
}

static bool is_invalidated_otp_buffer(uint16_t row, uint16_t len) {
    const uint8_t *raw = otp_buffer_raw(row);
    size_t raw_len = (size_t)len * 2u;
    for (size_t i = 0; i < raw_len; i++) {
        uint8_t expected = ((i & 3u) == 3u) ? 0x00u : 0xFFu;
        if (raw[i] != expected) {
            return false;
        }
    }
    return true;
}

static bool is_valid_otp_chaff(uint16_t row, uint16_t len) {
    const uint8_t *raw = otp_buffer_raw(row);
    const uint8_t *chaff = otp_buffer_raw(row + 32);
    size_t raw_len = (size_t)len * 2u;
    for (size_t i = 0; i < raw_len; i++) {
        uint8_t expected = ((i & 3u) == 3u) ? 0x00u : (uint8_t)(raw[i] ^ 0xFFu);
        if (chaff[i] != expected) {
            return false;
        }
    }
    return true;
}

static bool is_otp_locked_page(uint8_t page) {
    const uint8_t *lock1 = otp_buffer_raw(OTP_DATA_PAGE0_LOCK0_ROW + page * 2 + 1);
    return (lock1[0] == 0x3C && lock1[1] == 0x3C && lock1[2] == 0x3C);
}

static void otp_lock_page(uint8_t page) {
    if (!is_otp_locked_page(page)) {
        alignas(4) uint32_t value = 0x3c3c3c;
        otp_write_data_raw(OTP_DATA_PAGE0_LOCK0_ROW + page*2 + 1, CONST_BYTE_ARRAY((uint8_t *)&value, sizeof(value)));
    }

    otp_hw->sw_lock[page] = 0b1100;
}

static int otp_invalidate_key(uint16_t row, uint16_t len) {
    if (len == 0 || (len & 1u) != 0 || len > 32) {
        return BOOTROM_ERROR_INVALID_STATE;
    }
    if (is_empty_otp_buffer(row, len) || is_invalidated_otp_buffer(row, len)) {
        return BOOTROM_OK;
    }
    size_t rows = (size_t)len / 2u;
    alignas(4) uint32_t inval[16] = {0};
    for (size_t i = 0; i < rows; i++) {
        inval[i] = 0x00FFFFFFu;
    }
    int ret = otp_write_data_raw(row, CONST_BYTE_ARRAY((const uint8_t *)inval, rows * sizeof(uint32_t)));
    mbedtls_platform_zeroize(inval, sizeof(inval));
    if (ret == BOOTROM_OK && !is_invalidated_otp_buffer(row, len)) {
        return BOOTROM_ERROR_INVALID_STATE;
    }
    return ret;
}

static int otp_chaff(uint16_t row, uint16_t len) {
    if (len == 0 || (len & 1u) != 0 || len > 32) {
        return BOOTROM_ERROR_INVALID_STATE;
    }
    if (!is_empty_otp_buffer(row, len) && is_valid_otp_chaff(row, len)) {
        return BOOTROM_OK;
    }
    size_t raw_len = (size_t)len * 2u;
    const uint8_t *raw = otp_buffer_raw(row);
    alignas(4) uint32_t chaff_words[16] = {0};
    uint8_t *chaff = (uint8_t *)chaff_words;
    for (size_t i = 0; i < raw_len; i++) {
        chaff[i] = ((i & 3u) == 3u) ? 0x00u : (uint8_t)(raw[i] ^ 0xFFu);
    }
    int ret = otp_write_data_raw(row + 32, CONST_BYTE_ARRAY(chaff, raw_len));
    mbedtls_platform_zeroize(chaff_words, sizeof(chaff_words));
    if (ret == BOOTROM_OK && !is_valid_otp_chaff(row, len)) {
        return BOOTROM_ERROR_INVALID_STATE;
    }
    return ret;
}

static int otp_migrate_key(uint16_t new_row, uint16_t old_row, uint16_t len) {
    if (len == 0 || (len & 1u) != 0 || len > 32) {
        return BOOTROM_ERROR_INVALID_STATE;
    }
    if (is_empty_otp_buffer(old_row, len) || is_invalidated_otp_buffer(old_row, len)) {
        if (!is_empty_otp_buffer(new_row, len) && !is_valid_otp_chaff(new_row, len)) {
            return otp_chaff(new_row, len);
        }
        return BOOTROM_OK;
    }

    alignas(2) uint8_t new_key[32] = {0};
    memcpy(new_key, otp_buffer(old_row), len);
    int ret = BOOTROM_OK;
    if (is_empty_otp_buffer(new_row, len)) {
        ret = otp_write_data(new_row, CONST_BYTE_ARRAY(new_key, len));
    } else if (memcmp(otp_buffer(new_row), new_key, len) != 0) {
        for (uint16_t r = 0; r < len / 2u; r++) {
            if (is_empty_otp_buffer((uint16_t)(new_row + r), 2)) {
                ret = otp_write_data((uint16_t)(new_row + r), CONST_BYTE_ARRAY(new_key + r * 2u, 2));
                if (ret != BOOTROM_OK) {
                    break;
                }
            }
        }
    }
    if (ret == BOOTROM_OK && memcmp(otp_buffer(new_row), new_key, len) != 0) {
        ret = BOOTROM_ERROR_INVALID_STATE;
    }
    mbedtls_platform_zeroize(new_key, sizeof(new_key));

    if (ret == BOOTROM_OK) {
        ret = otp_chaff(new_row, len);
        if (ret != BOOTROM_OK) {
            printf("Error writing migrated OTP chaff [%d]\n", ret);
        }
    }
    if (ret == BOOTROM_OK) {
        ret = otp_invalidate_key(old_row, len);
        if (ret != BOOTROM_OK) {
            printf("Error invalidating old OTP key [%d]\n", ret);
        }
    }
    return ret;
}

static void otp_migrate_chaff(void) {
    otp_migrate_key(OTP_MKEK_ROW, OTP_OLD_MKEK_ROW, 32);
    otp_migrate_key(OTP_DEVK_ROW, OTP_OLD_DEVK_ROW, 32);
}

bool otp_platform_is_secure_boot_enabled(uint8_t *bootkey) {
    if (!PICO_SECURE_BOOT_KEY_CONFIGURED) {
        return false;
    }
    const uint8_t *crit1 = otp_buffer(OTP_DATA_CRIT1_ROW);
    if ((crit1[0] & (1 << OTP_DATA_CRIT1_SECURE_BOOT_ENABLE_LSB)) == 0) {
        return false;
    }
    const uint8_t *boot_flags1 = otp_buffer_raw(OTP_DATA_BOOT_FLAGS1_ROW);
    for (uint8_t bootkey_idx = 0; bootkey_idx < 4; bootkey_idx++) {
        if ((boot_flags1[0] & (1u << (bootkey_idx + OTP_DATA_BOOT_FLAGS1_KEY_VALID_LSB))) == 0 ||
            (boot_flags1[1] & (1u << bootkey_idx)) != 0) {
            continue;
        }
        const uint8_t *bootkey_row = otp_buffer(OTP_DATA_BOOTKEY0_0_ROW + 0x10 * bootkey_idx);
        if (memcmp(bootkey_row, pico_secure_boot_key_hash, sizeof(pico_secure_boot_key_hash)) == 0) {
            if (bootkey) {
                *bootkey = bootkey_idx;
            }
            return true;
        }
    }
    return false;
}

bool otp_platform_is_secure_boot_locked(void) {
    uint8_t bootkey_idx = 0xFF;
    if (otp_platform_is_secure_boot_enabled(&bootkey_idx) == false) {
        return false;
    }
    const uint8_t *boot_flags1 = otp_buffer_raw(OTP_DATA_BOOT_FLAGS1_ROW);
    if ((boot_flags1[1] & ((OTP_DATA_BOOT_FLAGS1_KEY_INVALID_BITS >> OTP_DATA_BOOT_FLAGS1_KEY_INVALID_LSB) & (~(1 << bootkey_idx)))) !=
        ((OTP_DATA_BOOT_FLAGS1_KEY_INVALID_BITS >> OTP_DATA_BOOT_FLAGS1_KEY_INVALID_LSB) & (~(1 << bootkey_idx)))) {
        return false;
    }
    const uint8_t *crit1 = otp_buffer_raw(OTP_DATA_CRIT1_ROW);
    if ((crit1[0] & (1 << OTP_DATA_CRIT1_DEBUG_DISABLE_LSB)) == 0
        || (crit1[0] & (1 << OTP_DATA_CRIT1_GLITCH_DETECTOR_ENABLE_LSB)) == 0
        || ((crit1[0] & (3 << OTP_DATA_CRIT1_GLITCH_DETECTOR_SENS_LSB)) != (3 << OTP_DATA_CRIT1_GLITCH_DETECTOR_SENS_LSB))) {
        return false;
    }
    return bootkey_idx != 0xFF;
}

int otp_platform_enable_secure_boot(uint8_t bootkey, bool secure_lock) {
    int ret = 0;

    if (!PICO_SECURE_BOOT_KEY_CONFIGURED || bootkey >= 4) {
        return PICOKEYS_WRONG_DATA;
    }

    uint16_t key_row = OTP_DATA_BOOTKEY0_0_ROW + 0x10 * bootkey;
    const uint8_t *boot_flags1 = otp_buffer_raw(OTP_DATA_BOOT_FLAGS1_ROW);
    if (boot_flags1[1] & (1u << bootkey)) {
        return PICOKEYS_WRONG_DATA;
    }

    alignas(2) uint8_t BOOTKEY[sizeof(pico_secure_boot_key_hash)];
    memcpy(BOOTKEY, pico_secure_boot_key_hash, sizeof(BOOTKEY));
    if (is_empty_otp_buffer(key_row, sizeof(BOOTKEY))) {
        PICOKEYS_CHECK(otp_write_data(key_row, CONST_BYTE_ARRAY(BOOTKEY, sizeof(BOOTKEY))));
    }
    if (memcmp(otp_buffer(key_row), BOOTKEY, sizeof(BOOTKEY)) != 0) {
        return PICOKEYS_WRONG_DATA;
    }
    alignas(4) uint8_t flagsb1[] = { boot_flags1[0] | (1 << (bootkey + OTP_DATA_BOOT_FLAGS1_KEY_VALID_LSB)), boot_flags1[1], boot_flags1[2], 0x00 };
    if (secure_lock) {
        flagsb1[1] |= ((OTP_DATA_BOOT_FLAGS1_KEY_INVALID_BITS >> OTP_DATA_BOOT_FLAGS1_KEY_INVALID_LSB) & (~(1 << bootkey)));
    }

    PICOKEYS_CHECK(otp_write_data_raw(OTP_DATA_BOOT_FLAGS1_ROW, CONST_BYTE_ARRAY(flagsb1, sizeof(flagsb1))));
    PICOKEYS_CHECK(otp_write_data_raw(OTP_DATA_BOOT_FLAGS1_R1_ROW, CONST_BYTE_ARRAY(flagsb1, sizeof(flagsb1))));
    PICOKEYS_CHECK(otp_write_data_raw(OTP_DATA_BOOT_FLAGS1_R2_ROW, CONST_BYTE_ARRAY(flagsb1, sizeof(flagsb1))));

    const uint8_t *crit1 = otp_buffer_raw(OTP_DATA_CRIT1_ROW);
    alignas(4) uint8_t flagsc1[] = { crit1[0] | (1 << OTP_DATA_CRIT1_SECURE_BOOT_ENABLE_LSB), crit1[1], crit1[2], 0x00 };
    if (secure_lock) {
        flagsc1[0] |= (1 << OTP_DATA_CRIT1_DEBUG_DISABLE_LSB);
        flagsc1[0] |= (1 << OTP_DATA_CRIT1_GLITCH_DETECTOR_ENABLE_LSB);
        flagsc1[0] |= (3 << OTP_DATA_CRIT1_GLITCH_DETECTOR_SENS_LSB);
    }
    PICOKEYS_CHECK(otp_write_data_raw(OTP_DATA_CRIT1_ROW, CONST_BYTE_ARRAY(flagsc1, sizeof(flagsc1))));
    PICOKEYS_CHECK(otp_write_data_raw(OTP_DATA_CRIT1_R1_ROW, CONST_BYTE_ARRAY(flagsc1, sizeof(flagsc1))));
    PICOKEYS_CHECK(otp_write_data_raw(OTP_DATA_CRIT1_R2_ROW, CONST_BYTE_ARRAY(flagsc1, sizeof(flagsc1))));
    PICOKEYS_CHECK(otp_write_data_raw(OTP_DATA_CRIT1_R3_ROW, CONST_BYTE_ARRAY(flagsc1, sizeof(flagsc1))));
    PICOKEYS_CHECK(otp_write_data_raw(OTP_DATA_CRIT1_R4_ROW, CONST_BYTE_ARRAY(flagsc1, sizeof(flagsc1))));
    PICOKEYS_CHECK(otp_write_data_raw(OTP_DATA_CRIT1_R5_ROW, CONST_BYTE_ARRAY(flagsc1, sizeof(flagsc1))));
    PICOKEYS_CHECK(otp_write_data_raw(OTP_DATA_CRIT1_R6_ROW, CONST_BYTE_ARRAY(flagsc1, sizeof(flagsc1))));
    PICOKEYS_CHECK(otp_write_data_raw(OTP_DATA_CRIT1_R7_ROW, CONST_BYTE_ARRAY(flagsc1, sizeof(flagsc1))));

    if (secure_lock) {
        const uint8_t *page1 = otp_buffer_raw(OTP_DATA_PAGE1_LOCK1_ROW);
        uint8_t page1v = page1[0] | (OTP_DATA_PAGE1_LOCK1_LOCK_BL_VALUE_READ_ONLY << OTP_DATA_PAGE1_LOCK1_LOCK_BL_LSB);
        alignas(4) uint8_t flagsp1[] = { page1v, page1v, page1v, 0x00 };
        PICOKEYS_CHECK(otp_write_data_raw(OTP_DATA_PAGE1_LOCK1_ROW, CONST_BYTE_ARRAY(flagsp1, sizeof(flagsp1))));
        const uint8_t *page2 = otp_buffer_raw(OTP_DATA_PAGE2_LOCK1_ROW);
        uint8_t page2v = page2[0] | (OTP_DATA_PAGE2_LOCK1_LOCK_BL_VALUE_READ_ONLY << OTP_DATA_PAGE2_LOCK1_LOCK_BL_LSB);
        alignas(4) uint8_t flagsp2[] = { page2v, page2v, page2v, 0x00 };
        PICOKEYS_CHECK(otp_write_data_raw(OTP_DATA_PAGE2_LOCK1_ROW, CONST_BYTE_ARRAY(flagsp2, sizeof(flagsp2))));
    }

    goto err;
err:
    if (ret != PICOKEYS_OK) {
        return ret;
    }
    return PICOKEYS_OK;
}

void otp_platform_init(const uint8_t **otp_key_1_out, const uint8_t **otp_key_2_out) {
    *otp_key_1_out = NULL;
    *otp_key_2_out = NULL;

    otp_migrate_chaff();

    int ret = 0;
    bool key1_ok = false;
    bool key2_ok = false;

    if (is_empty_otp_buffer(OTP_KEY_1, 32)) {
        alignas(2) uint8_t mkek[32] = {0};
        if (random_fill_buffer(BYTE_ARRAY(mkek, sizeof(mkek))) == PICOKEYS_OK &&
            !is_empty_buffer(CONST_BYTE_ARRAY(mkek, sizeof(mkek)))) {
            ret = otp_write_data(OTP_KEY_1, CONST_BYTE_ARRAY(mkek, sizeof(mkek)));
            if (ret == BOOTROM_OK && memcmp(otp_buffer(OTP_KEY_1), mkek, sizeof(mkek)) != 0) {
                ret = BOOTROM_ERROR_INVALID_STATE;
            }
            if (ret != BOOTROM_OK) {
                printf("Error writing OTP key 1 [%d]\n", ret);
            } else {
                ret = otp_chaff(OTP_KEY_1, 32);
                if (ret != BOOTROM_OK) {
                    printf("Error writing OTP key 1 chaff [%d]\n", ret);
                } else {
                    key1_ok = true;
                }
            }
        } else {
            printf("Error generating OTP key 1\n");
        }
        mbedtls_platform_zeroize(mkek, sizeof(mkek));
    } else {
        ret = otp_chaff(OTP_KEY_1, 32);
        if (ret != BOOTROM_OK) {
            printf("Error writing OTP key 1 chaff [%d]\n", ret);
        } else {
            key1_ok = true;
        }
    }
    if (!is_empty_otp_buffer(OTP_KEY_1, 32)) {
        *otp_key_1_out = otp_buffer(OTP_KEY_1);
    }

    if (is_empty_otp_buffer(OTP_KEY_2, 32)) {
        mbedtls_ecdsa_context ecdsa;
        size_t olen = 0;
        alignas(2) uint8_t pkey[MBEDTLS_ECP_MAX_BYTES] = {0};
        int gen_ret = -1;
        for (int attempt = 0; attempt < 8 && olen != 32; attempt++) {
            olen = 0;
            mbedtls_ecdsa_init(&ecdsa);
            gen_ret = mbedtls_ecdsa_genkey(&ecdsa, MBEDTLS_ECP_DP_SECP256K1, random_fill_iterator, NULL);
            if (gen_ret == 0) {
                gen_ret = mbedtls_ecp_write_key_ext(&ecdsa, &olen, pkey, sizeof(pkey));
            }
            mbedtls_ecdsa_free(&ecdsa);
            if (gen_ret != 0) {
                break;
            }
        }
        if (gen_ret == 0 && olen == 32 && !is_empty_buffer(CONST_BYTE_ARRAY(pkey, 32))) {
            ret = otp_write_data(OTP_KEY_2, CONST_BYTE_ARRAY(pkey, olen));
            if (ret == BOOTROM_OK && memcmp(otp_buffer(OTP_KEY_2), pkey, olen) != 0) {
                ret = BOOTROM_ERROR_INVALID_STATE;
            }
            if (ret != BOOTROM_OK) {
                printf("Error writing OTP key 2 [%d]\n", ret);
            } else {
                ret = otp_chaff(OTP_KEY_2, 32);
                if (ret != BOOTROM_OK) {
                    printf("Error writing OTP key 2 chaff [%d]\n", ret);
                } else {
                    key2_ok = true;
                }
            }
        } else {
            printf("Error generating OTP key 2 [%d]\n", gen_ret);
        }
        mbedtls_platform_zeroize(pkey, sizeof(pkey));
    } else {
        ret = otp_chaff(OTP_KEY_2, 32);
        if (ret != BOOTROM_OK) {
            printf("Error writing OTP key 2 chaff [%d]\n", ret);
        } else {
            key2_ok = true;
        }
    }
    if (!is_empty_otp_buffer(OTP_KEY_2, 32)) {
        *otp_key_2_out = otp_buffer(OTP_KEY_2);
    }

    if (key1_ok && key2_ok) {
        otp_lock_page(OTP_KEY_1 >> 6);
    }
}
