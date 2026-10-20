/*
 * This file is part of the Pico FIDO distribution (https://github.com/polhenarejos/pico-fido).
 * Copyright (c) 2022 Pol Henarejos.
 * Copyright (c) 2026 lazysaltyfish.
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#include "picokeys.h"
#include "oath_put.h"
#include "tlv.h"
#include "mbedtls/platform_util.h"

#define TAG_NAME        0x71
#define TAG_KEY         0x73
#define TAG_PROPERTY    0x78
#define TAG_IMF         0x7a
#define OATH_TYPE_HOTP  0x10
#define OATH_TYPE_TOTP  0x20
#define OATH_TYPE_MASK  0xf0
#define ALG_HMAC_SHA1   0x01
#define ALG_HMAC_SHA256 0x02
#define ALG_HMAC_SHA512 0x03
#define ALG_MASK       0x0f

static bool oath_put_append(uint8_t *buf, size_t capacity, size_t *used,
                            const uint8_t *data, size_t len) {
    if (*used > capacity || len > capacity - *used) {
        return false;
    }
    if (len > 0) {
        memcpy(buf + *used, data, len);
    }
    *used += len;
    return true;
}

int oath_normalize_put_data(const uint8_t *in, size_t in_len,
                            uint8_t **out_buf, size_t *out_len) {
    if (out_buf) {
        *out_buf = NULL;
    }
    if (out_len) {
        *out_len = 0;
    }
    /* A singleton Property grows by one byte; an absent HOTP IMF adds ten.
     * A supplied IMF grows by at most eight instead. Rejecting duplicates
     * keeps the total expansion within this bound and the stored length in
     * uint16_t. Every append also checks the actual remaining capacity. */
    const size_t max_expansion = 11;
    if (!in || in_len == 0 || !out_buf || !out_len ||
        in_len > UINT16_MAX - max_expansion) {
        return PICOKEYS_ERR_NULL_PARAM;
    }
    const size_t capacity = in_len + max_expansion;
    uint8_t *buf = (uint8_t *)calloc(1, capacity);
    if (!buf) {
        return PICOKEYS_ERR_NO_MEMORY;
    }
    size_t rpos = 0;
    size_t wpos = 0;
    bool has_name = false;
    bool has_key = false;
    bool has_property = false;
    bool has_imf = false;
    uint8_t key_type_alg = 0;
    int ret = PICOKEYS_WRONG_DATA;

    while (rpos < in_len) {
        uint8_t tag = in[rpos];
        size_t rem = in_len - rpos;
        if (tag == TAG_PROPERTY) {
            if (has_property || rem < 2) {
                goto fail;
            }
            has_property = true;
            uint8_t prop_val;
            bool is_two_byte = rem == 2 || in[rpos + 1] != 0x01;
            /* Yubico's legacy Property is tag/value, including INC (0x01)
             * followed by a final IMF TLV. Also accept tag/length/value. */
            if (!is_two_byte && rem >= 4 && in[rpos + 2] == TAG_IMF &&
                (size_t)(4 + in[rpos + 3]) == rem) {
                is_two_byte = true;
            }
            if (is_two_byte) {
                prop_val = in[rpos + 1];
                rpos += 2;
            }
            else {
                prop_val = in[rpos + 2];
                rpos += 3;
            }
            const uint8_t property[] = { TAG_PROPERTY, 1, prop_val };
            if (!oath_put_append(buf, capacity, &wpos, property, sizeof(property))) {
                goto fail;
            }
            continue;
        }

        /* tlv_walk permits trailing tag-only markers for other OATH commands;
         * PUT requires an explicit, supported definite-length encoding. */
        size_t tag_len = (tag & 0x1f) == 0x1f ? 2 : 1;
        if (rem <= tag_len) {
            goto fail;
        }
        uint8_t length_octet = in[rpos + tag_len];
        if (length_octet >= 0x80 && length_octet != 0x81 && length_octet != 0x82) {
            goto fail;
        }
        uint8_t *p = (uint8_t *)(in + rpos);
        tlv_ctx_t sub_ctx = { .data = p, .len = (uint16_t)rem };
        tlv_item_t item;
        uint8_t *walk_p = NULL;
        if (!tlv_walk(&sub_ctx, &walk_p, &item)) {
            goto fail;
        }
        size_t consumed = (size_t)(walk_p - p);
        if (item.tag == TAG_NAME) {
            if (has_name) {
                goto fail;
            }
            if (item.value.len == 0) {
                ret = PICOKEYS_ERR_NULL_PARAM;
                goto fail;
            }
            has_name = true;
        }
        else if (item.tag == TAG_KEY) {
            if (has_key || item.value.len < 2) {
                goto fail;
            }
            uint8_t oath_type = item.value.data[0] & OATH_TYPE_MASK;
            uint8_t oath_alg = item.value.data[0] & ALG_MASK;
            uint8_t digits = item.value.data[1];
            if ((oath_type != OATH_TYPE_HOTP && oath_type != OATH_TYPE_TOTP) ||
                (oath_alg != ALG_HMAC_SHA1 && oath_alg != ALG_HMAC_SHA256 &&
                 oath_alg != ALG_HMAC_SHA512) || (digits < 6 || digits > 8)) {
                goto fail;
            }
            has_key = true;
            key_type_alg = item.value.data[0];
        }
        else if (item.tag == TAG_IMF) {
            if (has_imf || item.value.len > 8) {
                goto fail;
            }
            has_imf = true;
            uint8_t imf[10] = { TAG_IMF, 8 };
            if (item.value.len > 0) {
                memcpy(imf + sizeof(imf) - item.value.len, item.value.data,
                       item.value.len);
            }
            if (!oath_put_append(buf, capacity, &wpos, imf, sizeof(imf))) {
                goto fail;
            }
            rpos += consumed;
            continue;
        }
        if (!oath_put_append(buf, capacity, &wpos, p, consumed)) {
            goto fail;
        }
        rpos += consumed;
    }

    if (!has_name || !has_key) {
        ret = PICOKEYS_ERR_NULL_PARAM;
        goto fail;
    }
    if ((key_type_alg & OATH_TYPE_MASK) == OATH_TYPE_HOTP && !has_imf) {
        const uint8_t imf[10] = { TAG_IMF, 8 };
        if (!oath_put_append(buf, capacity, &wpos, imf, sizeof(imf))) {
            goto fail;
        }
    }
    *out_buf = buf;
    *out_len = wpos;
    return PICOKEYS_OK;

fail:
    mbedtls_platform_zeroize(buf, capacity);
    free(buf);
    return ret;
}
