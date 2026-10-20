/* SPDX-License-Identifier: AGPL-3.0-only */
#include "picokeys.h"
#include "oath_put.h"

#include <assert.h>
#include <stdio.h>

static const uint8_t totp[] = { 0x71, 1, 'a', 0x73, 3, 0x21, 6, 0x55 };
static const uint8_t hotp[] = { 0x71, 1, 'a', 0x73, 3, 0x11, 6, 0x55 };
static const uint8_t zero_imf[] = { 0x7a, 8, 0, 0, 0, 0, 0, 0, 0, 0 };

static void expect_normalized(const uint8_t *input, size_t input_len,
                              const uint8_t *expected, size_t expected_len) {
    uint8_t *output = NULL;
    size_t output_len = 0;
    assert(oath_normalize_put_data(input, input_len, &output, &output_len) == PICOKEYS_OK);
    assert(output != NULL);
    assert(output_len == expected_len);
    assert(memcmp(output, expected, expected_len) == 0);
    memset(output, 0, output_len);
    free(output);
}

static void expect_rejected(const uint8_t *input, size_t input_len) {
    uint8_t *output = (uint8_t *)(uintptr_t)1;
    size_t output_len = SIZE_MAX;
    int ret = oath_normalize_put_data(input, input_len, &output, &output_len);
    assert(ret == PICOKEYS_WRONG_DATA || ret == PICOKEYS_ERR_NULL_PARAM);
    assert(output == NULL);
    assert(output_len == 0);
}

static void test_compatible_property_and_imf_encodings(void) {
    expect_normalized(totp, sizeof(totp), totp, sizeof(totp));
    uint8_t input[32];
    uint8_t expected[32];
    memcpy(input, hotp, sizeof(hotp));
    memcpy(expected, hotp, sizeof(hotp));
    memcpy(expected + sizeof(hotp), zero_imf, sizeof(zero_imf));
    expect_normalized(input, sizeof(hotp), expected, sizeof(hotp) + sizeof(zero_imf));

    /* Both legacy tag/value and tag/length/value Properties normalize to
     * the same stored representation, with a default counter for HOTP. */
    for (uint8_t property = 0; property <= 3; property++) {
        const uint8_t canonical_property[] = { 0x78, 1, property };
        memcpy(expected + sizeof(hotp), canonical_property, sizeof(canonical_property));
        memcpy(expected + sizeof(hotp) + 3, zero_imf, sizeof(zero_imf));
        input[sizeof(hotp)] = 0x78;
        input[sizeof(hotp) + 1] = property;
        expect_normalized(input, sizeof(hotp) + 2, expected, sizeof(hotp) + 13);
        memcpy(input + sizeof(hotp), canonical_property, sizeof(canonical_property));
        expect_normalized(input, sizeof(hotp) + 3, expected, sizeof(hotp) + 13);
    }

    /* Preserve the legacy INC Property followed by a four-byte IMF, as
     * emitted by existing clients. Normalize IMF to an eight-byte counter. */
    const uint8_t legacy_tail[] = { 0x78, 1, 0x7a, 4, 0x12, 0x34, 0x56, 0x78 };
    const uint8_t normalized_tail[] = {
        0x78, 1, 1, 0x7a, 8, 0, 0, 0, 0, 0x12, 0x34, 0x56, 0x78
    };
    memcpy(input + sizeof(hotp), legacy_tail, sizeof(legacy_tail));
    memcpy(expected + sizeof(hotp), normalized_tail, sizeof(normalized_tail));
    expect_normalized(input, sizeof(hotp) + sizeof(legacy_tail),
                      expected, sizeof(hotp) + sizeof(normalized_tail));

    /* Every supported IMF width, including a legacy empty counter. */
    for (uint8_t len = 0; len <= 8; len++) {
        memcpy(input, hotp, sizeof(hotp));
        input[sizeof(hotp)] = 0x7a;
        input[sizeof(hotp) + 1] = len;
        memset(input + sizeof(hotp) + 2, 0xa5, len);
        memcpy(expected, hotp, sizeof(hotp));
        memcpy(expected + sizeof(hotp), zero_imf, sizeof(zero_imf));
        memset(expected + sizeof(hotp) + 10 - len, 0xa5, len);
        expect_normalized(input, sizeof(hotp) + 2 + len, expected, sizeof(hotp) + 10);
    }
}

static void test_duplicate_singleton_fields(void) {
    uint8_t input[128];
    memcpy(input, totp, sizeof(totp));

    /* This previously expanded a +16 allocation by 24 bytes. */
    const uint8_t repeated_imf[] = { 0x7a, 0, 0x7a, 0, 0x7a, 0 };
    memcpy(input + sizeof(totp), repeated_imf, sizeof(repeated_imf));
    expect_rejected(input, sizeof(totp) + sizeof(repeated_imf));

    /* Legacy Property repetition previously grew the allocation without
     * limit; exercise enough repetitions to exceed the former slack. */
    for (size_t i = 0; i < 40; i++) {
        input[sizeof(totp) + i * 2] = 0x78;
        input[sizeof(totp) + i * 2 + 1] = 2;
    }
    expect_rejected(input, sizeof(totp) + 80);
    const uint8_t properties[] = { 0x78, 1, 2, 0x78, 1, 3 };
    memcpy(input + sizeof(totp), properties, sizeof(properties));
    expect_rejected(input, sizeof(totp) + sizeof(properties));

    const uint8_t name[] = { 0x71, 1, 'b' };
    memcpy(input + sizeof(totp), name, sizeof(name));
    expect_rejected(input, sizeof(totp) + sizeof(name));
    const uint8_t key[] = { 0x73, 3, 0x11, 8, 0x66 };
    memcpy(input + sizeof(totp), key, sizeof(key));
    expect_rejected(input, sizeof(totp) + sizeof(key));

    const uint8_t mixed_imf[] = { 0x7a, 0x81, 0, 0x7a, 8, 0, 0, 0, 0, 0, 0, 0, 0 };
    memcpy(input + sizeof(totp), mixed_imf, sizeof(mixed_imf));
    expect_rejected(input, sizeof(totp) + sizeof(mixed_imf));
}

static void test_malformed_fields(void) {
    uint8_t input[32];
    memcpy(input, totp, sizeof(totp));
    static const struct {
        uint8_t data[11];
        size_t len;
    } invalid_tails[] = {
        { { 0x78 }, 1 },
        { { 0x7a }, 1 },
        { { 0x7a, 4, 1, 2, 3 }, 5 },
        { { 0x7a, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, 11 },
        { { 0x7a, 0x81 }, 2 },
        { { 0x7a, 0x82, 0 }, 3 },
        { { 0x7a, 0x82, 1, 0 }, 4 },
        { { 0x7d, 0x80 }, 2 },
        { { 0x7d, 0x83, 0, 0, 0 }, 5 },
        { { 0x7f }, 1 },
        { { 0x7f, 0x01 }, 2 },
    };
    for (size_t i = 0; i < sizeof(invalid_tails) / sizeof(invalid_tails[0]); i++) {
        memcpy(input + sizeof(totp), invalid_tails[i].data, invalid_tails[i].len);
        expect_rejected(input, sizeof(totp) + invalid_tails[i].len);
    }
    for (size_t len = 0; len < sizeof(totp); len++) {
        expect_rejected(totp, len);
    }
    const uint8_t empty_name[] = { 0x71, 0, 0x73, 3, 0x21, 6, 0x55 };
    expect_rejected(empty_name, sizeof(empty_name));
    const uint8_t short_key[] = { 0x71, 1, 'a', 0x73, 1, 0x21 };
    expect_rejected(short_key, sizeof(short_key));
    memcpy(input, totp, sizeof(totp));
    input[5] = 0x31;
    expect_rejected(input, sizeof(totp));
    input[5] = 0x24;
    expect_rejected(input, sizeof(totp));
    input[5] = 0x21;
    input[6] = 5;
    expect_rejected(input, sizeof(totp));
    input[6] = 9;
    expect_rejected(input, sizeof(totp));
    expect_rejected(NULL, sizeof(totp));
    expect_rejected(totp, UINT16_MAX);

    uint8_t *output = (uint8_t *)(uintptr_t)1;
    size_t len = SIZE_MAX;
    assert(oath_normalize_put_data(totp, sizeof(totp), NULL, &len) == PICOKEYS_ERR_NULL_PARAM);
    assert(len == 0);
    assert(oath_normalize_put_data(totp, sizeof(totp), &output, NULL) == PICOKEYS_ERR_NULL_PARAM);
    assert(output == NULL);
}

static void test_supported_algorithms_and_extra_fields(void) {
    uint8_t input[32];
    for (uint8_t type = 0x10; type <= 0x20; type += 0x10) {
        for (uint8_t alg = 1; alg <= 3; alg++) {
            for (uint8_t digits = 6; digits <= 8; digits++) {
                memcpy(input, totp, sizeof(totp));
                input[5] = type | alg;
                input[6] = digits;
                uint8_t expected[sizeof(totp) + sizeof(zero_imf)];
                memcpy(expected, input, sizeof(totp));
                memcpy(expected + sizeof(totp), zero_imf, sizeof(zero_imf));
                expect_normalized(input, sizeof(totp), expected,
                                  sizeof(totp) + (type == 0x10 ? sizeof(zero_imf) : 0));
            }
        }
    }
    memcpy(input, totp, sizeof(totp));
    const uint8_t extra[] = { 0x7d, 0x81, 1, 0xaa, 0x7f, 0x88, 0x82, 0, 1, 0xbb };
    memcpy(input + sizeof(totp), extra, sizeof(extra));
    expect_normalized(input, sizeof(totp) + sizeof(extra), input, sizeof(totp) + sizeof(extra));
}

static void test_maximum_expansion(void) {
    /* Exercise the full uint16_t storage boundary and the largest possible
     * expansion: two-byte Property plus an automatically appended IMF. */
    size_t input_len = UINT16_MAX - 11;
    uint8_t *input = calloc(1, input_len);
    uint8_t *expected = calloc(1, UINT16_MAX);
    assert(input && expected);
    memcpy(input, hotp, sizeof(hotp));
    input[8] = 0x78;
    input[9] = 2;
    input[10] = 0x7d;
    input[11] = 0x82;
    size_t payload_len = input_len - 14;
    input[12] = (uint8_t)(payload_len >> 8);
    input[13] = (uint8_t)payload_len;
    memcpy(expected, hotp, sizeof(hotp));
    expected[8] = 0x78;
    expected[9] = 1;
    expected[10] = 2;
    memcpy(expected + 11, input + 10, input_len - 10);
    memcpy(expected + input_len + 1, zero_imf, sizeof(zero_imf));
    expect_normalized(input, input_len, expected, UINT16_MAX);
    free(expected);
    free(input);
}

int main(void) {
    test_compatible_property_and_imf_encodings();
    test_duplicate_singleton_fields();
    test_malformed_fields();
    test_supported_algorithms_and_extra_fields();
    test_maximum_expansion();
    puts("OATH PUT normalization regression tests passed");
    return 0;
}
