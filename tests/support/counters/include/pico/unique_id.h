/* SPDX-License-Identifier: AGPL-3.0-only */
#pragma once
#include <stdint.h>
#define PICO_UNIQUE_BOARD_ID_SIZE_BYTES 8
typedef struct { uint8_t id[8]; } pico_unique_board_id_t;
