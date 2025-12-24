//
// Created by Jon-Erik Storm on 12/26/21.
//
// Library based on jocover's sha256-armv8 assembly code.
//
// Copyright (C) 2021 Jon-Erik G. Storm
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with this program.  If not, see <https://www.gnu.org/licenses/>.
#ifndef LIBSHA256_ARMV8_H
#define LIBSHA256_ARMV8_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    SHA256_ARMV8_BLOCK_BYTES = 64,
    SHA256_ARMV8_DIGEST_BYTES = 32,
    SHA256_ARMV8_HEX_BYTES = 64,
};

typedef struct sha256_armv8_ctx {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t buffer[SHA256_ARMV8_BLOCK_BYTES];
    size_t buffer_len;
} sha256_armv8_ctx;

void sha256_block_data_order(uint32_t *state, const void *data, size_t blocks);

void sha256_armv8_init(sha256_armv8_ctx *ctx);
void sha256_armv8_update(sha256_armv8_ctx *ctx, const void *data, size_t len);
void sha256_armv8_final(sha256_armv8_ctx *ctx, uint8_t out[SHA256_ARMV8_DIGEST_BYTES]);

void sha256_armv8(const void *data, size_t len, uint8_t out[SHA256_ARMV8_DIGEST_BYTES]);
void sha256_armv8_to_hex(
    const uint8_t digest[SHA256_ARMV8_DIGEST_BYTES],
    char out_hex[SHA256_ARMV8_HEX_BYTES + 1]);

#ifdef __cplusplus
}
#endif

#endif
