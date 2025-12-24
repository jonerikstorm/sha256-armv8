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

#include "libsha256-armv8.h"

#include <string.h>

static void sha256_armv8_state_to_bytes(const uint32_t state[8], uint8_t out[SHA256_ARMV8_DIGEST_BYTES]) {
    for (size_t i = 0; i < 8; i++) {
        out[i * 4 + 0] = (uint8_t)(state[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(state[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(state[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(state[i] >> 0);
    }
}

void sha256_armv8_init(sha256_armv8_ctx *ctx) {
    ctx->state[0] = 0x6a09e667u;
    ctx->state[1] = 0xbb67ae85u;
    ctx->state[2] = 0x3c6ef372u;
    ctx->state[3] = 0xa54ff53au;
    ctx->state[4] = 0x510e527fu;
    ctx->state[5] = 0x9b05688cu;
    ctx->state[6] = 0x1f83d9abu;
    ctx->state[7] = 0x5be0cd19u;

    ctx->bitlen = 0;
    ctx->buffer_len = 0;
}

void sha256_armv8_update(sha256_armv8_ctx *ctx, const void *data, size_t len) {
    if (len == 0) {
        return;
    }

    const uint8_t *p = (const uint8_t *)data;
    ctx->bitlen += (uint64_t)len * 8u;

    if (ctx->buffer_len != 0) {
        size_t to_copy = SHA256_ARMV8_BLOCK_BYTES - ctx->buffer_len;
        if (to_copy > len) {
            to_copy = len;
        }

        memcpy(ctx->buffer + ctx->buffer_len, p, to_copy);
        ctx->buffer_len += to_copy;
        p += to_copy;
        len -= to_copy;

        if (ctx->buffer_len == SHA256_ARMV8_BLOCK_BYTES) {
            sha256_block_data_order(ctx->state, ctx->buffer, 1);
            ctx->buffer_len = 0;
        }
    }

    if (len >= SHA256_ARMV8_BLOCK_BYTES) {
        size_t blocks = len / SHA256_ARMV8_BLOCK_BYTES;
        sha256_block_data_order(ctx->state, p, blocks);
        p += blocks * SHA256_ARMV8_BLOCK_BYTES;
        len -= blocks * SHA256_ARMV8_BLOCK_BYTES;
    }

    if (len != 0) {
        memcpy(ctx->buffer, p, len);
        ctx->buffer_len = len;
    }
}

void sha256_armv8_final(sha256_armv8_ctx *ctx, uint8_t out[SHA256_ARMV8_DIGEST_BYTES]) {
    size_t i = ctx->buffer_len;

    ctx->buffer[i++] = 0x80;
    if (i > 56) {
        memset(ctx->buffer + i, 0, SHA256_ARMV8_BLOCK_BYTES - i);
        sha256_block_data_order(ctx->state, ctx->buffer, 1);
        i = 0;
    }

    memset(ctx->buffer + i, 0, 56 - i);
    ctx->buffer[56] = (uint8_t)(ctx->bitlen >> 56);
    ctx->buffer[57] = (uint8_t)(ctx->bitlen >> 48);
    ctx->buffer[58] = (uint8_t)(ctx->bitlen >> 40);
    ctx->buffer[59] = (uint8_t)(ctx->bitlen >> 32);
    ctx->buffer[60] = (uint8_t)(ctx->bitlen >> 24);
    ctx->buffer[61] = (uint8_t)(ctx->bitlen >> 16);
    ctx->buffer[62] = (uint8_t)(ctx->bitlen >> 8);
    ctx->buffer[63] = (uint8_t)(ctx->bitlen >> 0);

    sha256_block_data_order(ctx->state, ctx->buffer, 1);
    sha256_armv8_state_to_bytes(ctx->state, out);

    ctx->buffer_len = 0;
}

void sha256_armv8(const void *data, size_t len, uint8_t out[SHA256_ARMV8_DIGEST_BYTES]) {
    sha256_armv8_ctx ctx;
    sha256_armv8_init(&ctx);
    sha256_armv8_update(&ctx, data, len);
    sha256_armv8_final(&ctx, out);
}

void sha256_armv8_to_hex(
    const uint8_t digest[SHA256_ARMV8_DIGEST_BYTES],
    char out_hex[SHA256_ARMV8_HEX_BYTES + 1]) {
    static const char table[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    };

    for (size_t i = 0; i < SHA256_ARMV8_DIGEST_BYTES; i++) {
        out_hex[i * 2 + 0] = table[(digest[i] >> 4) & 0x0f];
        out_hex[i * 2 + 1] = table[digest[i] & 0x0f];
    }
    out_hex[SHA256_ARMV8_HEX_BYTES] = '\0';
}

