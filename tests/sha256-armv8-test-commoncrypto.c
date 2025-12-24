#include "libsha256-armv8.h"

#include <CommonCrypto/CommonDigest.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t prng_next(uint32_t *state) {
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

static void fill_prng(uint8_t *buf, size_t len, uint32_t seed) {
    uint32_t state = seed == 0 ? 0x6a09e667u : seed;
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)prng_next(&state);
    }
}

static void print_mismatch(const char *name, size_t len, const uint8_t got[SHA256_ARMV8_DIGEST_BYTES],
    const uint8_t expected[SHA256_ARMV8_DIGEST_BYTES]) {
    char got_hex[SHA256_ARMV8_HEX_BYTES + 1];
    char expected_hex[SHA256_ARMV8_HEX_BYTES + 1];
    sha256_armv8_to_hex(got, got_hex);
    sha256_armv8_to_hex(expected, expected_hex);

    fprintf(stderr, "FAIL %s (len=%zu)\nexpected: %s\ngot:      %s\n", name, len, expected_hex, got_hex);
}

static int check_case(const char *name, const uint8_t *msg, size_t len) {
    uint8_t expected[SHA256_ARMV8_DIGEST_BYTES];
    CC_SHA256(msg, (CC_LONG)len, expected);

    uint8_t got[SHA256_ARMV8_DIGEST_BYTES];
    sha256_armv8(msg, len, got);
    if (memcmp(got, expected, SHA256_ARMV8_DIGEST_BYTES) != 0) {
        print_mismatch(name, len, got, expected);
        return 1;
    }

    static const size_t chunk_sizes[] = {1, 7, 64, 65, 128, 1024};
    for (size_t i = 0; i < sizeof(chunk_sizes) / sizeof(chunk_sizes[0]); i++) {
        const size_t chunk = chunk_sizes[i];

        sha256_armv8_ctx ctx;
        sha256_armv8_init(&ctx);

        sha256_armv8_update(&ctx, msg, 0);

        const uint8_t *p = msg;
        size_t remaining = len;
        while (remaining != 0) {
            size_t n = remaining < chunk ? remaining : chunk;
            sha256_armv8_update(&ctx, p, n);
            p += n;
            remaining -= n;
        }

        sha256_armv8_final(&ctx, got);
        if (memcmp(got, expected, SHA256_ARMV8_DIGEST_BYTES) != 0) {
            char label[128];
            snprintf(label, sizeof(label), "%s (chunk=%zu)", name, chunk);
            print_mismatch(label, len, got, expected);
            return 1;
        }
    }

    if (len != 0) {
        const size_t chunk = len + 1;
        sha256_armv8_ctx ctx;
        sha256_armv8_init(&ctx);
        sha256_armv8_update(&ctx, msg, len);
        sha256_armv8_final(&ctx, got);
        if (memcmp(got, expected, SHA256_ARMV8_DIGEST_BYTES) != 0) {
            char label[128];
            snprintf(label, sizeof(label), "%s (chunk=%zu)", name, chunk);
            print_mismatch(label, len, got, expected);
            return 1;
        }
    }

    return 0;
}

int main(void) {
    int failed = 0;

    const size_t max_len = 1u << 20;
    uint8_t *buf = (uint8_t *)malloc(max_len);
    if (!buf) {
        fprintf(stderr, "malloc failed\n");
        return 2;
    }

    const size_t boundary_lengths[] = {
        0,  1,  2,  3,  55, 56, 57, 63, 64, 65, 127, 128, 129, 255, 256, 257,
        511, 512, 513, 1023, 1024, 1025, 4095, 4096, 4097,
    };

    for (size_t i = 0; i < sizeof(boundary_lengths) / sizeof(boundary_lengths[0]); i++) {
        const size_t len = boundary_lengths[i];
        fill_prng(buf, len, (uint32_t)(0x9e3779b9u ^ (uint32_t)len));
        failed |= check_case("boundary", buf, len);
        if (failed) {
            free(buf);
            return 1;
        }
    }

    uint32_t rng = 0x243f6a88u;
    for (int i = 0; i < 300; i++) {
        const size_t len = (size_t)(prng_next(&rng) % 4096u);
        fill_prng(buf, len, prng_next(&rng));
        failed |= check_case("random", buf, len);
        if (failed) {
            free(buf);
            return 1;
        }
    }

    fill_prng(buf, max_len, 0x13198a2eu);
    failed |= check_case("random-1MiB", buf, max_len);

    free(buf);
    if (failed) {
        return 1;
    }

    printf("OK (CommonCrypto)\n");
    return 0;
}
