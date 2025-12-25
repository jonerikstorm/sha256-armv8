#include "libsha256-armv8.h"

#include <CommonCrypto/CommonDigest.h>
#include <mach/mach_time.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile uint8_t bench_sink;

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

static uint64_t now_ns(void) {
    static mach_timebase_info_data_t tb;
    if (tb.denom == 0) {
        (void)mach_timebase_info(&tb);
    }
    const uint64_t t = mach_absolute_time();
    const __uint128_t ns = (__uint128_t)t * tb.numer / tb.denom;
    return (uint64_t)ns;
}

typedef void (*hash_fn)(const uint8_t *msg, size_t len, uint8_t out[SHA256_ARMV8_DIGEST_BYTES]);

static void hash_armv8(const uint8_t *msg, size_t len, uint8_t out[SHA256_ARMV8_DIGEST_BYTES]) {
    sha256_armv8(msg, len, out);
}

static void hash_commoncrypto(const uint8_t *msg, size_t len, uint8_t out[SHA256_ARMV8_DIGEST_BYTES]) {
    CC_SHA256(msg, (CC_LONG)len, out);
}

static int verify_equal(const char *label, const uint8_t *msg, size_t len) {
    uint8_t a[SHA256_ARMV8_DIGEST_BYTES];
    uint8_t b[SHA256_ARMV8_DIGEST_BYTES];
    hash_armv8(msg, len, a);
    hash_commoncrypto(msg, len, b);
    if (memcmp(a, b, sizeof(a)) != 0) {
        char a_hex[SHA256_ARMV8_HEX_BYTES + 1];
        char b_hex[SHA256_ARMV8_HEX_BYTES + 1];
        sha256_armv8_to_hex(a, a_hex);
        sha256_armv8_to_hex(b, b_hex);
        fprintf(stderr, "FAIL digest mismatch %s (len=%zu)\narmv8: %s\ncc:    %s\n", label, len, a_hex, b_hex);
        return 1;
    }
    return 0;
}

static double bench(hash_fn fn, const uint8_t *msg, size_t len, uint64_t target_ns, uint64_t *iters_out) {
    uint8_t out[SHA256_ARMV8_DIGEST_BYTES];

    uint64_t iters = 0;
    uint64_t inner = 1;

    const uint64_t start = now_ns();
    uint64_t end = start;

    for (;;) {
        for (uint64_t i = 0; i < inner; i++) {
            fn(msg, len, out);
            bench_sink ^= out[0];
        }
        iters += inner;

        end = now_ns();
        if (end - start >= target_ns) {
            break;
        }

        if (inner < (1u << 20)) {
            inner <<= 1;
        }
    }

    const double seconds = (double)(end - start) / 1e9;
    const double mib = ((double)iters * (double)len) / (1024.0 * 1024.0);
    *iters_out = iters;
    return mib / seconds;
}

static int bench_size(const uint8_t *buf, size_t len, uint64_t target_ns) {
    char label[64];
    snprintf(label, sizeof(label), "bench-%zu", len);
    if (verify_equal(label, buf, len) != 0) {
        return 1;
    }

    uint64_t iters_arm = 0;
    uint64_t iters_cc = 0;
    const double arm_mib_s = bench(hash_armv8, buf, len, target_ns, &iters_arm);
    const double cc_mib_s = bench(hash_commoncrypto, buf, len, target_ns, &iters_cc);
    const double speedup = cc_mib_s == 0.0 ? 0.0 : (arm_mib_s / cc_mib_s);

    printf(
        "%10zu  %12.1f  %18.1f  %7.2fx\n",
        len,
        arm_mib_s,
        cc_mib_s,
        speedup);
    (void)iters_arm;
    (void)iters_cc;
    return 0;
}

int main(void) {
    const uint64_t target_ns = 250ull * 1000ull * 1000ull;

    const size_t sizes[] = {64, 80, 256, 1024, 8192, 65536, 1u << 20};
    const size_t max_len = sizes[sizeof(sizes) / sizeof(sizes[0]) - 1];

    uint8_t *buf = (uint8_t *)malloc(max_len);
    if (!buf) {
        fprintf(stderr, "malloc failed\n");
        return 2;
    }
    fill_prng(buf, max_len, 0x13198a2eu);

    uint8_t out[SHA256_ARMV8_DIGEST_BYTES];
    hash_armv8(buf, 64, out);
    hash_commoncrypto(buf, 64, out);
    bench_sink ^= out[0];

    printf("SHA-256 throughput (MiB/s), higher is better\n");
    printf("%10s  %12s  %18s  %8s\n", "size(B)", "armv8", "CommonCrypto", "speedup");

    int failed = 0;
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        const size_t len = sizes[i];
        failed |= bench_size(buf, len, target_ns);
        if (failed) {
            break;
        }
    }

    free(buf);
    return failed ? 1 : 0;
}
