#include "libsha256-armv8.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int check_vector(const char *name, const void *data, size_t len, const char *expected_hex) {
    uint8_t digest[SHA256_ARMV8_DIGEST_BYTES];
    char got_hex[SHA256_ARMV8_HEX_BYTES + 1];

    sha256_armv8(data, len, digest);
    sha256_armv8_to_hex(digest, got_hex);

    if (strcmp(got_hex, expected_hex) != 0) {
        fprintf(stderr, "FAIL %s\nexpected: %s\ngot:      %s\n", name, expected_hex, got_hex);
        return 1;
    }
    return 0;
}

static int check_vector_chunked(
    const char *name,
    const void *data,
    size_t len,
    size_t chunk,
    const char *expected_hex) {
    sha256_armv8_ctx ctx;
    sha256_armv8_init(&ctx);

    const uint8_t *p = (const uint8_t *)data;
    size_t remaining = len;
    while (remaining != 0) {
        size_t n = remaining < chunk ? remaining : chunk;
        sha256_armv8_update(&ctx, p, n);
        p += n;
        remaining -= n;
    }

    uint8_t digest[SHA256_ARMV8_DIGEST_BYTES];
    char got_hex[SHA256_ARMV8_HEX_BYTES + 1];
    sha256_armv8_final(&ctx, digest);
    sha256_armv8_to_hex(digest, got_hex);

    if (strcmp(got_hex, expected_hex) != 0) {
        fprintf(
            stderr,
            "FAIL %s (chunk=%zu)\nexpected: %s\ngot:      %s\n",
            name,
            chunk,
            expected_hex,
            got_hex);
        return 1;
    }
    return 0;
}

static int check_million_a(void) {
    static const char *expected =
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";

    sha256_armv8_ctx ctx;
    sha256_armv8_init(&ctx);

    uint8_t block[1000];
    memset(block, 'a', sizeof(block));
    for (int i = 0; i < 1000; i++) {
        sha256_armv8_update(&ctx, block, sizeof(block));
    }

    uint8_t digest[SHA256_ARMV8_DIGEST_BYTES];
    char got_hex[SHA256_ARMV8_HEX_BYTES + 1];
    sha256_armv8_final(&ctx, digest);
    sha256_armv8_to_hex(digest, got_hex);

    if (strcmp(got_hex, expected) != 0) {
        fprintf(stderr, "FAIL 1,000,000 x 'a'\nexpected: %s\ngot:      %s\n", expected, got_hex);
        return 1;
    }
    return 0;
}

int main(void) {
    int failed = 0;

    failed |= check_vector(
        "empty",
        "",
        0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    failed |= check_vector(
        "abc",
        "abc",
        3,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    failed |= check_vector_chunked(
        "abc",
        "abc",
        3,
        1,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    static const char *msg =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    failed |= check_vector(
        "fips-180-4 56-byte",
        msg,
        strlen(msg),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    failed |= check_vector_chunked(
        "fips-180-4 56-byte",
        msg,
        strlen(msg),
        7,
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

    failed |= check_vector(
        "quick brown fox",
        "The quick brown fox jumps over the lazy dog",
        strlen("The quick brown fox jumps over the lazy dog"),
        "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");

    failed |= check_million_a();

    if (failed) {
        return 1;
    }

    printf("OK\n");
    return 0;
}

