# sha256-armv8 (macOS arm64)

SHA-256 compression function implemented in AArch64 using ARMv8 Crypto Extensions, plus a small C wrapper that provides a correct, binary-safe SHA-256 API (single-shot + streaming).

This route is *382%* faster than commoncrypto at the size of a bitcoin hash, as tested on an M4 Mac.

## Requirements

- macOS arm64 (Apple Silicon).
- ARMv8 crypto extension support (`sha256h`, `sha256h2`, `sha256su0`, `sha256su1`).
- `clang` (Xcode Command Line Tools).

## Build and test

```sh
make
make test
```

This builds `libsha256-armv8.a` and runs `sha256-armv8-test` against FIPS 180-4 test vectors.

Optional:

```sh
make test-commoncrypto
make bench
```

## API

The header is `libsha256-armv8.h`.

- One-shot: `sha256_armv8(const void *data, size_t len, uint8_t out[32])`
- Streaming: `sha256_armv8_init` / `sha256_armv8_update` / `sha256_armv8_final`
- Hex encoding: `sha256_armv8_to_hex(const uint8_t digest[32], char out_hex[65])`

## License / provenance

This repository is GPL-3.0 (see `LICENSE`). The assembly is based on `jocover/sha256-armv8`; if you plan to redistribute this code, audit upstream provenance/licensing for your use case.
