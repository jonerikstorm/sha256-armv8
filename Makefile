CC = clang
AR = ar
RANLIB = ranlib

CFLAGS ?= -O3 -Wall -Wextra -Wpedantic -std=c11

LIB := libsha256-armv8.a
OBJS := libsha256-armv8.o sha256-armv8-aarch64.o

.PHONY: all clean test
.PHONY: test-commoncrypto
.PHONY: bench
.PHONY: bench-asm-permutations

all: $(LIB)

$(LIB): $(OBJS)
	$(AR) rcs $@ $(OBJS)
	$(RANLIB) $@

libsha256-armv8.o: libsha256-armv8.c libsha256-armv8.h
	$(CC) $(CFLAGS) -c libsha256-armv8.c -o $@

sha256-armv8-aarch64.o: sha256-armv8-aarch64.s
	$(CC) -c sha256-armv8-aarch64.s -o $@

sha256-armv8-test: tests/sha256-armv8-test.c $(LIB)
	$(CC) $(CFLAGS) -I. tests/sha256-armv8-test.c $(LIB) -o $@

test: sha256-armv8-test
	./sha256-armv8-test

sha256-armv8-test-commoncrypto: tests/sha256-armv8-test-commoncrypto.c $(LIB)
	$(CC) $(CFLAGS) -I. tests/sha256-armv8-test-commoncrypto.c $(LIB) -o $@

test-commoncrypto: sha256-armv8-test-commoncrypto
	./sha256-armv8-test-commoncrypto

sha256-armv8-bench: tests/sha256-armv8-bench.c $(LIB)
	$(CC) $(CFLAGS) -I. tests/sha256-armv8-bench.c $(LIB) -o $@

bench: sha256-armv8-bench
	./sha256-armv8-bench

bench-asm-permutations:
	python3 tools/bench-asm-permutations.py

clean:
	rm -f $(OBJS) $(LIB) sha256-armv8-test sha256-armv8-test-commoncrypto sha256-armv8-bench
	rm -rf sha256-armv8-test.dSYM
