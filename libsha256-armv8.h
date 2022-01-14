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
#ifndef _LIBSHA265ARM64__N
#define _LIBSHA265ARM64__N
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>

void sha256_block_data_order(uint32_t *ctx, const void *in, size_t num);
void sha256(uint32_t* hash, unsigned char** message, uint64_t len, _Bool safe, _Bool switchEndianness);
const char* sha256_hex(unsigned char * message);
const char* sha256_str(unsigned char * message);
#endif
