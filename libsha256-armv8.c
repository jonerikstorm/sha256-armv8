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

#include "libsha256arm64.h"
const char* sha256_str(unsigned char * message){
    static char buffer[64];
    unsigned char* in;
    in = (unsigned char *)sha256_hex(message);
    for(int i = 0; i < 32; i++)
    {
        sprintf(&buffer[i*2],"%02x",*((unsigned char *) in + i));
    }
    return (const char*)&buffer;
}
const char* sha256_hex(unsigned char * message) {
    static uint32_t hash[8];
    sha256(hash, (unsigned char**)message, strlen((char*)message), 0, 1);
    return (void*)hash;
}

void sha256(uint32_t* hash, unsigned char** message, uint64_t len, _Bool safe, _Bool switchEndianness) {
    if (len > 0b00010000000000000000000000000000) {
        fprintf(stderr, "Message lengths larger than 2^61 not supported.\n");
        exit(-1);
    }
    uint8_t padding;         // For example, if len is 76, this is 52.
    if ((len % 64) > 55){
        padding = (len % 64) + 64;
    }
    else {
        padding = 64 - (len % 64);
    }

    uint64_t lengthInBits;     // Has to be a 64-bit number to put at the end
    lengthInBits = len << 3;   // For example, if len is 76, this is 608.

    unsigned char* dest;
    if (!safe) {
        unsigned char* buffer = malloc(len + padding);
        if (buffer == NULL) {
            fprintf(stderr, "Failed to allocate memory.\n");
            exit(-1);
        }
        memcpy(buffer, message, len);
        dest = buffer;
    }
    else {
        dest = *message;
    }

    *(dest + len) = 0x80;                // Start the padding with a single "on" bit followed by zeros.

    for (uint8_t i = 1; i < (padding - 8); i++) {
            *(dest + len + i) = 0x00;              // For example, if len is 76, we write from 77 to 120 (43 total)
        }
        // message[len+padding-8] = lengthInBits; // For example, if len is 76, this should be 76+52-8=120.
    dest[len + padding - 8] = (uint8_t) (lengthInBits >> 56);
    dest[len + padding - 7] = (uint8_t) (lengthInBits >> 48);
    dest[len + padding - 6] = (uint8_t) (lengthInBits >> 40);
    dest[len + padding - 5] = (uint8_t) (lengthInBits >> 32);
    dest[len + padding - 4] = (uint8_t) (lengthInBits >> 24);
    dest[len + padding - 3] = (uint8_t) (lengthInBits >> 16);
    dest[len + padding - 2] = (uint8_t) (lengthInBits >> 8);
    dest[len + padding - 1] = (uint8_t) lengthInBits;

    // load default state
    hash[0]=0x6a09e667,
    hash[1]=0xbb67ae85,
    hash[2]=0x3c6ef372,
    hash[3]=0xa54ff53a,
    hash[4]=0x510e527f,
    hash[5]=0x9b05688c,
    hash[6]=0x1f83d9ab,
    hash[7]=0x5be0cd19;

    for(uint64_t i = 0; i < len; i += 64) {
        sha256_block_data_order(hash, (unsigned char*)(dest + i), 1);
    }
    if(!safe) {
        free(dest);
    }
    if(switchEndianness) {
        unsigned char switchBuffer[32];
        switchBuffer[0] = *(((unsigned char*) hash) + 3);
        switchBuffer[1] = *(((unsigned char*) hash) + 2);  switchBuffer[2] = *(((unsigned char*) hash) + 1); switchBuffer[3] = *(((unsigned char*) hash) + 0);
        switchBuffer[4] = *(((unsigned char*) hash) + 7); switchBuffer[5] = *(((unsigned char*) hash) + 6);  switchBuffer[6] = *(((unsigned char*) hash) + 5); switchBuffer[7] = *(((unsigned char*) hash) + 4);
        switchBuffer[8] = *(((unsigned char*) hash) + 11); switchBuffer[9] = *(((unsigned char*) hash) + 10);  switchBuffer[10] = *(((unsigned char*) hash) + 9); switchBuffer[11] = *(((unsigned char*) hash) + 8);
        switchBuffer[12] = *(((unsigned char*) hash) + 15); switchBuffer[13] = *(((unsigned char*) hash) + 14);  switchBuffer[14] = *(((unsigned char*) hash) + 13); switchBuffer[15] = *(((unsigned char*) hash) + 12);
        switchBuffer[16] = *(((unsigned char*) hash) + 19); switchBuffer[17] = *(((unsigned char*) hash) + 18);  switchBuffer[18] = *(((unsigned char*) hash) + 17); switchBuffer[19] = *(((unsigned char*) hash) + 16);
        switchBuffer[20] = *(((unsigned char*) hash) + 23); switchBuffer[21] = *(((unsigned char*) hash) + 22);  switchBuffer[22] = *(((unsigned char*) hash) + 21); switchBuffer[23] = *(((unsigned char*) hash) + 20);
        switchBuffer[24] = *(((unsigned char*) hash) + 27); switchBuffer[25] = *(((unsigned char*) hash) + 26);  switchBuffer[26] = *(((unsigned char*) hash) + 25); switchBuffer[27] = *(((unsigned char*) hash) + 24);
        switchBuffer[28] = *(((unsigned char*) hash) + 31); switchBuffer[29] = *(((unsigned char*) hash) + 30);  switchBuffer[30] = *(((unsigned char*) hash) + 29); switchBuffer[31] = *(((unsigned char*) hash) + 28);
        memcpy(hash, &switchBuffer, 32);
    }
}
