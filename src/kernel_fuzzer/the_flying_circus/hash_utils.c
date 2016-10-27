/*
 *   _____   _                          ___     _      _  _     _              __ _
 *  |_   _| | |_      ___      o O O   | __|   | |    | || |   (_)    _ _     / _` |
 *    | |   | ' \    / -_)    o        | _|    | |     \_, |   | |   | ' \    \__, |
 *   _|_|_  |_||_|   \___|   TS__[O]  _|_|_   _|_|_   _|__/   _|_|_  |_||_|   |___/
 * _|"""""|_|"""""|_|"""""| {======|_| """ |_|"""""|_| """"|_|"""""|_|"""""|_|"""""|
 * "`-0-0-'"`-0-0-'"`-0-0-'./o--000'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'
 *            ___      _
 *    o O O  / __|    (_)      _ _    __     _  _     ___
 *   o      | (__     | |     | '_|  / _|   | +| |   (_-<
 *  TS__[O]  \___|   _|_|_   _|_|_   \__|_   \_,_|   /__/_
 *  {======|_|"""""|_|"""""|_|"""""|_|"""""|_|"""""|_|"""""|
 * ./o--000'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'
 *
 * And now for something completely different...
 *
 * A Mountain Lion rootkit for Phrack #69!
 *
 * Copyright (c) fG!, 2012, 2013 - reverser@put.as - http://reverse.put.as
 * All rights reserved.
 *
 * hash_utils.c
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "hash_utils.h"

#define ROL(x, n) (((x) << (n)) | ((x) >> (32-(n))))

// http://encode.ru/threads/1160-Fastest-non-secure-hash-function

uint32_t 
FNV1A_Hash_Jesteress(const char *str, size_t wrdlen)
{
    const uint32_t PRIME = 709607;
    uint32_t hash32 = 2166136261;
    const char *p = str;
    
    // Idea comes from Igor Pavlov's 7zCRC, thanks.
    for(; wrdlen >= 2*sizeof(uint32_t); wrdlen -= 2*sizeof(uint32_t), p += 2*sizeof(uint32_t)) {
        hash32 = (hash32 ^ (ROL(*(uint32_t *)p,5)^*(uint32_t *)(p+4))) * PRIME;        
    }
    // Cases: 0,1,2,3,4,5,6,7
    if (wrdlen & sizeof(uint32_t)) {
        hash32 = (hash32 ^ *(uint32_t*)p) * PRIME;
        p += sizeof(uint32_t);
    }
    if (wrdlen & sizeof(uint16_t)) {
        hash32 = (hash32 ^ *(uint16_t*)p) * PRIME;
        p += sizeof(uint16_t);
    }
    if (wrdlen & 1) 
        hash32 = (hash32 ^ *p) * PRIME;
    
    return hash32 ^ (hash32 >> 16);
}

// http://encode.ru/threads/612-Fastest-decompressor!?p=22184&viewfull=1#post22184
uint32_t 
FNV1A_Hash_WHIZ(const char *str, size_t wrdlen)
{
    const uint32_t PRIME = 1607;
    
    uint32_t hash32 = 2166136261;
    const char *p = str;
    
    for(; wrdlen >= sizeof(uint32_t); wrdlen -= sizeof(uint32_t), p += sizeof(uint32_t)) {
        hash32 = (hash32 ^ *(uint32_t *)p) * PRIME;
    }
    if (wrdlen & sizeof(uint16_t)) {
        hash32 = (hash32 ^ *(uint16_t*)p) * PRIME;
        p += sizeof(uint16_t);
    }
    if (wrdlen & 1) 
        hash32 = (hash32 ^ *p) * PRIME;
    
    return hash32 ^ (hash32 >> 16);
}
