// Copyright (c) 2018 Phil Leblanc  -- see LICENSE file
// ---------------------------------------------------------------------

//                 !!! WORK IN PROGRESS !!!

/*
Gimli - authenticated encryption and hash based on a sponge construction
over the Gimli permutation. 
- see Gimli links and authors list at https://gimli.cr.yp.to/
- see https://en.wikipedia.org/wiki/Sponge_function
- (current encryption is in overwrite mode, ie. input 
  replaces R instead of XOR)


*/


//~ #include <stdio.h>

#include <stdint.h>
#include <string.h>

#define LITTLE_ENDIAN
// #define BIG_ENDIAN

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;

//----------------------------------------------------------------------
// from norx.h

/* INLINE definition - Workaround for C89 compilers */
#if !defined(__cplusplus) && (!defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L)
  #if   defined(_MSC_VER)
    #define INLINE __inline
  #elif defined(__GNUC__)
    #define INLINE __inline__
  #else
    #define INLINE
  #endif
#else
  #define INLINE inline
#endif

// --------------------------------------------------------
// ON A BIG ENDIAN ARCH ONLY

#ifdef BIG_ENDIAN

// load the little endian byte rep of a u32, return the u32
static INLINE u32 beload32_le(const u8 *in)
{
	u8 p[4];
	p[0] = in[3];
	p[1] = in[2];
	p[2] = in[1];
	p[3] = in[0];
	return (u32) *p;
}

// store a u32 as little endian at addr dst
static INLINE void bestore32_le(u8 *dst, u32 *u)
{
	u8 p = (u8 *) u;
	dst[0] = p[3];
	dst[1] = p[2];
	dst[2] = p[1];
	dst[3] = p[0];
}
#endif
// --------------------------------------------------------


static inline void mem_zero(u8 *dst, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) dst[i] = 0;
}

static inline void mem_xor(u8 *dst, const u8 *src, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) dst[i] ^= src[i];
}

static inline void mem_xor2(u8 *dst, const u8 *src1, const u8 *src2, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) dst[i] = src1[i] ^ src2[i];
}

//----------------------------------------------------------------------

#define ROTL32(x, b) (uint32_t)(((x) << (b)) | ((x) >> (32 - (b))))

static void
gimli_core(uint32_t state[12])
{
    unsigned int round;
    unsigned int column;
    uint32_t     x;
    uint32_t     y;
    uint32_t     z;

    for (round = 24; round > 0; round--) {
        for (column = 0; column < 4; column++) {
            x = ROTL32(state[column], 24);
            y = ROTL32(state[4 + column], 9);
            z = state[8 + column];

            state[8 + column] = x ^ (z << 1) ^ ((y & z) << 2);
            state[4 + column] = y ^ x ^ ((x | z) << 1);
            state[column]     = z ^ y ^ ((x & y) << 3);
        }
        switch (round & 3) {
        case 0:
            x        = state[0];
            state[0] = state[1];
            state[1] = x;
            x        = state[2];
            state[2] = state[3];
            state[3] = x;
            state[0] ^= ((uint32_t) 0x9e377900 | round);
            break;
        case 2:
            x        = state[0];
            state[0] = state[2];
            state[2] = x;
            x        = state[1];
            state[1] = state[3];
            state[3] = x;
        }
    }
}

static void gim_permute(uint8_t state_u8[48])
{
#ifdef BIG_ENDIAN
    uint32_t state_u32[12];
    int      i;

    for (i = 0; i < 12; i++) {
        state_u32[i] = beload32_le(&state_u8[i * 4]);
    }
    gimli_core(state_u32);
    for (i = 0; i < 12; i++) {
        bestore32_le(&state_u8[i * 4], state_u32[i]);
    }
#else
	/* state_u8 must be properly aligned */
    gimli_core((uint32_t *) (void *) state_u8); 
#endif
}

//----------------------------------------------------------------------

static void gim_setup(u8 *buf, const u8 *key, const u8 *iv) 
{
	// bufln = 48, keyln = 32, ivln = 16
	memcpy(buf, iv, 16);
	memcpy(buf+16, key, 32); 
	gim_permute(buf); 
	gim_permute(buf); 
}

#define ENCRYPT 1
#define DECRYPT 0

static void gim_core(
	u8 *buf, 
	u8 *out, 
	const u8 *in, size_t inlen, 
	int encflag)
{
	// encflag=1 for encryption or 0 for decryption
	// mix is the stream mixed with the state 
	// - out for encryption or in
	const u8 *mix = encflag ? out : in; 
    size_t i;
    size_t leftover;

    for (i = 0; i + 16 <= inlen; i = i + 16) {
		//~ printf("core loop1 %d %d\n", i, inlen);
		mem_xor2(out + i, in + i, buf, 16);
		memcpy(buf, mix + i, 16);
		gim_permute(buf);
	}
	leftover = inlen - i;
    if (leftover != 0) {
        mem_xor2(out + i, in + i, buf, leftover);
        memcpy(buf, mix + i, leftover);
    }
    gim_permute(buf);
}


static void gim_finalize(u8 *buf, const u8 *key)
{
    mem_xor(buf + 16, key, 32);
    gim_permute(buf);
    mem_xor(buf + 16, key, 32);
    gim_permute(buf);
}

static void gim_encrypt(
	u8 *c, u8 *mac, 
	const u8 *m, size_t mlen, 
	const u8 *key, const u8 *iv)
{
	u32 buf32[12];
	u8 *buf = (u8 *) buf32;  // ensure buf is aligned as a u32 array
	gim_setup(buf, key, iv);
	gim_core(buf, c, m, mlen, ENCRYPT);
	gim_finalize(buf, key);
	// extract the MAC
	memcpy(mac, buf + 16, 16);  // [why 'buf+16' ?? 'buf' not good?!?]
	mem_zero(buf, 48);
}

static int gim_decrypt(
	u8 *m, 
	const u8 *emac, const u8 *c, size_t clen, 
	const u8 *key, const u8 *iv)
{
	// emac is the expected MAC, mac is the computed MAC
	u32 state[12];
	u8 *buf = (u8 *) state;
	u8 mac[16];
	int i;
	gim_setup(buf, key, iv);
	gim_core(buf, m, c, clen, DECRYPT);
	gim_finalize(buf, key);
	// extract the MAC
	memcpy(mac, buf + 16, 16);  // [must be same offset as in gim_encrypt]
	mem_zero(buf, 48);
	// compare with the expected MAC:
	u32 acc = 0; 
	for (i = 0; i < 16; ++i) { acc |= mac[i] ^ emac[i]; }
	if (acc != 0) {
		mem_zero(m, clen);
		return -1;
	}
	return 0;
}

int gim_test()
{
	u8 *k = "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk"; //32
	u8 *n = "nnnnnnnnnnnnnnnn"; //16
	u8 *m = "abc"; //3
	size_t mlen = 3;
	u8 c[100];
	u8 mac[32];
	u8 buf[48];
	gim_setup(buf, k, n);
	gim_core(buf, c, m, mlen, 1);
	gim_finalize(buf, k);
	//~ gim_encrypt(c, mac, m, mlen, k, n);
	return 0;
}

// ---------------------------------------------------------------------
// from gimli_hash.c

#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define rateInBytes 16

static void gimli_hash(const uint8_t *input,
                uint64_t inputByteLen,
                uint8_t *output,
                uint64_t outputByteLen)
{
    uint32_t state[12];
    uint8_t* state_8 = (uint8_t*)state;
    uint64_t blockSize = 0;
    uint64_t i;

    // === Initialize the state ===
    memset(state, 0, sizeof(state));

    // === Absorb all the input blocks ===
    while(inputByteLen > 0) {
        blockSize = MIN(inputByteLen, rateInBytes);
        for(i=0; i<blockSize; i++)
            state_8[i] ^= input[i];
        input += blockSize;
        inputByteLen -= blockSize;

        if (blockSize == rateInBytes) {
            gimli_core(state);
            blockSize = 0;
        }
    }

    // === Do the padding and switch to the squeezing phase ===
    state_8[blockSize] ^= 0x1F;
    // Add the second bit of padding
    state_8[rateInBytes-1] ^= 0x80;
    // Switch to the squeezing phase
    gimli_core(state);

    // === Squeeze out all the output blocks ===
    while(outputByteLen > 0) {
        blockSize = MIN(outputByteLen, rateInBytes);
        memcpy(output, state, blockSize);
        output += blockSize;
        outputByteLen -= blockSize;

        if (outputByteLen > 0)
            gimli_core(state);
    }
}






// ---------------------------------------------------------------------
// lua binding


#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lua.h"
#include "lauxlib.h"

# define LERR(msg) return luaL_error(L, msg)



int ll_gimli_test(lua_State *L) {
	int r = gim_test();
	if (r != 0) { 
		lua_pushnil (L);
		lua_pushliteral(L, "ERROR");
		return 2;         
	} 
	lua_pushliteral(L, "OK"); 
	return 1;
}
	
int ll_gimli_encrypt(lua_State *L) {
	// Lua API: encrypt(k, n, m [, prefix [, ninc]])  return c
	//  k: key string (32 bytes)
	//  n: nonce string (16 bytes)
	//	m: message (plain text) string 
	//  prefix: string prepended to the encrypted message
	//       prefix is not encrypted. It can be used for example to prepend 
	//       the nonce to the message.
	//       (useful to limit allocation of strings in Lua)
	//  ninc: optional nonce increment (useful when encrypting a long message
	//       as a sequence of block). The same parameter n can be used for 
	//       the sequence. ninc is added to n for each block, so the actual
	//       nonce used for each block encryption is distinct.
	//       ninc defaults to 0 (the nonce n is used as-is)
	//  (c includes the 16-byte MAC: #c = #m + 16)
	int r;
	size_t mln, nln, kln, prefln, cln;
	const char *k = luaL_checklstring(L,1,&kln);
	const char *n = luaL_checklstring(L,2,&nln);	
	const char *m = luaL_checklstring(L,3,&mln);	
	const char *prefix = luaL_optlstring(L,4,"",&prefln);
	uint64_t ninc = luaL_optinteger(L, 5, 0);	
	if (kln != 32) LERR("bad key size");
	if (nln != 16) LERR("bad nonce size");
	// 
	char actn[16]; // actual nonce ("n + ninc")
	memcpy(actn, n, 16); 
	// addition modulo 2^64 over the first 8 bytes of n
	// (overflow not an issue: uint addition overflow _is_ defined)
	(*(uint64_t *) actn) = (*(uint64_t *) actn) + ninc;
	//
	// the layout of the encrypted result is: 
	// prefix | MAC | encr.msg
	cln = prefln + 16 + mln; 
	u8 *c = lua_newuserdata(L, cln);
	memcpy(c, prefix, prefln); // copy prefix
	gim_encrypt(
		c + prefln + 16, // encrypted stream
		c + prefln,      // mac
		m, mln,          // plain text msg
		k, actn);      // encryption key, actual nonce
	lua_pushlstring (L, c, cln); 
	return 1;
} // ll_gimli_encrypt()

int ll_gimli_decrypt(lua_State *L) {
	// Lua API: decrypt(k, n, c [, prefln [, ninc]]) 
	//     return m, or (nil, msg)
	//  k: key string (32 bytes)
	//  n: nonce string (16 bytes)
	//	c: encrypted message string 
	//  prefln: length of the prefix (default to 0)
	//  ninc: optional nonce increment (see above. defaults to 0)
	//  return plain text or (nil, errmsg) if MAC is not valid
	int r = 0;
	size_t cln, nln, kln, mln;
	const char *k = luaL_checklstring(L, 1, &kln);
	const char *n = luaL_checklstring(L, 2, &nln);	
	const char *c = luaL_checklstring(L, 3, &cln);	
	size_t prefln = luaL_optinteger(L, 4, 0);	
	uint64_t ninc = luaL_optinteger(L, 5, 0);	
	if (kln != 32) LERR("bad key size");
	if (nln != 16) LERR("bad nonce size");
	// 
	char actn[16]; // actual nonce ("n + ninc")
	memcpy(actn, n, 16); 
	// addition modulo 2^64 over the first 8 bytes of n
	// (overflow not an issue: uint addition overflow _is_ defined)
	(*(uint64_t *) actn) = (*(uint64_t *) actn) + ninc;
	//
	// cannot test "mln < 0" because mln is size_t is unsigned!!
	if (cln < prefln + 16) {  
		lua_pushnil (L);
		lua_pushliteral(L, "encrypted size error");
		return 2;         
	} 
	mln = cln - prefln - 16;
	u8 *m = lua_newuserdata(L, mln);
	r = gim_decrypt(
		m,
		c + prefln,      // expected MAC
		c + prefln + 16, // encrypted stream
		mln,             // length of encrypted stream
		k, actn);        // key anc actual nonce
			
	if (r != 0) { 
		lua_pushnil (L);
		lua_pushliteral(L, "decrypt error");
		return 2;         
	} 
	lua_pushlstring (L, m, mln); 
	return 1;
} // ll_gimli_decrypt()


//~ void gimli_hash(const uint8_t *input,
	//~ uint64_t inputByteLen,
	//~ uint8_t *output,
	//~ uint64_t outputByteLen)
int ll_gimli_hash(lua_State *L) {
	//
	size_t mln, hln, kln;
	const u8 *m = luaL_checklstring(L, 1, &mln);
	hln = luaL_optinteger(L, 2, 16);	
	//~ const u8 *k = luaL_optlstring(L,3,"",&kln);
	//~ if (kln != 32) LERR("bad key size");
	// 
	u8 hbuf[64];
	u8 *h = hbuf;
	if (hln > 64) {
		h = lua_newuserdata(L, hln);
	}
	gimli_hash(m, mln, h, hln);
	lua_pushlstring (L, h, hln); 
	return 1;
} // ll_gimli_hash()
