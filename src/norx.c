// Copyright (c) 2018  Phil Leblanc  -- see LICENSE file
// ---------------------------------------------------------------------
//
// NORX authenticated encryption - https://norx.io/
//
// ---------------------------------------------------------------------
// Original NORX public domain dedication:

/*
 * NORX reference source code package - reference C implementations
 *
 * Written 2014-2016 by:
 *
 *      - Samuel Neves <sneves@dei.uc.pt>
 *      - Philipp Jovanovic <philipp@jovanovic.io>
 *
 * To the extent possible under law, the author(s) have dedicated all copyright
 * and related and neighboring rights to this software to the public domain
 * worldwide. This software is distributed without any warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication along with
 * this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */
 
//----------------------------------------------------------------------
//-- content of original file norx_config.h

#define NORX_W 64           /* Word size */
#define NORX_L 4            /* Round number */
#define NORX_P 1            /* Parallelism degree */
#define NORX_T (NORX_W * 4) /* Tag size */

//----------------------------------------------------------------------
//-- content of original file norx.h

#include <stddef.h>
#include <stdint.h>

#if   NORX_W == 64
	typedef uint64_t norx_word_t;
#elif NORX_W == 32
	typedef uint32_t norx_word_t;
#else
	#error "Invalid word size!"
#endif

typedef struct norx_state__
{
    norx_word_t S[16];
} norx_state_t[1];

typedef enum tag__
{
    HEADER_TAG  = 0x01,
    PAYLOAD_TAG = 0x02,
    TRAILER_TAG = 0x04,
    FINAL_TAG   = 0x08,
    BRANCH_TAG  = 0x10,
    MERGE_TAG   = 0x20
} tag_t;

/* High-level operations */
void norx_aead_encrypt(
        unsigned char *c, size_t *clen,
        const unsigned char *a, size_t alen,
        const unsigned char *m, size_t mlen,
        const unsigned char *z, size_t zlen,
        const unsigned char *nonce, const unsigned char *key);

int norx_aead_decrypt(
        unsigned char *m, size_t *mlen,
        const unsigned char *a, size_t alen,
        const unsigned char *c, size_t clen,
        const unsigned char *z, size_t zlen,
        const unsigned char *nonce, const unsigned char *key);

//----------------------------------------------------------------------
//-- content of original file norx_util.h

/* Workaround for C89 compilers */
#if !defined(__cplusplus) && (!defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L)
  #if   defined(_MSC_VER)
    #define NORX_INLINE __inline
  #elif defined(__GNUC__)
    #define NORX_INLINE __inline__
  #else
    #define NORX_INLINE
  #endif
#else
  #define NORX_INLINE inline
#endif

#include <limits.h>
#include <stddef.h>
#include <string.h>
#include <stdint.h>

#define STR_(x) #x
#define STR(x) STR_(x)
#define PASTE_(A, B, C) A ## B ## C
#define PASTE(A, B, C) PASTE_(A, B, C)
#define BYTES(x) (((x) + 7) / 8)
#define WORDS(x) (((x) + (NORX_W-1)) / NORX_W)

#define BITS(x) (sizeof(x) * CHAR_BIT)
#define ROTL(x, c) ( ((x) << (c)) | ((x) >> (BITS(x) - (c))) )
#define ROTR(x, c) ( ((x) >> (c)) | ((x) << (BITS(x) - (c))) )

static NORX_INLINE uint32_t load32(const void * in)
{
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    uint32_t v;
    memcpy(&v, in, sizeof v);
    return v;
#else
    const uint8_t * p = (const uint8_t *)in;
    return ((uint32_t)p[0] <<  0) |
           ((uint32_t)p[1] <<  8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
#endif
}


static NORX_INLINE uint64_t load64(const void * in)
{
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    uint64_t v;
    memcpy(&v, in, sizeof v);
    return v;
#else
    const uint8_t * p = (const uint8_t *)in;
    return ((uint64_t)p[0] <<  0) |
           ((uint64_t)p[1] <<  8) |
           ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) |
           ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) |
           ((uint64_t)p[7] << 56);
#endif
}


static NORX_INLINE void store32(void * out, const uint32_t v)
{
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    memcpy(out, &v, sizeof v);
#else
    uint8_t * p = (uint8_t *)out;
    p[0] = (uint8_t)(v >>  0);
    p[1] = (uint8_t)(v >>  8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
#endif
}


static NORX_INLINE void store64(void * out, const uint64_t v)
{
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    memcpy(out, &v, sizeof v);
#else
    uint8_t * p = (uint8_t *)out;
    p[0] = (uint8_t)(v >>  0);
    p[1] = (uint8_t)(v >>  8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32);
    p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48);
    p[7] = (uint8_t)(v >> 56);
#endif
}

static void* (* const volatile burn)(void*, int, size_t) = memset;

//----------------------------------------------------------------------
//-- content of original file norx.c

#include <stdlib.h>


const char * norx_version = "3.0";

#define NORX_N (NORX_W *  4)     /* Nonce size */
#define NORX_K (NORX_W *  4)     /* Key size */
#define NORX_B (NORX_W * 16)     /* Permutation width */
#define NORX_C (NORX_W *  4)     /* Capacity */
#define NORX_R (NORX_B - NORX_C) /* Rate */

#if NORX_W == 32 /* NORX32 specific */

    #define LOAD load32
    #define STORE store32

    /* Rotation constants */
    #define R0  8
    #define R1 11
    #define R2 16
    #define R3 31

#elif NORX_W == 64 /* NORX64 specific */

    #define LOAD load64
    #define STORE store64

    /* Rotation constants */
    #define R0  8
    #define R1 19
    #define R2 40
    #define R3 63

#else
    #error "Invalid word size!"
#endif

#if defined(NORX_DEBUG)

#include <stdio.h>
#include <inttypes.h>

#if   NORX_W == 32
    #define NORX_FMT "08" PRIX32
#elif NORX_W == 64
    #define NORX_FMT "016" PRIX64
#endif

static void norx_print_state(norx_state_t state)
{
    static const char fmt[] = "%" NORX_FMT " "
                              "%" NORX_FMT " "
                              "%" NORX_FMT " "
                              "%" NORX_FMT "\n";
    const norx_word_t * S = state->S;
    printf(fmt, S[ 0],S[ 1],S[ 2],S[ 3]);
    printf(fmt, S[ 4],S[ 5],S[ 6],S[ 7]);
    printf(fmt, S[ 8],S[ 9],S[10],S[11]);
    printf(fmt, S[12],S[13],S[14],S[15]);
    printf("\n");
}

static void print_bytes(const uint8_t *in, size_t inlen)
{
    size_t i;
    for (i = 0; i < inlen; ++i) {
        printf("%02X%c", in[i], i%16 == 15 ? '\n' : ' ');
    }
    if (inlen%16 != 0) {
        printf("\n");
    }
}

static void norx_debug(norx_state_t state, const uint8_t *in, size_t inlen, const uint8_t *out, size_t outlen)
{
    if (in != NULL && inlen > 0) {
        printf("In:\n");
        print_bytes(in, inlen);
    }
    if (out != NULL && outlen > 0) {
        printf("Out:\n");
        print_bytes(out, outlen);
    }
    printf("State:\n");
    norx_print_state(state);
}

#endif

/* The nonlinear primitive */
#define H(A, B) ( ( (A) ^ (B) ) ^ ( ( (A) & (B) ) << 1) )

/* The quarter-round */
#define G(A, B, C, D)                               \
do                                                  \
{                                                   \
    (A) = H(A, B); (D) ^= (A); (D) = ROTR((D), R0); \
    (C) = H(C, D); (B) ^= (C); (B) = ROTR((B), R1); \
    (A) = H(A, B); (D) ^= (A); (D) = ROTR((D), R2); \
    (C) = H(C, D); (B) ^= (C); (B) = ROTR((B), R3); \
} while (0)

/* The full round */
static NORX_INLINE void F(norx_word_t S[16])
{
    /* Column step */
    G(S[ 0], S[ 4], S[ 8], S[12]);
    G(S[ 1], S[ 5], S[ 9], S[13]);
    G(S[ 2], S[ 6], S[10], S[14]);
    G(S[ 3], S[ 7], S[11], S[15]);
    /* Diagonal step */
    G(S[ 0], S[ 5], S[10], S[15]);
    G(S[ 1], S[ 6], S[11], S[12]);
    G(S[ 2], S[ 7], S[ 8], S[13]);
    G(S[ 3], S[ 4], S[ 9], S[14]);
}

/* The core permutation */
static NORX_INLINE void norx_permute(norx_state_t state)
{
    size_t i;
    norx_word_t * S = state->S;

    for (i = 0; i < NORX_L; ++i) {
        F(S);
    }
}

static NORX_INLINE void norx_pad(uint8_t *out, const uint8_t *in, const size_t inlen)
{
    memset(out, 0, BYTES(NORX_R));
    memcpy(out, in, inlen);
    out[inlen] = 0x01;
    out[BYTES(NORX_R) - 1] |= 0x80;
}

static NORX_INLINE void norx_absorb_block(norx_state_t state, const uint8_t * in, tag_t tag)
{
    size_t i;
    norx_word_t * S = state->S;

    S[15] ^= tag;
    norx_permute(state);

    for (i = 0; i < WORDS(NORX_R); ++i) {
        S[i] ^= LOAD(in + i * BYTES(NORX_W));
    }
}

static NORX_INLINE void norx_absorb_lastblock(norx_state_t state, const uint8_t * in, size_t inlen, tag_t tag)
{
    uint8_t lastblock[BYTES(NORX_R)];
    norx_pad(lastblock, in, inlen);
    norx_absorb_block(state, lastblock, tag);
}

static NORX_INLINE void norx_encrypt_block(norx_state_t state, uint8_t *out, const uint8_t * in)
{
    size_t i;
    norx_word_t * S = state->S;

    S[15] ^= PAYLOAD_TAG;
    norx_permute(state);

    for (i = 0; i < WORDS(NORX_R); ++i) {
        S[i] ^= LOAD(in + i * BYTES(NORX_W));
        STORE(out + i * BYTES(NORX_W), S[i]);
    }
}

static NORX_INLINE void norx_encrypt_lastblock(norx_state_t state, uint8_t *out, const uint8_t * in, size_t inlen)
{
    uint8_t lastblock[BYTES(NORX_R)];
    norx_pad(lastblock, in, inlen);
    norx_encrypt_block(state, lastblock, lastblock);
    memcpy(out, lastblock, inlen);
}

static NORX_INLINE void norx_decrypt_block(norx_state_t state, uint8_t *out, const uint8_t * in)
{
    size_t i;
    norx_word_t * S = state->S;

    S[15] ^= PAYLOAD_TAG;
    norx_permute(state);

    for (i = 0; i < WORDS(NORX_R); ++i) {
        const norx_word_t c = LOAD(in + i * BYTES(NORX_W));
        STORE(out + i * BYTES(NORX_W), S[i] ^ c);
        S[i] = c;
    }
}

static NORX_INLINE void norx_decrypt_lastblock(norx_state_t state, uint8_t *out, const uint8_t * in, size_t inlen)
{
    norx_word_t * S = state->S;
    uint8_t lastblock[BYTES(NORX_R)];
    size_t i;

    S[15] ^= PAYLOAD_TAG;
    norx_permute(state);

    for(i = 0; i < WORDS(NORX_R); ++i) {
        STORE(lastblock + i * BYTES(NORX_W), S[i]);
    }

    memcpy(lastblock, in, inlen);
    lastblock[inlen] ^= 0x01;
    lastblock[BYTES(NORX_R) - 1] ^= 0x80;

    for (i = 0; i < WORDS(NORX_R); ++i) {
        const norx_word_t c = LOAD(lastblock + i * BYTES(NORX_W));
        STORE(lastblock + i * BYTES(NORX_W), S[i] ^ c);
        S[i] = c;
    }

    memcpy(out, lastblock, inlen);
    burn(lastblock, 0, sizeof lastblock);
}

/* Low-level operations */
static NORX_INLINE void norx_init(norx_state_t state, const unsigned char *k, const unsigned char *n)
{
    norx_word_t * S = state->S;
    size_t i;

    for(i = 0; i < 16; ++i) {
        S[i] = i;
    }

    F(S);
    F(S);

    S[ 0] = LOAD(n + 0 * BYTES(NORX_W));
    S[ 1] = LOAD(n + 1 * BYTES(NORX_W));
    S[ 2] = LOAD(n + 2 * BYTES(NORX_W));
    S[ 3] = LOAD(n + 3 * BYTES(NORX_W));

    S[ 4] = LOAD(k + 0 * BYTES(NORX_W));
    S[ 5] = LOAD(k + 1 * BYTES(NORX_W));
    S[ 6] = LOAD(k + 2 * BYTES(NORX_W));
    S[ 7] = LOAD(k + 3 * BYTES(NORX_W));

    S[12] ^= NORX_W;
    S[13] ^= NORX_L;
    S[14] ^= NORX_P;
    S[15] ^= NORX_T;

    norx_permute(state);

    S[12] ^= LOAD(k + 0 * BYTES(NORX_W));
    S[13] ^= LOAD(k + 1 * BYTES(NORX_W));
    S[14] ^= LOAD(k + 2 * BYTES(NORX_W));
    S[15] ^= LOAD(k + 3 * BYTES(NORX_W));

#if defined(NORX_DEBUG)
    printf("Initialise\n");
    norx_debug(state, NULL, 0, NULL, 0);
#endif
}

void norx_absorb_data(norx_state_t state, const unsigned char * in, size_t inlen, tag_t tag)
{
    if (inlen > 0)
    {
        while (inlen >= BYTES(NORX_R))
        {
            norx_absorb_block(state, in, tag);
            #if defined(NORX_DEBUG)
            printf("Absorb block\n");
            norx_debug(state, in, BYTES(NORX_R), NULL, 0);
            #endif
            inlen -= BYTES(NORX_R);
            in += BYTES(NORX_R);
        }
        norx_absorb_lastblock(state, in, inlen, tag);
        #if defined(NORX_DEBUG)
        printf("Absorb lastblock\n");
        norx_debug(state, in, inlen, NULL, 0);
        #endif
    }
}

void norx_encrypt_data(norx_state_t state, unsigned char *out, const unsigned char * in, size_t inlen)
{
    if (inlen > 0)
    {
        while (inlen >= BYTES(NORX_R))
        {
            norx_encrypt_block(state, out, in);
            #if defined(NORX_DEBUG)
            printf("Encrypt block\n");
            norx_debug(state, in, BYTES(NORX_R), out, BYTES(NORX_R));
            #endif
            inlen -= BYTES(NORX_R);
            in    += BYTES(NORX_R);
            out   += BYTES(NORX_R);
        }
        norx_encrypt_lastblock(state, out, in, inlen);
        #if defined(NORX_DEBUG)
        printf("Encrypt lastblock\n");
        norx_debug(state, in, inlen, out, inlen);
        #endif
    }
}

void norx_decrypt_data(norx_state_t state, unsigned char *out, const unsigned char * in, size_t inlen)
{
    if (inlen > 0)
    {
        while (inlen >= BYTES(NORX_R))
        {
            norx_decrypt_block(state, out, in);
            #if defined(NORX_DEBUG)
            printf("Decrypt block\n");
            norx_debug(state, in, BYTES(NORX_R), out, BYTES(NORX_R));
            #endif
            inlen -= BYTES(NORX_R);
            in    += BYTES(NORX_R);
            out   += BYTES(NORX_R);
        }
        norx_decrypt_lastblock(state, out, in, inlen);
        #if defined(NORX_DEBUG)
        printf("Decrypt lastblock\n");
        norx_debug(state, in, inlen, out, inlen);
        #endif
    }
}

static NORX_INLINE void norx_finalise(norx_state_t state, unsigned char * tag, const unsigned char * k)
{
    norx_word_t * S = state->S;
    uint8_t lastblock[BYTES(NORX_C)];

    S[15] ^= FINAL_TAG;

    norx_permute(state);

    S[12] ^= LOAD(k + 0 * BYTES(NORX_W));
    S[13] ^= LOAD(k + 1 * BYTES(NORX_W));
    S[14] ^= LOAD(k + 2 * BYTES(NORX_W));
    S[15] ^= LOAD(k + 3 * BYTES(NORX_W));

    norx_permute(state);

    S[12] ^= LOAD(k + 0 * BYTES(NORX_W));
    S[13] ^= LOAD(k + 1 * BYTES(NORX_W));
    S[14] ^= LOAD(k + 2 * BYTES(NORX_W));
    S[15] ^= LOAD(k + 3 * BYTES(NORX_W));

    STORE(lastblock + 0 * BYTES(NORX_W), S[12]);
    STORE(lastblock + 1 * BYTES(NORX_W), S[13]);
    STORE(lastblock + 2 * BYTES(NORX_W), S[14]);
    STORE(lastblock + 3 * BYTES(NORX_W), S[15]);

    memcpy(tag, lastblock, BYTES(NORX_T));

    #if defined(NORX_DEBUG)
    printf("Finalise\n");
    norx_debug(state, NULL, 0, NULL, 0);
    #endif

    burn(lastblock, 0, BYTES(NORX_C)); /* burn buffer */
    burn(state, 0, sizeof(norx_state_t)); /* at this point we can also burn the state */
}

/* Verify tags in constant time: 0 for success, -1 for fail */
int norx_verify_tag(const unsigned char * tag1, const unsigned char * tag2)
{
    size_t i;
    unsigned acc = 0;

    for (i = 0; i < BYTES(NORX_T); ++i) {
        acc |= tag1[i] ^ tag2[i];
    }

    return (((acc - 1) >> 8) & 1) - 1;
}

/* High-level operations */
void norx_aead_encrypt(
  unsigned char *c, size_t *clen,
  const unsigned char *a, size_t alen,
  const unsigned char *m, size_t mlen,
  const unsigned char *z, size_t zlen,
  const unsigned char *nonce,
  const unsigned char *key
)
{
    unsigned char k[BYTES(NORX_K)];
    norx_state_t state;

    memcpy(k, key, sizeof(k));
    norx_init(state, k, nonce);
    norx_absorb_data(state, a, alen, HEADER_TAG);
    norx_encrypt_data(state, c, m, mlen);
    norx_absorb_data(state, z, zlen, TRAILER_TAG);
    norx_finalise(state, c + mlen, k);
    *clen = mlen + BYTES(NORX_T);

    burn(state, 0, sizeof(norx_state_t));
    burn(k, 0, sizeof(k));
}

int norx_aead_decrypt(
  unsigned char *m, size_t *mlen,
  const unsigned char *a, size_t alen,
  const unsigned char *c, size_t clen,
  const unsigned char *z, size_t zlen,
  const unsigned char *nonce,
  const unsigned char *key
)
{
    unsigned char k[BYTES(NORX_K)];
    unsigned char tag[BYTES(NORX_T)];
    norx_state_t state;
    int result = -1;

    if (clen < BYTES(NORX_T)) {
        return -1;
    }

    memcpy(k, key, sizeof(k));
    norx_init(state, k, nonce);
    norx_absorb_data(state, a, alen, HEADER_TAG);
    norx_decrypt_data(state, m, c, clen - BYTES(NORX_T));
    norx_absorb_data(state, z, zlen, TRAILER_TAG);
    norx_finalise(state, tag, k);
    *mlen = clen - BYTES(NORX_T);

    result = norx_verify_tag(c + clen - BYTES(NORX_T), tag);
    if (result != 0) { /* burn decrypted plaintext on auth failure */
        burn(m, 0, clen - BYTES(NORX_T));
    }
    burn(state, 0, sizeof(norx_state_t));
    burn(k, 0, sizeof(k));
    return result;
}






// ---------------------------------------------------------------------
// Lua binding

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include "lua.h"
#include "lauxlib.h"
# define LERR(msg) return luaL_error(L, msg)

//----------------------------------------------------------------------


int ll_norx_encrypt(lua_State *L) {
	// Lua API: encrypt(k, n, m [, ninc [, aad [, zad]]])  return c
	//  k: key string (32 bytes)
	//  n: nonce string (32 bytes)
	//	m: message (plain text) string 
	//  ninc: optional nonce increment (useful when encrypting a long message
	//       as a sequence of block). The same parameter n can be used for 
	//       the sequence. ninc is added to n for each block, so the actual
	//       nonce used for each block encryption is distinct.
	//       ninc defaults to 0 (the nonce n is used as-is)
	//  aad: prefix additional data (not encrypted, prepended to the 
	//       encrypted message). default to the empty string
	//  zad: suffix additional data (not encrypted, appended to the 
	//       encrypted message). default to the empty string
	//  return encrypted text string c with aad prefix and zad suffix
	//  (c includes the 32-byte MAC: #c = #aad + #m + 32 + #zad)
	int r;
	size_t mln, nln, kln, aadln, zadln, cln, bufln;
	const char *k = luaL_checklstring(L,1,&kln);
	const char *n = luaL_checklstring(L,2,&nln);	
	const char *m = luaL_checklstring(L,3,&mln);	
	uint64_t ninc = luaL_optinteger(L, 4, 0);	
	const char *aad = luaL_optlstring(L,5,"",&aadln);
	const char *zad = luaL_optlstring(L,6,"",&zadln);
	if (nln != 32) LERR("bad nonce size");
	if (kln != 32) LERR("bad key size");
	bufln = aadln + mln + 32 + zadln;
	unsigned char * buf = malloc(bufln);
	char actn[32]; // actual nonce "n + ninc"
	memcpy(actn, n, 32); 
	// addition modulo 2^64 over the first 8 bytes of n
	// (uint addition overflow _is_ defined)
	(*(uint64_t *) actn) = (*(uint64_t *) actn) + ninc;
	norx_aead_encrypt(buf+aadln, &cln, aad, aadln, m, mln, 
	                  zad, zadln, actn, k);
	if (cln != mln+32) LERR("bad result size");
	memcpy(buf, aad, aadln); 
	memcpy(buf+aadln+cln, zad, zadln);
	lua_pushlstring (L, buf, bufln); 
	free(buf);
	return 1;
} // ll_norx_encrypt()

int ll_norx_decrypt(lua_State *L) {
	// Lua API: decrypt(k, n, c [, ninc [, aadln [, zadln]]]) 
	//     return (m, aad, zad) | (nil, msg)
	//  k: key string (32 bytes)
	//  n: nonce string (32 bytes)
	//	c: encrypted message string 
	//  ninc: optional nonce increment (see above. defaults to 0)
	//  aadln: length of the AD prefix (default to 0)
	//  zadln: length of the AD suffix  (default to 0)
	//  return (plain text, aad, zad) or (nil, errmsg) if MAC is not valid
	int r = 0;
	size_t cln, nln, kln, boxln, mln;
	const char *k = luaL_checklstring(L, 1, &kln);
	const char *n = luaL_checklstring(L, 2, &nln);	
	const char *c = luaL_checklstring(L, 3, &cln);	
	uint64_t ninc = luaL_optinteger(L, 4, 0);	
	size_t aadln = luaL_optinteger(L, 5, 0);	
	size_t zadln = luaL_optinteger(L, 6, 0);	
	if (nln != 32) LERR("bad nonce size");
	if (kln != 32) LERR("bad key size");
	boxln = cln - aadln - zadln;
	unsigned char * buf = malloc(boxln);
	char actn[32]; // actual nonce "n + ninc"
	memcpy(actn, n, 32); 
	(*(uint64_t *) actn) = (*(uint64_t *) actn) + ninc;
	r = norx_aead_decrypt(buf, &mln, c, aadln, c+aadln, 
						  boxln, c+aadln+boxln, zadln, actn, k);
	if (r != 0) { 
		free(buf); 
		lua_pushnil (L);
		lua_pushliteral(L, "decrypt error");
		return 2;         
	} 
	lua_pushlstring (L, buf, mln); 
	lua_pushlstring (L, c, aadln); 
	lua_pushlstring (L, c+aadln+boxln, zadln); 
	free(buf);
	return 3;
} // ll_norx_decrypt()

