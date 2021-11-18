// Copyright (c) 2019  Phil Leblanc  -- see LICENSE file
// ---------------------------------------------------------------------
//
// Ascon-128a  -- 64-bit optimized version
//
// Ascon is one of the selected AEAD encryption algorithm in the CAESAR 
// competition http://competitions.cr.yp.to/caesar-submissions.html
//
// Ascon home: https://ascon.iaik.tugraz.at/
//
// Ascon Authors: 
// Christoph Dobraunig, Maria Eichlseder, Florian Mendel, Martin Schläffer,
// Graz University of Technology, Infineon Technologies, and Radboud 
// University. 
//
// this code includes the C reference code v1.2 for Ascon-128a
// (128-bit key, nonce and MAC)
//
// ---------------------------------------------------------------------


#include <stdio.h>
//~ #include <inttypes.h>
#include <string.h>
#include <stdint.h>

//----------------------------------------------------------------------
// debug functions

#define pmsg(x) printf("== %s\n", x);
#define pxln(msg, x, ln) printf("== %s  %x  %d\n", msg, x, ln)

#ifdef DEBUG
static void p48(uint64_t a, uint64_t b, uint64_t c, uint64_t d) {
	//~ printf("%016I64x %016I64x %016I64x %016I64x \n", a, b, c, d);
	printf("%016llx %016llx %016llx %016llx \n", a, b, c, d);
}
static void pst(uint64_t s[][4]) {
	p48(s[0][0],s[0][1],s[0][2],s[0][3]);
	p48(s[1][0],s[1][1],s[1][2],s[1][3]);
	p48(s[2][0],s[2][1],s[2][2],s[2][3]);
	p48(s[3][0],s[3][1],s[3][2],s[3][3]);
	p48(s[4][0],s[4][1],s[4][2],s[4][3]);
	printf("---\n");
}//pst

#endif

//----------------------------------------------------------------------
// ascon128av12/ref code


#include <stdio.h>

//~ #include "api.h"
#define CRYPTO_KEYBYTES 16
#define CRYPTO_NSECBYTES 0
#define CRYPTO_NPUBBYTES 16
#define CRYPTO_ABYTES 16
#define CRYPTO_NOOVERLAP 1

//~ #include "crypto_aead.h"


typedef unsigned char u8;
typedef unsigned long long u64;
typedef long long i64;


#define LITTLE_ENDIAN
//#define BIG_ENDIAN

#define RATE (128 / 8)
#define PA_ROUNDS 12
#define PB_ROUNDS 8

#define ROTR(x,n) (((x)>>(n))|((x)<<(64-(n))))

#ifdef BIG_ENDIAN
#define EXT_BYTE(x,n) ((u8)((u64)(x)>>(8*(n))))
#define INS_BYTE(x,n) ((u64)(x)<<(8*(n)))
#define U64BIG(x) (x)
#endif

#ifdef LITTLE_ENDIAN
#define EXT_BYTE(x,n) ((u8)((u64)(x)>>(8*(7-(n)))))
#define INS_BYTE(x,n) ((u64)(x)<<(8*(7-(n))))
#define U64BIG(x) \
    ((ROTR(x, 8) & (0xFF000000FF000000ULL)) | \
     (ROTR(x,24) & (0x00FF000000FF0000ULL)) | \
     (ROTR(x,40) & (0x0000FF000000FF00ULL)) | \
     (ROTR(x,56) & (0x000000FF000000FFULL)))
#endif

static const int R[5][2] = { {19, 28}, {39, 61}, {1, 6}, {10, 17}, {7, 41} };

#define ROUND(C) {\
    x2 ^= C;\
    x0 ^= x4;\
    x4 ^= x3;\
    x2 ^= x1;\
    t0 = x0;\
    t4 = x4;\
    t3 = x3;\
    t1 = x1;\
    t2 = x2;\
    x0 = t0 ^ ((~t1) & t2);\
    x2 = t2 ^ ((~t3) & t4);\
    x4 = t4 ^ ((~t0) & t1);\
    x1 = t1 ^ ((~t2) & t3);\
    x3 = t3 ^ ((~t4) & t0);\
    x1 ^= x0;\
    t1  = x1;\
    x1 = ROTR(x1, R[1][0]);\
    x3 ^= x2;\
    t2  = x2;\
    x2 = ROTR(x2, R[2][0]);\
    t4  = x4;\
    t2 ^= x2;\
    x2 = ROTR(x2, R[2][1] - R[2][0]);\
    t3  = x3;\
    t1 ^= x1;\
    x3 = ROTR(x3, R[3][0]);\
    x0 ^= x4;\
    x4 = ROTR(x4, R[4][0]);\
    t3 ^= x3;\
    x2 ^= t2;\
    x1 = ROTR(x1, R[1][1] - R[1][0]);\
    t0  = x0;\
    x2 = ~x2;\
    x3 = ROTR(x3, R[3][1] - R[3][0]);\
    t4 ^= x4;\
    x4 = ROTR(x4, R[4][1] - R[4][0]);\
    x3 ^= t3;\
    x1 ^= t1;\
    x0 = ROTR(x0, R[0][0]);\
    x4 ^= t4;\
    t0 ^= x0;\
    x0 = ROTR(x0, R[0][1] - R[0][0]);\
    x0 ^= t0;\
  }

#define P12 {\
  ROUND(0xf0);\
  ROUND(0xe1);\
  ROUND(0xd2);\
  ROUND(0xc3);\
  ROUND(0xb4);\
  ROUND(0xa5);\
  ROUND(0x96);\
  ROUND(0x87);\
  ROUND(0x78);\
  ROUND(0x69);\
  ROUND(0x5a);\
  ROUND(0x4b);\
}

#define P8 {\
  ROUND(0xb4);\
  ROUND(0xa5);\
  ROUND(0x96);\
  ROUND(0x87);\
  ROUND(0x78);\
  ROUND(0x69);\
  ROUND(0x5a);\
  ROUND(0x4b);\
}

static int crypto_aead_encrypt(
    unsigned char *c, unsigned long long *clen,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *nsec,
    const unsigned char *npub,
    const unsigned char *k) {

  u64 K0 = U64BIG(((u64*)k)[0]);
  u64 K1 = U64BIG(((u64*)k)[1]);
  u64 N0 = U64BIG(((u64*)npub)[0]);
  u64 N1 = U64BIG(((u64*)npub)[1]);
  u64 x0, x1, x2, x3, x4;
  u64 t0, t1, t2, t3, t4;
  u64 rlen;
  int i;

  // initialization
  x0 = (u64)((CRYPTO_KEYBYTES * 8) << 24 | (RATE * 8) << 16 | PA_ROUNDS << 8 | PB_ROUNDS << 0) << 32;
  x1 = K0;
  x2 = K1;
  x3 = N0;
  x4 = N1;
  P12;
  x3 ^= K0;
  x4 ^= K1;

  // process associated data
  if (adlen) {
    rlen = adlen;
    while (rlen >= RATE) {
      x0 ^= U64BIG(*(u64*)ad);
      x1 ^= U64BIG(*(u64*)(ad + 8));
      P8;
      rlen -= RATE;
      ad += RATE;
    }
    for (i = 0; i < rlen; ++i, ++ad)
      if (i < 8)
        x0 ^= INS_BYTE(*ad, i);
      else
        x1 ^= INS_BYTE(*ad, i);
    if (rlen < 8)
      x0 ^= INS_BYTE(0x80, rlen);
    else
      x1 ^= INS_BYTE(0x80, rlen);
    P8;
  }
  x4 ^= 1;

  // process plaintext
  rlen = mlen;
  while (rlen >= RATE) {
    x0 ^= U64BIG(*(u64*)m);
    x1 ^= U64BIG(*(u64*)(m + 8));
    *(u64*)c = U64BIG(x0);
    *(u64*)(c + 8) = U64BIG(x1);
    P8;
    rlen -= RATE;
    m += RATE;
    c += RATE;
  }
  for (i = 0; i < rlen; ++i, ++m, ++c) {
    if (i < 8) {
      x0 ^= INS_BYTE(*m, i);
      *c = EXT_BYTE(x0, i);
    } else {
      x1 ^= INS_BYTE(*m, i);
      *c = EXT_BYTE(x1, i);
    }
  }
  if (rlen < 8)
    x0 ^= INS_BYTE(0x80, rlen);
  else
    x1 ^= INS_BYTE(0x80, rlen);

  // finalization
  x2 ^= K0;
  x3 ^= K1;
  P12;
  x3 ^= K0;
  x4 ^= K1;

  // return tag
  ((u64*)c)[0] = U64BIG(x3);
  ((u64*)c)[1] = U64BIG(x4);
  *clen = mlen + CRYPTO_KEYBYTES;

  return 0;
}

static int crypto_aead_decrypt(
    unsigned char *m, unsigned long long *mlen,
    unsigned char *nsec,
    const unsigned char *c, unsigned long long clen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *npub,
    const unsigned char *k) {

  *mlen = 0;
  if (clen < CRYPTO_KEYBYTES)
    return -1;

  u64 K0 = U64BIG(((u64*)k)[0]);
  u64 K1 = U64BIG(((u64*)k)[1]);
  u64 N0 = U64BIG(((u64*)npub)[0]);
  u64 N1 = U64BIG(((u64*)npub)[1]);
  u64 x0, x1, x2, x3, x4;
  u64 t0, t1, t2, t3, t4;
  u64 rlen;
  int i;

  // initialization
  x0 = (u64)((CRYPTO_KEYBYTES * 8) << 24 | (RATE * 8) << 16 | PA_ROUNDS << 8 | PB_ROUNDS << 0) << 32;
  x1 = K0;
  x2 = K1;
  x3 = N0;
  x4 = N1;
  P12;
  x3 ^= K0;
  x4 ^= K1;

  // process associated data
  if (adlen) {
    rlen = adlen;
    while (rlen >= RATE) {
      x0 ^= U64BIG(*(u64*)ad);
      x1 ^= U64BIG(*(u64*)(ad + 8));
      P8;
      rlen -= RATE;
      ad += RATE;
    }
    for (i = 0; i < rlen; ++i, ++ad)
      if (i < 8)
        x0 ^= INS_BYTE(*ad, i);
      else
        x1 ^= INS_BYTE(*ad, i);
    if (rlen < 8)
      x0 ^= INS_BYTE(0x80, rlen);
    else
      x1 ^= INS_BYTE(0x80, rlen);
    P8;
  }
  x4 ^= 1;

  // process plaintext
  rlen = clen - CRYPTO_KEYBYTES;
  while (rlen >= RATE) {
    *(u64*)m = U64BIG(x0) ^ *(u64*)c;
    *(u64*)(m + 8) = U64BIG(x1) ^ *(u64*)(c + 8);
    x0 = U64BIG(*((u64*)c));
    x1 = U64BIG(*((u64*)(c + 8)));
    P8;
    rlen -= RATE;
    m += RATE;
    c += RATE;
  }
  for (i = 0; i < rlen; ++i, ++m, ++c) {
    if (i < 8) {
      *m = EXT_BYTE(x0, i) ^ *c;
      x0 &= ~INS_BYTE(0xff, i);
      x0 |= INS_BYTE(*c, i);
    } else {
      *m = EXT_BYTE(x1, i) ^ *c;
      x1 &= ~INS_BYTE(0xff, i);
      x1 |= INS_BYTE(*c, i);
    }
  }
  if (rlen < 8)
    x0 ^= INS_BYTE(0x80, rlen);
  else
    x1 ^= INS_BYTE(0x80, rlen);

  // finalization
  x2 ^= K0;
  x3 ^= K1;
  P12;
  x3 ^= K0;
  x4 ^= K1;

  // return -1 if verification fails
  if (((u64*)c)[0] != U64BIG(x3) ||
      ((u64*)c)[1] != U64BIG(x4))
    return -1;

  // return plaintext
  *mlen = clen - CRYPTO_KEYBYTES;
  return 0;
}//crypto_aead_decrypt


// ---------------------------------------------------------------------
// Lua binding

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "lua.h"
#include "lauxlib.h"
#define LERR(msg) return luaL_error(L, msg)

//----------------------------------------------------------------------


int ll_ascon_encrypt(lua_State *L) {
	// Lua API: encrypt(k, n, m [, ninc [, aad ]])  return c
	//  k: key string (16 bytes)
	//  n: nonce string (16 bytes)
	//  m: message (plain text) string 
	//  aad: additional data prefix  (not encrypted, prepended to the 
	//       encrypted message). default to the empty string
	//  ninc: optional nonce increment (useful when encrypting a 
	//       long message as a sequence of block). 
	//       The same nonce n can be used for the sequence. 
	//       ninc is added to n for each block, so the actual
	//       nonce used for each block encryption is distinct.
	//       ninc defaults to 0 (the nonce n is used as-is)
	//  return encrypted text string c with aad prefix 
	//  (c includes the 16-byte MAC: #c = #aad + #m + 16)
	int r;
	size_t mln, nln, kln, aadln, bufln;
	const char *k = luaL_checklstring(L,1,&kln);
	const char *n = luaL_checklstring(L,2,&nln);	
	const char *m = luaL_checklstring(L,3,&mln);	
	uint64_t ninc = luaL_optinteger(L, 4, 0);	
	const char *aad = luaL_optlstring(L,5,"",&aadln);
//~ if (m == 0) {  printf("@@@ m=NULL \n"); }
//~ printf("@@@ m=%x \n", m);
	if (nln != 16) LERR("bad nonce size");
	if (kln != 16) LERR("bad key size");
	bufln = aadln + mln + 16;

	char * buf = lua_newuserdata(L, bufln);

// compute actual nonce "n + ninc"
	char actn[16]; 
	memcpy(actn, n, 16); 
	// addition modulo 2^64 over the first 8 bytes of n
	// (uint addition overflow _is_ defined)
	(*(uint64_t *) actn) = (*(uint64_t *) actn) + ninc;
	//
	memcpy(buf, aad, aadln); 
	unsigned long long cln;
	crypto_aead_encrypt(
		buf+aadln, &cln, 
		m, mln, 
		aad, aadln, 
		0, actn, 
		k);
	if (cln != mln+16) LERR("bad result size");
	lua_pushlstring (L, buf, bufln); 
	return 1;
} // ll_ascon_encrypt()

int ll_ascon_decrypt(lua_State *L) {
	// Lua API: decrypt(k, n, c [, ninc [, aadln]]) 
	//     return m | (nil, msg)
	//  k: key string (16 bytes)
	//  n: nonce string (16 bytes)
	//  c: encrypted message string 
	//  ninc: optional nonce increment (see above. defaults to 0)
	//  aadln: length of the AD prefix (default to 0)
	//  return plain text or (nil, errmsg) if MAC is not valid
	int r = 0;
	size_t cln, nln, kln, boxln;
	const char *k = luaL_checklstring(L, 1, &kln);
	const char *n = luaL_checklstring(L, 2, &nln);	
	const char *c = luaL_checklstring(L, 3, &cln);	
	uint64_t ninc = luaL_optinteger(L, 4, 0);	
	size_t aadln = luaL_optinteger(L, 5, 0);	
	if (nln != 16) LERR("bad nonce size");
	if (kln != 16) LERR("bad key size");
	// allocate buffer for decrypted text
	boxln = cln - aadln;
	unsigned char * buf = lua_newuserdata(L, boxln);
	// compute actual nonce "n + ninc"
	char actn[16]; 
	memcpy(actn, n, 16); 
	(*(uint64_t *) actn) = (*(uint64_t *) actn) + ninc;
	//
	unsigned long long mln;
	r = crypto_aead_decrypt(buf, &mln, 0, 
		c+aadln, boxln, c, aadln, actn, k);
	if (r != 0) { 
		lua_pushnil (L);
		lua_pushliteral(L, "decrypt error");
		return 2;         
	} 
	lua_pushlstring (L, buf, mln); 
	return 1;
	
} // ll_ascon_decrypt()


