// Copyright (c) 2018  Phil Leblanc  -- see LICENSE file
// ---------------------------------------------------------------------
//
// Morus-1280
//
//   1280-bit/160-byte state (as 20 uint64), 32-byte block
//   16 or 32-byte key, 16-byte nonce
//
// Morus Authors: Hongjun Wu, Tao Huang - Nanyang Tech University (NTU)
// http://www3.ntu.edu.sg/home/wuhj/research/caesar/caesar.html
//
// Morus is a finalist (round 4) in the CAESAR competition
// http://competitions.cr.yp.to/caesar-submissions.html
//
// this code is a slightly modified version of the C reference code v2
// submitted to CAESAR (see NTU link above)
//
//---
//
// NOTE: I have added an experimental hash / XOF function based on the 
// Morus permutation. It is NOT part of the Morus submission and has NOT 
// been analyzed / reviewed. The design is certainly not final.  
// => DON'T USE THE HASH FUNCTION for any serious purpose.
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

//~ #ifdef _MSC_VER
//~ #define inline __inline
//~ #endif

#define ROTN1 13
#define ROTN2 46
#define ROTN3 38
#define ROTN4 7
#define ROTN5 4

#define rotl(x,n)      (((x) << (n)) | ((x) >> (64-n)))

void morus_stateupdate(const uint64_t* msgblk, uint64_t state[][4])
{
	uint64_t temp, temp1;

	state[0][0] ^= state[3][0];
	state[0][1] ^= state[3][1];
	state[0][2] ^= state[3][2];
	state[0][3] ^= state[3][3];

	temp = state[3][3];
	state[3][3] = state[3][2];
	state[3][2] = state[3][1];
	state[3][1] = state[3][0];
	state[3][0] = temp;

	state[0][0] ^= state[1][0] & state[2][0];
	state[0][1] ^= state[1][1] & state[2][1];
	state[0][2] ^= state[1][2] & state[2][2];
	state[0][3] ^= state[1][3] & state[2][3];

	state[0][0] = rotl(state[0][0], ROTN1);
	state[0][1] = rotl(state[0][1], ROTN1);
	state[0][2] = rotl(state[0][2], ROTN1);
	state[0][3] = rotl(state[0][3], ROTN1);


	state[1][0] ^= msgblk[0];
	state[1][1] ^= msgblk[1];
	state[1][2] ^= msgblk[2];
	state[1][3] ^= msgblk[3];

	state[1][0] ^= state[4][0];
	state[1][1] ^= state[4][1];
	state[1][2] ^= state[4][2];
	state[1][3] ^= state[4][3];

	temp = state[4][3];
	state[4][3] = state[4][1];
	state[4][1] = temp;

	temp1 = state[4][2];
	state[4][2] = state[4][0];
	state[4][0] = temp1;

	state[1][0] ^= (state[2][0] & state[3][0]);
	state[1][1] ^= (state[2][1] & state[3][1]);
	state[1][2] ^= (state[2][2] & state[3][2]);
	state[1][3] ^= (state[2][3] & state[3][3]);

	state[1][0] = rotl(state[1][0], ROTN2);
	state[1][1] = rotl(state[1][1], ROTN2);
	state[1][2] = rotl(state[1][2], ROTN2);
	state[1][3] = rotl(state[1][3], ROTN2);


	state[2][0] ^= msgblk[0];
	state[2][1] ^= msgblk[1];
	state[2][2] ^= msgblk[2];
	state[2][3] ^= msgblk[3];

	state[2][0] ^= state[0][0];
	state[2][1] ^= state[0][1];
	state[2][2] ^= state[0][2];
	state[2][3] ^= state[0][3];

	temp = state[0][0];
	state[0][0] = state[0][1];
	state[0][1] = state[0][2];
	state[0][2] = state[0][3];
	state[0][3] = temp;

	state[2][0] ^= state[3][0] & state[4][0];
	state[2][1] ^= state[3][1] & state[4][1];
	state[2][2] ^= state[3][2] & state[4][2];
	state[2][3] ^= state[3][3] & state[4][3];

	state[2][0] = rotl(state[2][0], ROTN3);
	state[2][1] = rotl(state[2][1], ROTN3);
	state[2][2] = rotl(state[2][2], ROTN3);
	state[2][3] = rotl(state[2][3], ROTN3);


	state[3][0] ^= msgblk[0];
	state[3][1] ^= msgblk[1];
	state[3][2] ^= msgblk[2];
	state[3][3] ^= msgblk[3];

	state[3][0] ^= state[1][0];
	state[3][1] ^= state[1][1];
	state[3][2] ^= state[1][2];
	state[3][3] ^= state[1][3];

	temp = state[1][3];
	state[1][3] = state[1][1];
	state[1][1] = temp;

	temp1 = state[1][2];
	state[1][2] = state[1][0];
	state[1][0] = temp1;

	state[3][0] ^= state[4][0] & state[0][0];
	state[3][1] ^= state[4][1] & state[0][1];
	state[3][2] ^= state[4][2] & state[0][2];
	state[3][3] ^= state[4][3] & state[0][3];

	state[3][0] = rotl(state[3][0], ROTN4);
	state[3][1] = rotl(state[3][1], ROTN4);
	state[3][2] = rotl(state[3][2], ROTN4);
	state[3][3] = rotl(state[3][3], ROTN4);


	state[4][0] ^= msgblk[0];
	state[4][1] ^= msgblk[1];
	state[4][2] ^= msgblk[2];
	state[4][3] ^= msgblk[3];

	state[4][0] ^= state[2][0];
	state[4][1] ^= state[2][1];
	state[4][2] ^= state[2][2];
	state[4][3] ^= state[2][3];

	temp = state[2][3];
	state[2][3] = state[2][2];
	state[2][2] = state[2][1];
	state[2][1] = state[2][0];
	state[2][0] = temp;

	state[4][0] ^= state[0][0] & state[1][0];
	state[4][1] ^= state[0][1] & state[1][1];
	state[4][2] ^= state[0][2] & state[1][2];
	state[4][3] ^= state[0][3] & state[1][3];

	state[4][0] = rotl(state[4][0], ROTN5);
	state[4][1] = rotl(state[4][1], ROTN5);
	state[4][2] = rotl(state[4][2], ROTN5);
	state[4][3] = rotl(state[4][3], ROTN5);
	
}

/*The input to the initialization is the 128/256-bit key; 128-bit IV;*/
static void morus_initialization(
	const uint8_t *key, 
	const unsigned int keylen, // must be 16 or 32
	const uint8_t *iv, 
	uint64_t state[][4])
{
	int i;
	uint64_t temp[4] = { 0,0,0,0 };
	uint8_t con[32] = { 
		0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 
		0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62,  
		0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 
		0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd };
	uint64_t ekey[4];
	if (keylen == 16) {
		memcpy(ekey, key, 16);
		ekey[2] = ekey[0]; 
		ekey[3] = ekey[1]; 
	} else {
		memcpy(ekey, key, 32);
	}
	memcpy(state[0], iv, 16);   
	memset(state[0] + 2, 0, 16);
	memcpy(state[1], ekey, 32);
	memset(state[2], 0xff, 32);
	memset(state[3], 0, 32);
	memcpy(state[4], con, 32);

	for (i = 0; i < 4; i++) temp[i] = 0;
	for (i = 0; i < 16; i++) morus_stateupdate(temp, state);
	for (i = 0; i < 4; i++) state[1][i] ^= ((uint64_t*)ekey)[i];

} // morus_initialization

//the finalization state of MORUS
static void morus_tag_generation(
	uint64_t msglen, 
	uint64_t adlen, 
	uint8_t *c, 
	uint64_t state[][4])
{
	int i, j;
	uint8_t t[32];

	((uint64_t*)t)[0] = (adlen << 3);
	((uint64_t*)t)[1] = (msglen << 3);
	((uint64_t*)t)[2] = 0;
	((uint64_t*)t)[3] = 0;

	state[4][0] ^= state[0][0]; 
	state[4][1] ^= state[0][1]; 
	state[4][2] ^= state[0][2]; 
	state[4][3] ^= state[0][3];

	for (i = 0; i < 10; i++) morus_stateupdate((uint64_t*)t, state);

	for (j = 0; j < 4; j++) {
		state[0][j] ^= state[1][(j + 1) & 3] ^ (state[2][j] & state[3][j]);
	}
	//in this program, the mac length is assumed to be a multiple of bytes
	memcpy(c + msglen, state[0], 16);
}

static int morus_tag_verification(
	uint64_t msglen, 
	uint64_t adlen, 
	const uint8_t *c, 
	uint64_t state[][4])
{
	int i, j;
	uint8_t t[32];
	int check = 0;

	((uint64_t*)t)[0] = (adlen << 3);
	((uint64_t*)t)[1] = (msglen << 3);
	((uint64_t*)t)[2] = 0;
	((uint64_t*)t)[3] = 0;

	state[4][0] ^= state[0][0]; 
	state[4][1] ^= state[0][1]; 
	state[4][2] ^= state[0][2]; 
	state[4][3] ^= state[0][3];

	for (i = 0; i < 10; i++) morus_stateupdate((uint64_t*)t, state);

	for (j = 0; j < 4; j++) {
		state[0][j] ^= state[1][(j + 1) & 3] ^ (state[2][j] & state[3][j]);
	}
	for (i = 0; i < 16; i++) {
		check |= (c[msglen + i] ^ ((uint8_t *)state[0])[i]);
	}
	if (0 == check) return 0;
	else return -1;
}

// one step of encryption: it encrypts a 32-byte block
static void morus_enc_aut_step(
	const uint8_t *plaintextblock, 
	uint8_t *ciphertextblock, 
	uint64_t state[5][4])
{
	uint64_t temp, temp1;
	//encryption
	((uint64_t*)ciphertextblock)[0] = ((uint64_t*)plaintextblock)[0] 
		^ state[0][0] ^ state[1][1] ^ (state[2][0] & state[3][0]);
	((uint64_t*)ciphertextblock)[1] = ((uint64_t*)plaintextblock)[1] 
		^ state[0][1] ^ state[1][2] ^ (state[2][1] & state[3][1]);
	((uint64_t*)ciphertextblock)[2] = ((uint64_t*)plaintextblock)[2] 
		^ state[0][2] ^ state[1][3] ^ (state[2][2] & state[3][2]);
	((uint64_t*)ciphertextblock)[3] = ((uint64_t*)plaintextblock)[3] 
		^ state[0][3] ^ state[1][0] ^ (state[2][3] & state[3][3]);
	morus_stateupdate(((uint64_t*)plaintextblock), state);
}// morus_enc_aut_step

// one step of decryption: it decrypts a 32-byte block
static void morus_dec_aut_step(
	uint8_t *plaintextblock,
	const uint8_t *ciphertextblock, 
	uint64_t state[][4])
{
	uint64_t temp, temp1;
	//decryption
	((uint64_t*)plaintextblock)[0] = ((uint64_t*)ciphertextblock)[0] 
		^ state[0][0] ^ state[1][1] ^ (state[2][0] & state[3][0]);
	((uint64_t*)plaintextblock)[1] = ((uint64_t*)ciphertextblock)[1] 
		^ state[0][1] ^ state[1][2] ^ (state[2][1] & state[3][1]);
	((uint64_t*)plaintextblock)[2] = ((uint64_t*)ciphertextblock)[2] 
		^ state[0][2] ^ state[1][3] ^ (state[2][2] & state[3][2]);
	((uint64_t*)plaintextblock)[3] = ((uint64_t*)ciphertextblock)[3] 
		^ state[0][3] ^ state[1][0] ^ (state[2][3] & state[3][3]);
	morus_stateupdate(((uint64_t*)plaintextblock), state);
}// morus_dec_aut_step

// encrypt a partial block
static void morus_enc_aut_partialblock(
	const uint8_t *plaintext,
	uint8_t *ciphertext, 
	uint64_t len, 
	uint64_t state[][4])
{
	uint8_t plaintextblock[32], ciphertextblock[32];

	memset(plaintextblock, 0, 32);
	memcpy(plaintextblock, plaintext, len);

	//encryption
	((uint64_t*)ciphertextblock)[0] = ((uint64_t*)plaintextblock)[0] 
		^ state[0][0] ^ state[1][1] ^ (state[2][0] & state[3][0]);
	((uint64_t*)ciphertextblock)[1] = ((uint64_t*)plaintextblock)[1] 
		^ state[0][1] ^ state[1][2] ^ (state[2][1] & state[3][1]);
	((uint64_t*)ciphertextblock)[2] = ((uint64_t*)plaintextblock)[2] 
		^ state[0][2] ^ state[1][3] ^ (state[2][2] & state[3][2]);
	((uint64_t*)ciphertextblock)[3] = ((uint64_t*)plaintextblock)[3] 
		^ state[0][3] ^ state[1][0] ^ (state[2][3] & state[3][3]);

	memcpy(ciphertext, ciphertextblock, len);
	morus_stateupdate(((uint64_t*)plaintextblock), state);
}//morus_enc_aut_partialblock

// decrypt a partial block
static void morus_dec_aut_partialblock(
	uint8_t *plaintext,
	const uint8_t *ciphertext, 
	unsigned long len, 
	uint64_t state[][4])
{
	uint8_t plaintextblock[32], ciphertextblock[32];

	memset(ciphertextblock, 0, 32);
	memcpy(ciphertextblock, ciphertext, len);

	//decryption
	((uint64_t*)plaintextblock)[0] = ((uint64_t*)ciphertextblock)[0] 
		^ state[0][0] ^ state[1][1] ^ (state[2][0] & state[3][0]);
	((uint64_t*)plaintextblock)[1] = ((uint64_t*)ciphertextblock)[1] 
		^ state[0][1] ^ state[1][2] ^ (state[2][1] & state[3][1]);
	((uint64_t*)plaintextblock)[2] = ((uint64_t*)ciphertextblock)[2] 
		^ state[0][2] ^ state[1][3] ^ (state[2][2] & state[3][2]);
	((uint64_t*)plaintextblock)[3] = ((uint64_t*)ciphertextblock)[3] 
		^ state[0][3] ^ state[1][0] ^ (state[2][3] & state[3][3]);

	memcpy(plaintext, plaintextblock, len);
	memset(plaintextblock, 0, 32);
	memcpy(plaintextblock, plaintext, len);
	morus_stateupdate(((uint64_t*)plaintextblock), state);
}//morus_dec_aut_partialblock


//encrypt a message
static int morus_aead_encrypt(
	unsigned char *c, size_t *clen,
	const unsigned char *m, size_t mlen,
	const unsigned char *ad, size_t adlen,
	const unsigned char *nsec, // ignored
	const unsigned char *npub, // nonce (iv)
	const unsigned char *k,
	const size_t klen // must be 16 or 32
	)
{
	uint64_t i;
	uint8_t ciphertextblock[32];
	uint64_t morus_state[5][4];

	//initialization
	morus_initialization(k, klen, npub, morus_state);

	//process the associated data
	for (i = 0; (i + 32) <= adlen; i += 32) {
		morus_enc_aut_step(ad + i, ciphertextblock, morus_state);
	}

	//deal with the partial block of associated data
	if ((adlen & 0x1f) != 0) {
		morus_enc_aut_partialblock(
			ad + i, ciphertextblock, adlen & 0x1f, morus_state);
	}

	//encrypt the plaintext
	for (i = 0; (i + 32) <= mlen; i += 32) {
		morus_enc_aut_step(m + i, c + i, morus_state);
	}

	// Deal with the partial block
	if ((mlen & 0x1f) != 0) {
		morus_enc_aut_partialblock(
			m + i, c + i, mlen & 0x1f, morus_state);
	}

	morus_tag_generation(mlen, adlen, c, morus_state);
	*clen = mlen + 16;
	return 0;
}//crypto_aead_encrypt


static int morus_aead_decrypt(
	unsigned char *m, size_t *mlen,
	unsigned char *nsec,
	const unsigned char *c, size_t clen,
	const unsigned char *ad, size_t adlen,
	const unsigned char *npub,
	const unsigned char *k,
	const size_t klen // must be 16 or 32
	)
{
	unsigned long i;
	uint8_t ciphertextblock[32];
	uint8_t check = 0;
	uint64_t  morus_state[5][4];

	if (clen < 16) return -1;

	morus_initialization(k, klen, npub, morus_state);

	//process the associated data
	for (i = 0; (i + 32) <= adlen; i += 32)
	{
		morus_enc_aut_step(ad + i, ciphertextblock, morus_state);
	}

	// deal with the partial block of associated data
	if ((adlen & 0x1f) != 0)
	{
		morus_enc_aut_partialblock(
			ad + i, ciphertextblock, adlen & 0x1f, morus_state);
	}

	// decrypt the ciphertext
	*mlen = clen - 16;
	for (i = 0; (i + 32) <= *mlen; i += 32)
	{
		morus_dec_aut_step(m + i, c + i, morus_state);
	}

	// Deal with the partial block
	if ((*mlen & 0x1f) != 0) {
		morus_dec_aut_partialblock(m + i, c + i, *mlen & 0x1f, morus_state);
	}

	// verification
	return morus_tag_verification(*mlen, adlen, c, morus_state);
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


int ll_morus_encrypt(lua_State *L) {
	// Lua API: encrypt(k, n, m [, ninc [, aad ]])  return c
	//  k: key string (16 or 32 bytes)
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
	size_t mln, nln, kln, aadln, cln, bufln;
	const char *k = luaL_checklstring(L,1,&kln);
	const char *n = luaL_checklstring(L,2,&nln);	
	const char *m = luaL_checklstring(L,3,&mln);	
	uint64_t ninc = luaL_optinteger(L, 4, 0);	
	const char *aad = luaL_optlstring(L,5,"",&aadln);
//~ if (m == 0) {  printf("@@@ m=NULL \n"); }
//~ printf("@@@ m=%x \n", m);
	if (nln != 16) LERR("bad nonce size");
	if ((kln != 32) && (kln != 16)) LERR("bad key size");
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
	morus_aead_encrypt(
		buf+aadln, &cln, 
		m, mln, 
		aad, aadln, 
		0, actn, 
		k, kln);
	if (cln != mln+16) LERR("bad result size");
	lua_pushlstring (L, buf, bufln); 
	return 1;
} // ll_morus_encrypt()

int ll_morus_decrypt(lua_State *L) {
	// Lua API: decrypt(k, n, c [, ninc [, aadln]]) 
	//     return m | (nil, msg)
	//  k: key string (16 or 32 bytes)
	//  n: nonce string (16 bytes)
	//  c: encrypted message string 
	//  ninc: optional nonce increment (see above. defaults to 0)
	//  aadln: length of the AD prefix (default to 0)
	//  return plain text or (nil, errmsg) if MAC is not valid
	int r = 0;
	size_t cln, nln, kln, boxln, mln;
	const char *k = luaL_checklstring(L, 1, &kln);
	const char *n = luaL_checklstring(L, 2, &nln);	
	const char *c = luaL_checklstring(L, 3, &cln);	
	uint64_t ninc = luaL_optinteger(L, 4, 0);	
	size_t aadln = luaL_optinteger(L, 5, 0);	
	if (nln != 16) LERR("bad nonce size");
	if ((kln != 32) && (kln != 16)) LERR("bad key size");
	// allocate buffer for decrypted text
	boxln = cln - aadln;
	unsigned char * buf = lua_newuserdata(L, boxln);
	// compute actual nonce "n + ninc"
	char actn[16]; 
	memcpy(actn, n, 16); 
	(*(uint64_t *) actn) = (*(uint64_t *) actn) + ninc;
	//
	r = morus_aead_decrypt(buf, &mln, 0, 
		c+aadln, boxln, c, aadln, actn, k, kln);
	if (r != 0) { 
		lua_pushnil (L);
		lua_pushliteral(L, "decrypt error");
		return 2;         
	} 
	lua_pushlstring (L, buf, mln); 
	return 1;
	
} // ll_morus_decrypt()

int ll_morus_hash(lua_State *L) {
	//
	// !! EXPERIMENTAL - NOT DESIGNED BY THE MORUS AUTHORS !! 
	// !! => DON'T USE IT FOR ANYTHING !! 
	//
	// Lua API: hash(m, [diglen [, k]])  return dig
	//  m: message string to hash
	//  diglen: optional digest length in bytes (defaults to 32)
	//  k: optional key string (32 bytes)
	//  return digest string dig
	//  (#dig == diglen)
	int i, r;
	size_t mln, kln, n;
	uint64_t *pu64;
	const char *m = luaL_checklstring(L,1,&mln);	
	size_t diglen = luaL_optinteger(L, 2, 32);	
	const char *k = luaL_optlstring(L,3,"",&kln);
	//if (kln != 32) LERR("bad key size");
	
	char *p; 
	char *dig = lua_newuserdata(L, diglen);
	uint8_t iv[16] = {0};  
	uint8_t kb[32] = {0};  
	uint8_t blk[32] = {0}; 
	uint64_t st[5][4];
	
	// initialize the state
	if (kln > 32) kln = 32;
	if (kln > 0) memcpy(kb, k, kln);
	pu64 = (uint64_t *)iv;
	*pu64 = diglen;
	morus_initialization(kb, 32, iv, st);
	// absorb m
	while (mln >= 32) {
		morus_stateupdate((uint64_t*)m, st);
		m += 32;
		mln -= 32; 
	}
	// absorb last partial block (if any) and pad
	memcpy(blk, m, mln);
	blk[mln] = 0x01;
	blk[31] ^= 0x80;
	morus_stateupdate((uint64_t*)blk, st);
	// mix state
	memset(blk, 0, 32);
	for (i=0; i<16; i++) { morus_stateupdate((uint64_t*)blk, st); }
	// squeeze digest
	p = dig;
	n = diglen;
	while (n > 32) {
		memcpy(p, (char *)st[0], 32);
		p += 32; 
		n -= 32;
		morus_stateupdate((uint64_t*)blk, st);
	}
	memcpy(p, (char *)st[0], n);
	lua_pushlstring (L, dig, diglen); 
	return 1;
} // ll_morus_hash()

