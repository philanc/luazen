// Copyright (c) 2021 Phil Leblanc -- License: MIT
//----------------------------------------------------------------------
/*
luamonocypher - a Lua wrapping for the Monocypher library

*/
//----------------------------------------------------------------------
// lua binding name, version

#define LIBNAME luamonocypher
#define VERSION "luamonocypher-0.3"


//----------------------------------------------------------------------
#include <assert.h>
#include <stdlib.h>
#include <string.h>	// memcpy()

#include "lua.h"
#include "lauxlib.h"

#include "monocypher.h"
#include "monocypher-ed25519.h"


// compatibility with Lua 5.2  --and lua 5.3, added 150621
// (from roberto's lpeg 0.10.1 dated 101203)
//
#if (LUA_VERSION_NUM >= 502)

#undef lua_equal
#define lua_equal(L,idx1,idx2)  lua_compare(L,(idx1),(idx2),LUA_OPEQ)

#undef lua_getfenv
#define lua_getfenv	lua_getuservalue
#undef lua_setfenv
#define lua_setfenv	lua_setuservalue

#undef lua_objlen
#define lua_objlen	lua_rawlen

#undef luaL_register
#define luaL_register(L,n,f) \
	{ if ((n) == NULL) luaL_setfuncs(L,f,0); else luaL_newlib(L,f); }

#endif


//----------------------------------------------------------------------
// lua binding   (all lua library functions are prefixed with "ll_")


# define LERR(msg) return luaL_error(L, msg)

//----------------------------------------------------------------------
// xchacha / poly1305 authenticated encryption


int ll_encrypt(lua_State *L) {
	// Authenticated encryption (XChacha20 + Poly1305)
	// Lua API: encrypt(k, n, m [, ninc]) return c
	// k: key string (32 bytes)
	// n: nonce string (24 bytes)
	// m: message (plain text) string 
	// ninc: optional nonce increment (useful when encrypting a long
	//   message as a sequence of block). The same parameter n can 
	//   be used for the sequence. ninc is added to n for each block, 
	//   so the actual nonce used for each block encryption is distinct.
	//   ninc defaults to 0 (the nonce n is used as-is).
	// return encrypted message as a binary string c
	//   c includes the 16-byte MAC (or "tag"), so #c = #m + 16
	//   (the MAC is stored at the end of c)

	
	int r;
	size_t mln, nln, kln, bufln;
	const char *k = luaL_checklstring(L,1,&kln);
	const char *n = luaL_checklstring(L,2,&nln);	
	const char *m = luaL_checklstring(L,3,&mln);	
	uint64_t ninc = luaL_optinteger(L, 4, 0);	
	if (nln != 24) LERR("bad nonce size");
	if (kln != 32) LERR("bad key size");
	// allocate a buffer for the encrypted text
	bufln = mln + 16; //make room for the MAC
	unsigned char * buf = lua_newuserdata(L, bufln);
	// compute the actual nonce
	char actn[24]; // "actual nonce = n + ninc"
	memcpy(actn, n, 24); 
	// addition modulo 2^64 over the first 8 bytes of n
	// (overflow not an issue: uint addition overflow _is_ defined)
	(*(uint64_t *) actn) = (*(uint64_t *) actn) + ninc;
	// encrypted text will be stored at buf, 
	// MAC at end of encrypted text
	crypto_lock(buf+mln, buf, k, actn, m, mln);
	lua_pushlstring (L, buf, bufln); 
	return 1;
} // encrypt()

int ll_decrypt(lua_State *L) {
	// Authenticated decryption (XChacha20 + Poly1305)
	// Lua API: decrypt(k, n, c [, ninc]) return m
	//  k: key string (32 bytes)
	//  n: nonce string (24 bytes)
	//  c: encrypted message string. 
	//     (MAC has been stored by encrypt() at the end of c)
	//  ninc: optional nonce increment (see above. defaults to 0)
	//  return plain text string or nil, errmsg if MAC is not valid
	int r = 0;
	size_t cln, nln, kln;
	const char *k = luaL_checklstring(L, 1, &kln);
	const char *n = luaL_checklstring(L, 2, &nln);	
	const char *c = luaL_checklstring(L, 3, &cln);	
	uint64_t ninc = luaL_optinteger(L, 4, 0);	
	if (nln != 24) LERR("bad nonce size");
	if (kln != 32) LERR("bad key size");
	if (cln < 16) LERR("bad msg size");
	
	// allocate a buffer for the decrypted text
	unsigned char * buf = lua_newuserdata(L, cln);
	// compute the actual nonce
	char actn[24]; // "actual nonce = n + ninc"
	memcpy(actn, n, 24); 
	// addition modulo 2^64 over the first 8 bytes of n
	// (overflow not an issue: uint addition overflow _is_ defined)
	(*(uint64_t *) actn) = (*(uint64_t *) actn) + ninc;
	// encrypted text is at c, its length is cln-16
	// MAC is at c + cln - 16
	r = crypto_unlock(buf, k, actn, c+cln-16, c, cln-16);
	if (r != 0) { 
		lua_pushnil (L);
		lua_pushliteral(L, "decrypt error");
		return 2;         
	} 
	lua_pushlstring (L, buf, cln-16); 
	return 1;
} // ll_decrypt()

//----------------------------------------------------------------------
// blake2b hash and argon2i KDF

int ll_blake2b(lua_State *L) {
	// compute the blake2b hash of a string
	// lua api:  blake2b(m, diglen, key) return digest
	// m: the string to be hashed
	// diglen: the optional length of the digest to be computed 
	//    (between 1 and 64) - default value is 64
	// key: an optional secret key, allowing blake2b to work as a MAC 
	//    (if provided, key length must be between 1 and 64)
	//    default is no key	
	// digest: the blake2b hash (a <diglen>-byte string)
	size_t mln; 
	size_t keyln = 0; 
	char digest[64];
	const char *m = luaL_checklstring (L, 1, &mln);
	int digln = luaL_optinteger(L, 2, 64);
	const char *key = luaL_optlstring(L, 3, NULL, &keyln);
	if ((keyln < 0)||(keyln > 64)) LERR("bad key size");
	if ((digln < 1)||(digln > 64)) LERR("bad digest size");
	crypto_blake2b_general(digest, digln, key, keyln, m, mln);
	lua_pushlstring (L, digest, digln); 
	return 1;
}// ll_blake2b

int ll_argon2i(lua_State *L) {
	// Lua API: argon2i(pw, salt, nkb, niters) => k
	// pw: the password string
	// salt: some entropy as a string (typically 16 bytes)
	// nkb:  number of kilobytes used in RAM (as large as possible)
	// niters: number of iterations (as large as possible, >= 10)
	//  return k, a key string (32 bytes)
	size_t pwln, saltln, kln, mln;
	const char *pw = luaL_checklstring(L,1,&pwln);
	const char *salt = luaL_checklstring(L,2,&saltln);	
	int nkb = luaL_checkinteger(L,3);	
	int niters = luaL_checkinteger(L,4);	
	unsigned char k[32];
	size_t worksize = nkb * 1024;
	unsigned char *work= lua_newuserdata(L, worksize); 
	crypto_argon2i_general(	
		k, 32, work, nkb, niters,
		pw, pwln, salt, saltln, 
		"", 0, "", 0 	// optional key and additional data
	);
	lua_pushlstring (L, k, 32); 
	return 1;
} // ll_argon2i()

//----------------------------------------------------------------------
// key exchange (ec25519)

int ll_x25519_public_key(lua_State *L) {
	// return the public key associated to a secret key
	// lua api:  x25519_public_key(sk) return pk
	// sk: a secret key (can be any 32-byte random value)
	// pk: the matching public key
	size_t skln;
	unsigned char pk[32];
	const char *sk = luaL_checklstring(L,1,&skln); // secret key
	if (skln != 32) LERR("bad sk size");
	crypto_x25519_public_key(pk, sk);
	lua_pushlstring (L, pk, 32); 
	return 1;
}//ll_x25519_public_key()

int ll_x25519(lua_State *L) {
	// raw scalar multiplication over curve25519
	// Note: this function should usually not be used directly.
	// For DH key exchange, the key_exchange() function below 
	// should be used instead.
	// --
	// lua api:  x25519(s, P1) => P2
	// s: a scalar as a 32-byte string
	// P1: a point as a 32-byte string
	// return the product s.P1 as a 32-byte string
	// the bit distribution in P2 is not uniform, so P2 should
	// not be directly used as a shared key. 
	// Again, use key_exchange() instead.
	size_t pkln, skln;
	unsigned char k[32];
	const char *sk = luaL_checklstring(L,1,&skln); // your secret key
	const char *pk = luaL_checklstring(L,2,&pkln); // their public key
	if (pkln != 32) LERR("bad pk size");
	if (skln != 32) LERR("bad sk size");
	crypto_x25519(k, sk, pk);
	lua_pushlstring(L, k, 32); 
	return 1;   
}// ll_x25519()

int ll_key_exchange(lua_State *L) {
	// DH key exchange: compute a session key
	// lua api:  key_exchange(sk, pk) => k
	// !! beware, reversed order compared to nacl box_beforenm() !!
	// sk: "your" secret key
	// pk: "their" public key
	// return the session key k
	size_t pkln, skln;
	unsigned char k[32];
	const char *sk = luaL_checklstring(L,1,&skln); // your secret key
	const char *pk = luaL_checklstring(L,2,&pkln); // their public key
	if (pkln != 32) LERR("bad pk size");
	if (skln != 32) LERR("bad sk size");
	crypto_key_exchange(k, sk, pk);
	lua_pushlstring(L, k, 32); 
	return 1;   
}// ll_key_exchange()
 
//----------------------------------------------------------------------
// signature


//---------------------------------------------------------------------- 
//--- sha512 and ed25519 signature (compatible with original NaCl)


int ll_sha512(lua_State *L) {
	// compute the SHA2-512 hash of a string
	// lua api:  sha512(m) return digest as a binary string
	// m: the string to be hashed
	size_t mln; 
	char digest[64];
	const char *m = luaL_checklstring (L, 1, &mln);
	crypto_sha512(digest, m, mln);
	lua_pushlstring (L, digest, 64); 
	return 1;
}// ll_sha512



int ll_ed25519_public_key(lua_State *L) {
	// return the public key associated to an ed25519 secret key
	// lua api:  sign_public_key(sk) return pk
	// sk: a secret key (can be any 32-byte random string)
	// pk: the matching public key
	size_t skln;
	unsigned char pk[32];
	const char *sk = luaL_checklstring(L,1,&skln); // secret key
	if (skln != 32) LERR("bad sk size");
	crypto_ed25519_public_key(pk, sk);
	lua_pushlstring (L, pk, 32); 
	return 1;
}//ll_sign_public_key()

int ll_ed25519_sign(lua_State *L) {
	// sign a text with a secret key
	// Lua API: sign(sk, pk, m) return sig
	//  sk: key string (32 bytes)
	//  pk: associated public key string (32 bytes)
	//	m: message to sign (string)
	//  return signature (a 64-byte string)
	size_t mln, skln, pkln;
	const char *sk = luaL_checklstring(L,1,&skln);
	const char *pk = luaL_checklstring(L,2,&pkln);
	const char *m = luaL_checklstring(L,3,&mln);	
	if (skln != 32) LERR("bad key size");
	if (pkln != 32) LERR("bad pub key size");
	unsigned char sig[64];
	crypto_ed25519_sign(sig, sk, pk, m, mln);
	lua_pushlstring (L, sig, 64); 
	return 1;
} // ll_ed25519_sign()

int ll_ed25519_check(lua_State *L) {
	// check a text signature with a public key
	// Lua API: check(sig, pk, m) return boolean
	//  sig: signature string (64 bytes)
	//  pk: public key string (32 bytes)
	//	m: message to verify (string)
	//  return true if the signature match, or false
	int r;
	size_t mln, pkln, sigln;
	const char *sig = luaL_checklstring(L,1,&sigln);
	const char *pk = luaL_checklstring(L,2,&pkln);
	const char *m = luaL_checklstring(L,3,&mln);	
	if (sigln != 64) LERR("bad signature size");
	if (pkln != 32) LERR("bad key size");
	r = crypto_ed25519_check(sig, pk, m, mln);
	// r == 0 if the signature matches
	lua_pushboolean (L, (r == 0)); 
	return 1;
} // ll_ed25519_check()

