// Copyright (c) 2017  Phil Leblanc  -- see LICENSE file
// ---------------------------------------------------------------------

/*

170522  
- slua lz renamed to luazen for win slua533-2
- added a windows RNG function in file randombytes_win.c
  (randombytes.c from win slua533-1 tweetnacl)


TODO:  
- remove keypair functions? leave it to lua apps
- drop key_echange => repl with x25519 or "get_shared_secret"
  or key it but expose x25519 to allow public test vectors

---

lz is a Lua library including encoding, encryption and compression 
functions.

It includes the following algorithms
- random source interface
- NORX authenticated encryption - https://norx.io/
- Blake2b cryptographic hash 
- Argon2i key derivation 
- curve25519 key exchange and ed25519 signature
e- LZF compression
- base64, base58, xor
- legacy cryptography (md5, rc4)

*/

#define VERSION "luazen-0.8"

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "lua.h"
#include "lauxlib.h"

// for NORX
#include "norx.h"

// for blake2b, curve25519
#include "mono.h"

//for luazen stuff
#include "lzf.h"
#include "rc4.h"
#include "md5.h"
#include "base58.h"

//----------------------------------------------------------------------
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
# define LERR(msg) return luaL_error(L, msg)

//----------------------------------------------------------------------
// lua binding   (all exposed functions are prefixed with "lz_")


extern int randombytes(unsigned char *x,unsigned long long xlen); 

static int lz_randombytes(lua_State *L) {
	// Lua API:   randombytes(n)  returns a string with n random bytes 
	// or nil, error msg if the RNG fails
	// size limit: If n > 4096, randombytes will return a 4096-byte string
    size_t bufln; 
	lua_Integer li = luaL_checkinteger(L, 1);  // 1st arg
	bufln = (size_t) li;
    unsigned char *buf = malloc(bufln); 
	int r = randombytes(buf, li);
	if (r != 0) { 
		free(buf); 
		lua_pushnil (L);
		lua_pushliteral(L, "randombytes error");
		return 2;         
	} 	
    lua_pushlstring (L, buf, bufln); 
    free(buf);
	return 1;
}//randombytes()

//----------------------------------------------------------------------
// NORX authenticated encryption

static int lz_aead_encrypt(lua_State *L) {
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
} // lz_aead_encrypt()

static int lz_aead_decrypt(lua_State *L) {
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
} // lz_aead_decrypt()


//----------------------------------------------------------------------
// curve25519 functions

static int lz_x25519_keypair(lua_State *L) {
	// generate and return a random key pair (publickey, secretkey)
	// lua api: x25519_keypair()
	// return (sk, pk)
	unsigned char pk[32];
	unsigned char sk[32];
	// sk is a random string. Then, compute the matching public key
	randombytes(sk, 32);
	crypto_x25519_public_key(pk, sk);
	lua_pushlstring (L, pk, 32); 
	lua_pushlstring (L, sk, 32); 
	return 2;
}//lz_x25519_keypair()

static int lz_x25519_public_key(lua_State *L) {
	// return the public key associated to a secret key
	// lua api:  x25519_public_key(sk) return pk
	// sk: a secret key (can be any random value)
	// pk: the matching public key
	size_t skln;
	unsigned char pk[32];
	const char *sk = luaL_checklstring(L,1,&skln); // secret key
	if (skln != 32) LERR("bad sk size");
	crypto_x25519_public_key(pk, sk);
	lua_pushlstring (L, pk, 32); 
	return 1;
}//lz_x25519_public_key()

static int lz_key_exchange(lua_State *L) {
	// DH key exchange: compute a session key
	// lua api:  lock_key(sk, pk) => k
	// (!! reversed order compared to nacl box_beforenm() !!)
	// sk: "your" secret key
	// pk: "their" public key
	// return the session key k
	// --Note: In order to make the session key more uniformly distributed,
	// the shared secret generated by x25519 is hashed by blake2b.
	// (blake2b plays here the same role as HSalsa20 in nacl box_beforenm())
	size_t pkln, skln;
	unsigned char k[32];
	const char *sk = luaL_checklstring(L,1,&skln); // your secret key
	const char *pk = luaL_checklstring(L,2,&pkln); // their public key
	if (pkln != 32) LERR("bad pk size");
	if (skln != 32) LERR("bad sk size");

    unsigned char shared_secret[32];
	/// replace crypto_chacha20_H with crypto_blake2b_general
    int status = crypto_x25519(shared_secret, sk, pk);
    crypto_blake2b_general(k, 32, 0, 0, shared_secret, 32);	
	lua_pushlstring(L, k, 32); 
	return 1;   
}// lz_key_exchange()


//----------------------------------------------------------------------
// blake2b hash functions

static int lz_blake2b(lua_State *L) {
	// compute the hash of a string (convenience function)
	// with default parameters (64-byte digest, no key)
	// lua api:  blake2b(m) return digest
	// m: the string to be hashed
	// digest: the blake2b hash (a 64-byte string)
    size_t mln; 
    const char *m = luaL_checklstring (L, 1, &mln);
    char digest[64];
    crypto_blake2b_general(digest, 64, 0, 0, m, mln);
    lua_pushlstring (L, digest, 64); 
    return 1;
}// lz_blake2b

static int lz_blake2b_init(lua_State *L) {
	// create and initialize a blake2b context
	// lua api:  blake2b_init([digln [, key]]) return ctx
	// digln: the optional length of the digest to be computed 
	// (between 1 and 64) - default value is 64
	// key: an optional secret key, allowing blake2b to work as a MAC 
	//    (if provided, key length must be between 1 and 64)
	//    default is no key
	// return ctx, a pointer to the blake2b context as a light userdata
	// 
	// NOTE: the caller must ensure that blake2b_final() will be called to
	// free the context, and that the ctx varible will NOT be used after
	// the call to blake2b_final() 
	//
    size_t keyln = 0; 
    int digln = luaL_optinteger(L, 1, 64);
    const char *key = luaL_optlstring(L, 2, NULL, &keyln);
	if ((keyln < 0)||(keyln > 64)) LERR("bad key size");
	if ((digln < 1)||(digln > 64)) LERR("bad digest size");
    size_t ctxln = sizeof(crypto_blake2b_ctx);
	crypto_blake2b_ctx *ctx = (crypto_blake2b_ctx *) malloc(ctxln);
    crypto_blake2b_general_init(ctx, digln, key, keyln);
	lua_pushlightuserdata(L, (void *)ctx);
    return 1;
}// lz_blake2b_init

static int lz_blake2b_update(lua_State *L) {
	// update the hash with a new text fragment
	// lua api:  blake2b_update(ctx, t)
	// ctx, a pointer to the blake2b context as a light userdata
	//    (created by blake2b_init())
	// t: a text fragment as a string
	//
	size_t tln; 
	crypto_blake2b_ctx *ctx = (crypto_blake2b_ctx *) lua_touserdata(L, 1);
    const char *t = luaL_checklstring (L, 2, &tln);
	if (ctx == NULL) LERR("invalid ctx");	
    crypto_blake2b_update(ctx, t, tln);
    return 0;
}// lz_blake2b_update


static int lz_blake2b_final(lua_State *L) {
	// return the final value of the hash (and free the context)
	// lua api:  blake2b_final(ctx) return dig
	// ctx, a pointer to the blake2b context as a light userdata
	//    (created by blake2b_init())
	// dig: the digest value as a string (string length depends on 
	// the digln parameter used for blake2b_init() - default is 64
	//
	crypto_blake2b_ctx *ctx = (crypto_blake2b_ctx *) lua_touserdata(L, 1);
	if (ctx == NULL) LERR("invalid ctx");	
	int digln = ctx->output_size;
	unsigned char dig[64];
    crypto_blake2b_final(ctx, dig);
	free(ctx);
    lua_pushlstring (L, dig, digln); 
    return 1;
}// lz_blake2b_final


//----------------------------------------------------------------------
// ed25519 signature functions

static int lz_sign_keypair(lua_State *L) {
	// generates and return a pair of ed25519 signature keys 
	// lua api: sign_keypair()  return (sk, pk)
	unsigned char pk[32];
	unsigned char sk[32];
	// sk is a random string. Then, compute the matching public key
	randombytes(sk, 32);
	crypto_sign_public_key(pk, sk);
	lua_pushlstring (L, pk, 32); 
	lua_pushlstring (L, sk, 32); 
	return 2;
}//lz_sign_keypair()

static int lz_sign_public_key(lua_State *L) {
	// return the public key associated to an ed25519 secret key
	// lua api:  sign_public_key(sk) return pk
	// sk: a secret key (can be any random value)
	// pk: the matching public key
	size_t skln;
	unsigned char pk[32];
	const char *sk = luaL_checklstring(L,1,&skln); // secret key
	if (skln != 32) LERR("bad sk size");
	crypto_sign_public_key(pk, sk);
	lua_pushlstring (L, pk, 32); 
	return 1;
}//lz_sign_public_key()

static int lz_sign(lua_State *L) {
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
	crypto_sign(sig, sk, pk, m, mln);
	lua_pushlstring (L, sig, 64); 
	return 1;
} // lz_sign()

static int lz_check(lua_State *L) {
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
	r = crypto_check(sig, pk, m, mln);
	// r == 0 if the signature matches
	lua_pushboolean (L, (r == 0)); 
	return 1;
} // lz_check()

//------------------------------------------------------------
// argon2i password derivation
//
#ifndef NOARGON

static int lz_argon2i(lua_State *L) {
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
	unsigned char *work= malloc(worksize);
	crypto_argon2i(	k, 32, work, nkb, niters,
					pw, pwln, salt, saltln, 
					"", 0, "", 0 	// optional key and additional data
					);

	lua_pushlstring (L, k, 32); 
	free(work);
	return 1;
} // lz_argon2i()
#endif

//----------------------------------------------------------------------
// luazen functions

// lzf compression functions

static int lz_lzf(lua_State *L) {
    size_t sln, bufln; 
    unsigned int dstln;
    const char *s = luaL_checklstring (L, 1, &sln);
	// special case for empty string:  lzf_compress cannot handle it.
	// => return an empty string
	if (sln == 0) {
		lua_pushlstring (L, s, sln); 
		return 1;  		
	}
	// headln set to 4 for compatibility with previous 32-bit versions
    const size_t headln = sizeof(uint32_t);  
    bufln =  sln + (sln/5) + 20 ;
    char *buf = malloc(bufln); 
    //store compressed data at dstbuf
    //1st headln bytes in buf used to store uncompressed length
    char *dstbuf = buf + headln; 
	// store the original size of the string in the first headln bytes
	// FIXME
	// !!this is ENDIANNESS DEPENDANT!! (written for little endian platforms)
	// also should ensure that sln < 0xffffffff (ie. can fit a uint32_t)
    *((uint32_t *) buf) = (uint32_t) sln;  
	dstln = bufln - headln ; //dstln must be set to buf ln upon entry
    unsigned int r = lzf_compress(s, sln, dstbuf, dstln); 
    if (r == 0) {
		free(buf); 
        lua_pushnil (L);
		lua_pushfstring (L, "luazen: lzf compress error (E2BIG) %d", r);
        return 2;         
    }
    lua_pushlstring (L, buf, headln + r); 
    free(buf);
    return 1;    
}

static int lz_unlzf(lua_State *L) {
    size_t sln, bufln; 
    unsigned int dstln;
    const char *s = luaL_checklstring (L, 1, &sln);
	// special case for empty string:  return an empty string
	if (sln == 0) {
		lua_pushlstring (L, s, sln); 
		return 1;  		
	}	
    const size_t headln = sizeof(uint32_t);
    // 1st headln bytes i s are uncompressed data length
    bufln = (*((uint32_t *) s));  // !!ENDIANNESS DEPENDANT!!
	bufln += 20 ;  // ...just in case some room needed for null at end...
    char *buf = malloc(bufln); 
    const char *src = s + headln; 
	dstln = bufln - headln ; //dstln must be set to buf ln upon entry
    unsigned int r = lzf_decompress(src, sln - headln, buf, dstln); 
    if (r == 0) {
		free(buf);
        lua_pushnil (L);
		lua_pushfstring (L, "luazen: lzf decompress error (E2BIG or EINVAL) %d", r);
        return 2;         
    }
    lua_pushlstring (L, buf, r); 
    free(buf);
    return 1;    
}
//----------------------------------------------------------------------
// 
//--- xor(input:string, key:string) =>  output:string
//-- obfuscate a string using xor and a key string
//-- output is same length as input
//-- if key is shorter than input, it is repeated as much as necessary
//
static int lz_xor(lua_State *L) {
    size_t sln, kln; 
    const char *s = luaL_checklstring (L, 1, &sln);
    const char *k = luaL_checklstring (L, 2, &kln);
    //printf("[%s]%d  [%s]%d \n", s, sln, k, kln);
    char *p = (char *) malloc(sln); 
    size_t is = 0; 
    size_t ik = 0; 
    while (is < sln) {
        p[is] = s[is] ^ k[ik]; 
        is++; ik++; 
        if (ik == kln)  ik = 0;
    }
    lua_pushlstring (L, p, sln); 
    free(p);
    return 1;
}

#ifndef NOLEGACY

//--- rc4raw() - a rc4 encrypt/decrypt function
//-- see http://en.wikipedia.org/wiki/RC4 for raw rc4 weaknesses
//-- use rc4() instead for regular uses (a rc4-drop implementation)
//
static int lz_rc4raw(lua_State *L) {
	size_t sln, kln; 
	const char *src = luaL_checklstring (L, 1, &sln);
	const char *key = luaL_checklstring (L, 2, &kln);
	if (kln != 16) {
		lua_pushnil (L);
		lua_pushliteral (L, "luazen: rc4 key must be 16 bytes");
		return 2;         
	}
	//printf("[%s]%d  [%s]%d \n", s, sln, k, kln);
	char *dst = (char *) malloc(sln); 
	rc4_ctx ctx;
	rc4_setup(&ctx, key, kln); 
	rc4_crypt(&ctx, src, dst, sln);
	lua_pushlstring (L, dst, sln); 
	free(dst);
	return 1;
}


//--- rc4() - a rc4-drop encrypt/decrypt function
//-- see http://www.users.zetnet.co.uk/hopwood/crypto/scan/cs.html#RC4-drop
//
static int lz_rc4(lua_State *L) {
    size_t sln, kln; 
    const char *src = luaL_checklstring (L, 1, &sln);
    const char *key = luaL_checklstring (L, 2, &kln);
	if (kln != 16) {
		lua_pushnil (L);
		lua_pushliteral (L, "luazen: rc4 key must be 16 bytes");
		return 2;         
	}
	const int dropln = 256;
    char drop[dropln]; 
	// ensure drop is zeroed
	int i;  for (i=0;  i<dropln; i++) drop[i] = 0;
    char *dst = (char *) malloc(sln); 
    rc4_ctx ctx;
    rc4_setup(&ctx, key, kln); 
    // drop initial bytes of keystream
    // copy following line n times to get a rc4-drop <n*256>
    rc4_crypt(&ctx, drop, drop, 256);
    // crypt actual input
    rc4_crypt(&ctx, src, dst, sln);
    lua_pushlstring (L, dst, sln); 
    free(dst);
    return 1;
}



//----------------------------------------------------------------------
// md5
// 

static int lz_md5(lua_State *L) {
    size_t sln; 
    const char *src = luaL_checklstring (L, 1, &sln);
    char digest[MD5_SIZE];
    MD5_CTX ctx; 
    MD5_Init(&ctx);
    MD5_Update(&ctx, src, sln);
    MD5_Final(digest, &ctx);
    lua_pushlstring (L, digest, MD5_SIZE); 
    return 1;
}
#endif   //NOLEGACY
//------------------------------------------------------------
// base64 encode, decode 
//	public domain, by Luiz Henrique de Figueiredo, 2010

//  encode(): added an optional 'linelength' parameter 
//  decode(): modified to allow decoding of non well-formed 
//  encoded strings (ie. strings with no '=' padding)

#define uint unsigned int
#define B64LINELENGTH 72

static const char code[]=
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void b64encode(luaL_Buffer *b, uint c1, uint c2, uint c3, int n) {
	unsigned long tuple=c3+256UL*(c2+256UL*c1);
	int i;
	char s[4];
	for (i=0; i<4; i++) {
	s[3-i] = code[tuple % 64];
	tuple /= 64;
	}
	for (i=n+1; i<4; i++) s[i]='=';
	luaL_addlstring(b,s,4);
}

static int lz_b64encode(lua_State *L) {
	// Lua:  
	//   b64encode(str)  or  b64encode(str, linelen)
	//     str is the tring to enccode
	//     linelen is an optional output line length
	//       must be multiple of 4
	//       default is 72, (must be <= 76 for Mime)
	//       if 0, no '\n' is inserted
	size_t l;
	const unsigned char *s=(const unsigned char*)luaL_checklstring(L,1,&l);
	int linelength = (
		lua_isnoneornil(L, 2) ? B64LINELENGTH : luaL_checkinteger(L, 2)); 
	luaL_Buffer b;
	int n;
	int cn = 0; 
	luaL_buffinit(L,&b);
	for (n=l/3; n--; s+=3) {
		b64encode(&b,s[0],s[1],s[2],3);
		cn += 4; 
		if ( linelength && cn >= linelength) {
			cn = 0;
			luaL_addlstring(&b,"\n",1);
		}
	}
	switch (l%3)
	{
	case 1: b64encode(&b,s[0],0,0,1);		break;
	case 2: b64encode(&b,s[0],s[1],0,2);		break;
	}
	luaL_pushresult(&b);
	return 1;
}

static void b64decode(luaL_Buffer *b, int c1, int c2, int c3, int c4, int n)
{
	unsigned long tuple=c4+64L*(c3+64L*(c2+64L*c1));
	char s[3];
	switch (--n)
	{
	case 3: s[2]=tuple;
	case 2: s[1]=tuple >> 8;
	case 1: s[0]=tuple >> 16;
	}
	luaL_addlstring(b,s,n);
}

static int lz_b64decode(lua_State *L)		/** decode(s) */
{
	size_t l;
	const char *s=luaL_checklstring(L,1,&l);
	luaL_Buffer b;
	int n=0;
	char t[4];
	luaL_buffinit(L,&b);
	for (;;) 	{
		int c=*s++;
		switch (c)	{
		const char *p;
		default:
			p=strchr(code,c); if (p==NULL) return 0;
			t[n++]= p-code;
			if (n==4) 	{
				b64decode(&b,t[0],t[1],t[2],t[3],4);
				n=0;
			}
			break;
		case '=':
		//ph: added 'case 0:' here to allow decoding of non well-formed 
		//    encoded strings (ie. strings with no padding)
		case 0:  
			switch (n) 	{
				case 1: b64decode(&b,t[0],0,0,0,1);		break;
				case 2: b64decode(&b,t[0],t[1],0,0,2);	break;
				case 3: b64decode(&b,t[0],t[1],t[2],0,3);	break;
			}
			luaL_pushresult(&b);
			return 1;
		case '\n': case '\r': case '\t': case ' ': case '\f': case '\b':
			break;
		} //switch(c)
	} //for(;;)
	return 0;
}
//------------------------------------------------------------
// base58 encode, decode 
// based on code from Luke Dashjr (MIT license - see source code)

// this encoding uses the same alphabet as bitcoin addresses:
//   "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

static int lz_b58encode(lua_State *L) {
	size_t bln, eln;
	const char *b = luaL_checklstring(L,1,&bln);	
	if (bln == 0) { // empty string special case (not ok with b58enc)
		lua_pushliteral (L, ""); 
		return 1;
	}
	unsigned char * buf = malloc(bln * 2); // more than enough!
	eln = bln * 2; // eln must be set to buffer size before calling b58enc
	bool r = b58enc(buf, &eln, b, bln);
	if (!r) { 
		free(buf); 
		lua_pushnil (L);
		lua_pushfstring(L, "b58encode error");
		return 2;         
	} 
	eln = eln - 1;  // b58enc add \0 at the end of the encode string
	lua_pushlstring (L, buf, eln); 
	free(buf);
	return 1;
}

static int lz_b58decode(lua_State *L) {
	size_t bufsz, bln, eln;
	const char *e = luaL_checklstring(L,1,&eln); // encoded data
	if (eln == 0) { // empty string special case 
		lua_pushliteral (L, ""); 
		return 1;
	}
	bufsz = eln; // more than enough!
	unsigned char *buf = malloc(bufsz); 
	bln = bufsz; // give the result buffer size to b58tobin
	bool r = b58tobin(buf, &bln, e, eln);
	if (!r) { 
		free(buf); 
		lua_pushnil (L);
		lua_pushfstring(L, "b58decode error");
		return 2;         
	} 
	// b58tobin returns its result at the _end_ of buf!!!
	lua_pushlstring (L, buf+bufsz-bln, bln); 
	free(buf);
	return 1;
}


//------------------------------------------------------------
// lua library declaration
//
static const struct luaL_Reg lzlib[] = {
	{"randombytes", lz_randombytes},
	//
	{"aead_encrypt", lz_aead_encrypt},
	{"aead_decrypt", lz_aead_decrypt},
	{"encrypt", lz_aead_encrypt},  // alias
	{"decrypt", lz_aead_decrypt},  // alias
	//
	{"x25519_keypair", lz_x25519_keypair},
	{"x25519_public_key", lz_x25519_public_key},
	{"keypair", lz_x25519_keypair},        // alias
	{"public_key", lz_x25519_public_key},  // alias
	{"key_exchange", lz_key_exchange},
	{"dh_key", lz_key_exchange},           // alias
	//
	{"blake2b", lz_blake2b},
	{"blake2b_init", lz_blake2b_init},
	{"blake2b_update", lz_blake2b_update},
	{"blake2b_final", lz_blake2b_final},
	//
	{"sign_keypair", lz_sign_keypair},
	{"sign_public_key", lz_sign_public_key},	
	{"sign", lz_sign},	
	{"check", lz_check},	
	//
#ifndef NOARGON
	{"argon2i", lz_argon2i},	
#endif
	//
	{"xor", lz_xor},
	{"lzf", lz_lzf},
	{"unlzf", lz_unlzf},
#ifndef NOLEGACY
	{"rc4", lz_rc4},
	{"rc4raw", lz_rc4raw},
	{"md5", lz_md5},
#endif
	{"b64encode",	lz_b64encode},
	{"b64decode",	lz_b64decode},
	{"b58encode",	lz_b58encode},
	{"b58decode",	lz_b58decode},
	//
	{NULL, NULL},
};

int luaopen_luazen(lua_State *L) {
	luaL_register (L, "luazen", lzlib);
    // 
    lua_pushliteral (L, "VERSION");
	lua_pushliteral (L, VERSION); 
	lua_settable (L, -3);
	return 1;
}

