// Copyright (c) 2019 Phil Leblanc  -- see LICENSE file
// ---------------------------------------------------------------------
/*
luazen crypto, encoding and compression library

To facilitate custom builds, functions are included only if a related 
constant is defined (see function llib_init() below). 

The following constants can be defined by uncommenting lines below 
or with -Dname arguments in the compile command (see the Makefile)

*/

// #define BASE64     Base64 encode/decode
// #define BASE58     Base58 encode/decode
// #define BLZ        BriefLZ compress/uncompress
// #define LZF        LZF compress/uncompress
// #define LZMA       LZMA compress/uncompress
// #define NORX       Norx AEAD encrypt/decrypt
// #define CHACHA     Xchacha20 AEAD encrypt/decrypt
// #define RC4        RC4 encrypt/decrypt
// #define MD5        MD5 hash
// #define BLAKE      Blake2b hash, Argon2i key derivation
// #define SHA2       SHA2-512 hash
// #define X25519     Ec25519 key exchange and ed25519 signature functions
// #define MORUS      Morus AEAD encrypt/decrypt
// #define ASCON      Ascon128a AEAD encrypt/decrypt


// ---------------------------------------------------------------------
// lua binding

#define LIBNAME luazen
//~ #define VERSION "luazen-0.13"
#define VERSION "luazen-0.13b"

#include <assert.h>

#include "lua.h"
#include "lauxlib.h"

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
// library table

// max number of registered functions + 1
#define LT_SIZE 100

static struct luaL_Reg llib[LT_SIZE];
static int llib_top = 0;
static luaL_Reg regnull = {NULL, NULL};

static int llib_append(const char *fname, lua_CFunction func) {
	// append a function registration to the function table
	luaL_Reg reg;
	reg.name = fname;
	reg.func = func;
	llib[llib_top] = reg;
	llib_top++;
	assert(llib_top < LT_SIZE);
	llib[llib_top] = regnull;
}// llib_append

// APPEND macro: declare and register a Lua function in one place. eg:
//    APPEND(lzf)  
// is expanded to:
//    int ll_lzf(lua_State *L);
//    llib_append("lzf", ll_lzf);
//
// it assumes that
//    - all library Lua C functions are named as 'll_xyz'
//    - the Lua name for the ll_xyz C function is 'xyz'

#define APPEND(NAME) \
	int ll_##NAME(lua_State *L); \
	llib_append(#NAME, ll_ ## NAME);

static void llib_init() {
	// must reinitialize llib_top each time llib_init is called
	llib_top = 0;
	
	// luazen function declarations - comment APPEND lines to 
	// remove functions from the luazen build
	//
	// randombytes and xor are included by default
	APPEND(xor)	
	APPEND(randombytes)
	//
#ifdef BASE64
	// from base64.c
	APPEND(b64encode)
	APPEND(b64decode)
#endif
	//
#ifdef BASE58
	// from base58.c
	APPEND(b58encode)
	APPEND(b58decode)
#endif
	//
#ifdef BLZ
	// from blz.c
	APPEND(blz)
	APPEND(unblz)
#endif
	//
#ifdef LZF
	// from lzf.c
	APPEND(lzf)
	APPEND(unlzf)
#endif
	//
#ifdef LZMA
	// from lzma.c
	APPEND(lzma)
	APPEND(unlzma)
#endif
	//
#ifdef NORX
	// from norx.c
	APPEND(norx_encrypt)
	APPEND(norx_decrypt)
#endif
	//
#ifdef CHACHA
	// from chacha.c
	APPEND(xchacha_encrypt)
	APPEND(xchacha_decrypt)
#endif
	//
#ifdef RC4
	// from rc4.c
	APPEND(rc4)
	APPEND(rc4raw)
#endif
	//
#ifdef MD5
	// from md5.c
	APPEND(md5)
#endif
	//
#ifdef BLAKE
	// from blake2b.c
	APPEND(blake2b)
	APPEND(argon2i)
#endif
	//
#ifdef SHA2
	// from sha2.c
	APPEND(sha512)
#endif
	//
#ifdef X25519 
	// from x25519.c
	APPEND(x25519_public_key)
	APPEND(x25519_shared_secret)
	APPEND(x25519_sign_public_key)
	APPEND(x25519_sign)
	APPEND(x25519_sign_open)
	APPEND(x25519_sha512)	
#endif
	//
#ifdef MORUS
	// from morus.c
	APPEND(morus_encrypt)
	APPEND(morus_decrypt)
	APPEND(morus_xof)
#endif
	//
#ifdef ASCON
	// from ascon.c
	APPEND(ascon_encrypt)
	APPEND(ascon_decrypt)
#endif
	//

	//
} //llib_init()

//----------------------------------------------------------------------
// library registration

int luaopen_luazen (lua_State *L) {
	llib_init(); // fill the library table
	luaL_register (L, "luazen", llib);
    // 
    lua_pushliteral (L, "VERSION");
	lua_pushliteral (L, VERSION); 
	lua_settable (L, -3);
	return 1;
}
