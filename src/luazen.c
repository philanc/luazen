// Copyright (c) 2018 Phil Leblanc  -- see LICENSE file
// ---------------------------------------------------------------------
// luazen crypto, encoding and compression library

// ---------------------------------------------------------------------
// lua binding

#define LIBNAME luazen
#define VERSION "luazen-0.11"

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
	// luazen function declarations - comment APPEND lines to 
	// remove functions from the luazen build
	//
	// from random.c
	APPEND(randombytes)
	//
	// from base64.c
	APPEND(b64encode)
	APPEND(b64decode)
	//
	// from base58.c
	APPEND(b58encode)
	APPEND(b58decode)
	//
	// from blz.c
	APPEND(blz)
	APPEND(unblz)
	//
	// from lzf.c
	APPEND(lzf)
	APPEND(unlzf)
	//
	// from norx.c
	APPEND(norx_encrypt)
	APPEND(norx_decrypt)
	//
	// from chacha.c
	APPEND(xchacha_encrypt)
	APPEND(xchacha_decrypt)
	//
	// from rc4.c
	APPEND(rc4)
	APPEND(rc4raw)
	//
	// from md5.c
	APPEND(md5)
	//
	// from xor.c
	APPEND(xor)
	//
	// from blake2b.c
	APPEND(blake2b)
	APPEND(argon2i)
	//
	// from sha2.c
	//~ APPEND(sha512)
	//
	// from x25519.c
	APPEND(x25519_public_key)
	APPEND(x25519_shared_secret)
	APPEND(x25519_sign_public_key)
	APPEND(x25519_sign)
	APPEND(x25519_sign_open)
	APPEND(x25519_sha512)	
	//
	// from morus.c
	APPEND(morus_encrypt)
	APPEND(morus_decrypt)
	APPEND(morus_hash)
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
