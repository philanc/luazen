// Copyright (c) 2022 Phil Leblanc  -- see LICENSE file
// ---------------------------------------------------------------------
/*
luazen crypto, encoding and compression library

*/



// ---------------------------------------------------------------------
// lua binding

#define LIBNAME luazen
#define VERSION "luazen-2.1"

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
	//from lzma
	APPEND(lzma)
	APPEND(unlzma)
	//
	// from random, base64, md5
	APPEND(randombytes)
	APPEND(b64encode)
	APPEND(b64decode)
	APPEND(md5)
	//
	// from mono
	APPEND(encrypt)
	APPEND(decrypt)
	APPEND(blake2b)
	APPEND(argon2i)
	APPEND(x25519_public_key)
	APPEND(key_exchange)
	APPEND(x25519)
	APPEND(ed25519_public_key)
	APPEND(ed25519_sign)
	APPEND(ed25519_check)
	APPEND(sha512)	
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
