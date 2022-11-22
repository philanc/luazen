// Copyright (c) 2021 Phil Leblanc -- License: MIT
//----------------------------------------------------------------------
/*

luablake3 - a Lua wrapper for the BLAKE3 cryptographic hash function

*/
//----------------------------------------------------------------------
// lua binding name, version

#define LIBNAME luablake3
#define VERSION "luablake3-0.1"


//----------------------------------------------------------------------
#include <assert.h>
#include <stdlib.h>
#include <string.h>	// memcpy()

#include "lua.h"
#include "lauxlib.h"

#include "blake3.h"



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

int ll_blake3(lua_State *L) {
	// lua api: blake3(s [, key [,hashlen]]) => hash
	// if key is non-nil, the function returns a keyed hash of
	// the string (MAC). key must be a 32-byte string.
	// if hashlen is non-null, the function returns a hashlen-long
	// hash. The default hash length is 32 bytes. Any length can 
	// be requested. 
	// 
	size_t size = sizeof(blake3_hasher);
	size_t sln;
	const char *s = luaL_checklstring(L,1,&sln);

	size_t keyln = 0; 
	const char *key = luaL_optlstring(L, 2, "", &keyln);
	if (!(keyln == 0 || keyln == 32)) LERR("bad key size");
	int digln = luaL_optinteger(L, 3, 32);
	blake3_hasher *p_hasher = lua_newuserdata(L, size);
	char *dig = lua_newuserdata(L, digln);
	if (keyln == 0) {
		blake3_hasher_init(p_hasher);	
	} else {
		blake3_hasher_init_keyed(p_hasher, key);
	}
	blake3_hasher_update(p_hasher, s, sln);
	blake3_hasher_finalize(p_hasher, dig, digln);
	lua_pushlstring (L, dig, digln); 
	return 1;	
} 
