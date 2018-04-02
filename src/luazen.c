// Copyright (c) 2018 Phil Leblanc  -- see LICENSE file
// ---------------------------------------------------------------------
// luazen crypto, encoding and compression library




// ---------------------------------------------------------------------
// lua binding

#define VERSION "luazen-0.10"

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
// luazen function declarations

int ll_randombytes(lua_State *L);

int ll_b64encode(lua_State *L);
int ll_b64decode(lua_State *L);

int ll_b58encode(lua_State *L);
int ll_b58decode(lua_State *L);

int ll_blz(lua_State *L);
int ll_unblz(lua_State *L);

int ll_lzf(lua_State *L);
int ll_unlzf(lua_State *L);

int ll_norx_encrypt(lua_State *L);
int ll_norx_decrypt(lua_State *L);

int ll_xchacha_encrypt(lua_State *L);
int ll_xchacha_decrypt(lua_State *L);

int ll_rc4(lua_State *L);
int ll_rc4raw(lua_State *L);

int ll_md5(lua_State *L);

int ll_xor(lua_State *L);

int ll_blake2b(lua_State *L);
int ll_blake2b_init(lua_State *L);
int ll_blake2b_update(lua_State *L);
int ll_blake2b_final(lua_State *L);
int ll_argon2i(lua_State *L);

int ll_sha512(lua_State *L);

int ll_ec25519_public_key(lua_State *L);
int ll_ec25519_shared_secret(lua_State *L);
int ll_ed25519_public_key(lua_State *L);
int ll_ed25519_sign(lua_State *L);
int ll_ed25519_check(lua_State *L);

//----------------------------------------------------------------------
// lua library declaration
//
static const struct luaL_Reg llib[] = {
	//
	{"randombytes", ll_randombytes},
	{"xor", 		ll_xor},
	{"b64encode",	ll_b64encode},
	{"b64decode",	ll_b64decode},
	{"b58encode",	ll_b58encode},
	{"b58decode",	ll_b58decode},
	// 
	{"blz", ll_blz},
	{"unblz", ll_unblz},
	//
	{"lzf", ll_lzf},
	{"unlzf", ll_unlzf},
	//
	{"norx_encrypt", ll_norx_encrypt},
	{"norx_decrypt", ll_norx_decrypt},
	//
	{"xchacha_encrypt", ll_xchacha_encrypt},
	{"xchacha_decrypt", ll_xchacha_decrypt},
	//
	{"blake2b", ll_blake2b},
	{"blake2b_init", ll_blake2b_init},
	{"blake2b_update", ll_blake2b_update},
	{"blake2b_final", ll_blake2b_final},
	//
	{"argon2i", ll_argon2i},	
	
	//
	{"sha512", ll_sha512},
	//~ {"sha256", ll_sha256},
	//
	{"ec25519_public_key", ll_ec25519_public_key},
	{"ec25519_shared_secret", ll_ec25519_shared_secret},
	{"ed25519_public_key", ll_ed25519_public_key},	
	{"ed25519_sign", ll_ed25519_sign},	
	{"ed25519_check", ll_ed25519_check},		
	// 
	{"rc4", ll_rc4},
	{"rc4raw", ll_rc4raw},
	{"md5", ll_md5},
	//
	{NULL, NULL},
};

int luaopen_luazen (lua_State *L) {
	luaL_register (L, "luazen", llib);
    // 
    lua_pushliteral (L, "VERSION");
	lua_pushliteral (L, VERSION); 
	lua_settable (L, -3);
	return 1;
}




