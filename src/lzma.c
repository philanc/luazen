// Copyright (c) 2019 Phil Leblanc  -- see LICENSE file
// ---------------------------------------------------------------------
// lzma - a Lua binding to LZMA by Igor Pavlov (7z)
//	- all the LZMA code included here is Public Domain


//----------------------------------------------------------------------
// lua binding

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "lua.h"
#include "lauxlib.h"

// single thread (no multi-thread support)
#define _7ZIP_ST

#include "lzma/LzmaLib.h"


//----------------------------------------------------------------------
//-- lua binding

static uint32_t load32_le(const uint8_t s[4]) {
    return (uint32_t)s[0]
        | ((uint32_t)s[1] <<  8)
        | ((uint32_t)s[2] << 16)
        | ((uint32_t)s[3] << 24);
}

static void store32_le(uint8_t out[4], uint32_t in) {
    out[0] =  in        & 0xff;
    out[1] = (in >>  8) & 0xff;
    out[2] = (in >> 16) & 0xff;
    out[3] = (in >> 24) & 0xff;
}

int ll_lzma(lua_State *L) {
	// Lua API:  compress(s) => c
	// compress string s, return compressed string c
	// or nil, error msg, lzma error number -- in case of error
	//
	size_t sln, cln, bufln, propssize;
	int r;
	const char *s = luaL_checklstring(L, 1, &sln);	
	assert(sln < 0xffffffff); // fit a uint32
	
	// allocate compression buffer:
	// bufln is buffer length. suggested value is input size + 11% +16kb
	// (we use 'sln + sln>>3', ie input length +12.5%)
	//~ bufln = sln + (sln >> 3) + 16384; 
	bufln = sln + (sln >> 3) + 66000; 
	unsigned char * buf = lua_newuserdata(L, bufln);

	// cln, propssize _MUST_ be initialized before calling LzmaCompress
	propssize = LZMA_PROPS_SIZE; // = 5
	cln = bufln - 4 - LZMA_PROPS_SIZE; // max available space in buf
	
	// input buffer contains:
	//	- input string length stored little endian (4 bytes)
	//	- LZMA props: LZMA_PROPS_SIZE bytes (ie 5 bytes)
	//	- compressed output (at offset = 4 + LZMA_PROPS_SIZE)
	//
	r = LzmaCompress(
		buf+4+LZMA_PROPS_SIZE, &cln,  // dest, destlen
		s, sln, // src, srclen
		buf+4, &propssize, // props, propslen
		5, // level -- default values for this and following params
		(1<<24), // dict size
		3, 	// lc
		0, 	// lp
		2,	// pb
		32, 	// fb
		1	// numthreads
		);
	
	if (r != 0) {
		lua_pushnil (L);
		lua_pushliteral(L, "lzma error");
		lua_pushinteger(L, r);
		return 3;         
	}
	
	// prefix compressed string with original s length (little endian)
	store32_le(buf, sln);
	lua_pushlstring (L, buf, cln + 4 + LZMA_PROPS_SIZE); 	
	return 1;
} //lzma()

int ll_unlzma(lua_State *L) {
	// Lua API:  uncompress(c) => s | nil, error msg
	// decompress string c, return original string s
	// or nil, error msg in case of decompression error
	//
	size_t sln, cln, bufln, dln;
	int r;
	const char *c = luaL_checklstring(L, 1, &cln);	
	sln = load32_le(c);  
	bufln = sln + 8;  // have some extra space.  ...for what?
	char * buf = lua_newuserdata(L, bufln);
	cln = cln - (4 + LZMA_PROPS_SIZE);
	dln = sln; // destlen must be the exact uncompressed length
	r = LzmaUncompress(buf, &dln, c + 4 + LZMA_PROPS_SIZE, &cln,
		c + 4, LZMA_PROPS_SIZE );
	if ((r != 0) || (dln != sln)) {
		printf("@@ dln: %d   sln: %d \n", dln, sln);
		lua_pushnil (L);
		lua_pushliteral(L, "unlzma error");
		lua_pushinteger(L, r);
		return 3;         
	}
	lua_pushlstring (L, buf, sln); 
	return 1;
} //unlzma()
