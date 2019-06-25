// Copyright (c) 2018 Phil Leblanc  -- see LICENSE file
// ---------------------------------------------------------------------
// lzma - a Lua binding to LZMA by Igor Pavlov, of 7z fame


//----------------------------------------------------------------------
// lua binding

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "lua.h"
#include "lauxlib.h"


/// include LzmaLib source (from lzma/C)

#include "lzma/7zTypes.h"
#include "lzma/Compiler.h"
#include "lzma/Alloc.h"
#include "lzma/Alloc.c"
#include "lzma/LzHash.h"
#include "lzma/LzFind.h"
#include "lzma/LzFind.c"

// MOVE_POS is defined in LzFind.c _and_ in LzmaEnc.c
#undef MOVE_POS

#include "lzma/LzmaDec.h"
#include "lzma/LzmaEnc.h"
#include "lzma/LzmaDec.c"
#include "lzma/LzmaEnc.c"
#include "lzma/LzmaLib.h"
#include "lzma/LzmaLib.c"



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
	// or nil, error msg in case of error
	//
	size_t sln, cln, bufln, propssize;
	int r;
	const char *s = luaL_checklstring(L, 1, &sln);	
	assert(sln < 0xffffffff); // fit a uint32
	// bufln is arbitrary. plan for very short input (+32),
	// uncompressible input (+12.5% -- sln>>3 ie div 8)
	// uncompressed size (+4)
	// lzma_props_size (+5)
	bufln = sln + (sln >> 3) + 1024; 
	char * buf = lua_newuserdata(L, bufln);
	r = LzmaCompress(buf+4+LZMA_PROPS_SIZE, &cln, s, sln,
		buf+4, &propssize,
		5, // level -- default values for all following params
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
	// prefix compressed string with original s length (stored as LE)
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
