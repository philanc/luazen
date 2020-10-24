// Copyright (c) 2019 Phil Leblanc  -- see LICENSE file
// ---------------------------------------------------------------------
// lzma - a Lua binding to LZMA by Igor Pavlov (7z)
//	- all the LZMA code included here is Public Domain


//----------------------------------------------------------------------
// lua binding

#include <stdint.h>
#include <string.h>
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

static uint64_t load64_le(const uint8_t s[8]) {
    return (uint64_t)s[0]
        | ((uint64_t)s[1] <<  8)
        | ((uint64_t)s[2] << 16)
        | ((uint64_t)s[3] << 24)
        | ((uint64_t)s[4] << 32)
        | ((uint64_t)s[5] << 40)
        | ((uint64_t)s[6] << 48)
        | ((uint64_t)s[7] << 56);
}

static void store64_le(uint8_t out[8], uint64_t in) {
    out[0] =  in        & 0xff;
    out[1] = (in >>  8) & 0xff;
    out[2] = (in >> 16) & 0xff;
    out[3] = (in >> 24) & 0xff;
    out[4] = (in >> 32) & 0xff;
    out[5] = (in >> 40) & 0xff;
    out[6] = (in >> 48) & 0xff;
    out[7] = (in >> 56) & 0xff;
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
	bufln = sln + (sln >> 3) + 16384; 
	unsigned char * buf = lua_newuserdata(L, bufln);

	// buffer format: 
	// 2020-10-24 - use a format as can be uncompressed by the 
	// linux lzma/unlzma commands:
	//	- LZMA props: LZMA_PROPS_SIZE bytes (ie 5 bytes)
	//	- uncompressed string length stored little endian (8 bytes)
	//	- compressed output (at offset = LZMA_PROPS_SIZE + 8)
	//	

	// cln, propssize _MUST_ be initialized before calling LzmaCompress
	propssize = LZMA_PROPS_SIZE; // = 5
	cln = bufln - LZMA_PROPS_SIZE - 8; // max available space in buf
	
	r = LzmaCompress(
		buf + LZMA_PROPS_SIZE + 8, &cln,  // dest, destlen
		s, sln, // src, srclen
		buf, &propssize, // props, propslen
		
		// !! DO NOT CHANGE THE FOLLOWING PARAMETERS !!
		// (they are used to recognize lzma standard format
		//  vs. the luazen lzma legacy format)
		
		5, // level 
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
	
	// store  uncompressed string length (little endian)
	store64_le(buf+LZMA_PROPS_SIZE, sln);
	lua_pushlstring (L, buf, LZMA_PROPS_SIZE + 8 + cln); 	
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
	uint64_t sln64;
	
	// LzmaUncompress parameters
	unsigned char *dest;
	size_t *destLen;
	const unsigned char *src;
	size_t *srcLen;
	const unsigned char *props;
	size_t propsSize;
	
	// try to guess compressed string format (legacy or standard)
	const char default_props[5] = {0x5d, 0, 0, 0, 1};
	if (strncmp(c, default_props, 5) == 0) {
		// standard format - set LzmaUncompress parameters
		sln64 = load64_le(c + LZMA_PROPS_SIZE);
		if (sln64 >= 1L<<32) { 
			lua_pushnil (L);
			lua_pushliteral(L, "uncompressed string too large");
			return 2;
		}
		dln = (size_t) sln64;
		destLen = &dln;
		src = c + LZMA_PROPS_SIZE + 8;
		cln = cln - (LZMA_PROPS_SIZE + 8);
		srcLen = &cln;
		props = c;
		propsSize = LZMA_PROPS_SIZE;
	} else {
		// assume legacy format - set LzmaUncompress parameters
		dln = load32_le(c);
		destLen = &dln;
		src = c + 4 + LZMA_PROPS_SIZE;
		cln = cln - (4 + LZMA_PROPS_SIZE);
		srcLen = &cln;
		props = c + 4;
		propsSize = LZMA_PROPS_SIZE;
	}
	dest = lua_newuserdata(L, dln); // allocate buffer 
	r = LzmaUncompress(dest, destLen, src, srcLen, props, propsSize);
	if (r != 0) {
		lua_pushnil (L);
		lua_pushliteral(L, "unlzma error");
		lua_pushinteger(L, r);
		return 3;         
	}
	lua_pushlstring (L, dest, dln); 
	return 1;
} //unlzma()
