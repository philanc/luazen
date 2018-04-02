// Copyright (c) 2018 Phil Leblanc  -- see LICENSE file
// ---------------------------------------------------------------------
// base58 encoding


// ---------------------------------------------------------------------
// -- The base58 code is derived from 
// https://raw.githubusercontent.com/luke-jr/libbase58/master/base58.c
// commit 13dfa66514fca15d1fe536f3ba9dda2c817cb03d 
// bitcoin specific stuff has been removed
// original file author, copyright and license info:
/*
 * Copyright 2012-2014 Luke Dashjr
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the standard MIT license.  See COPYING for more details.
 */
 #include <stdbool.h>
#include <stddef.h>

// max length of a string to encode with base58
#define B58MAXLN 256

// longest 256-byte encoded string is 350 bytes long.
// add a bit (b58enc add \0 at the end of the encoded string)
#define B58MAXENCLN 360

#include <stdint.h>
#include <string.h>
#include <sys/types.h>

/// !!VC
#define ssize_t int32_t

static const int8_t b58digits_map[] = {
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
	-1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,
	-1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
	22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,
	-1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,
	47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1,
};

bool b58tobin(char *bin, size_t *binszp, const char *b58, size_t b58sz)
{
	size_t binsz = *binszp;
	const unsigned char *b58u = (void*)b58;
	unsigned char *binu = bin;
	size_t outisz = B58MAXENCLN / 4;
	uint32_t outi[B58MAXENCLN / 4];
	uint64_t t;
	uint32_t c;
	size_t i, j;
	uint8_t bytesleft = binsz % 4;
	uint32_t zeromask = bytesleft ? (0xffffffff << (bytesleft * 8)) : 0;
	unsigned zerocount = 0;
	
	if (!b58sz)
		b58sz = strlen(b58);
	
	memset(outi, 0, outisz * sizeof(*outi));
	
	// Leading zeros, just count
	for (i = 0; i < b58sz && b58u[i] == '1'; ++i)
		++zerocount;
	
	for ( ; i < b58sz; ++i)
	{
		if (b58u[i] & 0x80)
			// High-bit set on invalid digit
			return false;
		if (b58digits_map[b58u[i]] == -1)
			// Invalid base58 digit
			return false;
		c = (unsigned)b58digits_map[b58u[i]];
		for (j = outisz; j--; )
		{
			t = ((uint64_t)outi[j]) * 58 + c;
			c = (t & 0x3f00000000) >> 32;
			outi[j] = t & 0xffffffff;
		}
		if (c)
			// Output number too big (carry to the next int32)
			return false;
		if (outi[0] & zeromask)
			// Output number too big (last int32 filled too far)
			return false;
	}
	
	j = 0;
	switch (bytesleft) {
		case 3:
			*(binu++) = (outi[0] &   0xff0000) >> 16;
		case 2:
			*(binu++) = (outi[0] &     0xff00) >>  8;
		case 1:
			*(binu++) = (outi[0] &       0xff);
			++j;
		default:
			break;
	}
	
	for (; j < outisz; ++j)
	{
		*(binu++) = (outi[j] >> 0x18) & 0xff;
		*(binu++) = (outi[j] >> 0x10) & 0xff;
		*(binu++) = (outi[j] >>    8) & 0xff;
		*(binu++) = (outi[j] >>    0) & 0xff;
	}
	
	// Count canonical base58 byte count
	binu = bin;
	for (i = 0; i < binsz; ++i)
	{
		if (binu[i])
			break;
		--*binszp;
	}
	*binszp += zerocount;
	
	return true;
}

static const char b58digits_ordered[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

bool b58enc(char *b58, size_t *b58sz, const char *data, size_t binsz)
{
	const uint8_t *bin = data;
	int carry;
	ssize_t i, j, high, zcount = 0;
	size_t size;
	
	while (zcount < binsz && !bin[zcount])
		++zcount;
	
	size = (binsz - zcount) * 138 / 100 + 1;
	uint8_t buf[B58MAXENCLN];
	memset(buf, 0, size);
	
	for (i = zcount, high = size - 1; i < binsz; ++i, high = j)
	{
		for (carry = bin[i], j = size - 1; (j > high) || carry; --j)
		{
			carry += 256 * buf[j];
			buf[j] = carry % 58;
			carry /= 58;
		}
	}
	
	for (j = 0; j < size && !buf[j]; ++j);
	
	if (*b58sz <= zcount + size - j)  	{
		// with the added size limit on encoded string,
		// this should never happen -- XXXXX remove the test?
		*b58sz = zcount + size - j + 1;
		return false;
	}
	
	if (zcount)
		memset(b58, '1', zcount);
	for (i = zcount; j < size; ++i, ++j)
		b58[i] = b58digits_ordered[buf[j]];
	b58[i] = '\0';
	*b58sz = i + 1;
	
	return true;
}


// ---------------------------------------------------------------------
// lua binding

#define VERSION "util-0.9"

#include <stdlib.h>
#include <assert.h>

#include "lua.h"
#include "lauxlib.h"

# define LERR(msg) return luaL_error(L, msg)

// (exported functions are prefixed with 'll_')

//------------------------------------------------------------
// base58 encode, decode 
// based on code from Luke Dashjr (MIT license - see source code)

// this encoding uses the same alphabet as bitcoin addresses:
//   "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

int ll_b58encode(lua_State *L) {
	// lua api:  b58encode(str) => encoded | (nil, error msg)
	// prereq:  #str <= 256  (defined as B58MAXLN)
	size_t bln, eln;
	unsigned char buf[B58MAXENCLN]; 	// buffer to receive encoded string
	const char *b = luaL_checklstring(L,1,&bln);	
	if (bln == 0) { // empty string special case (not ok with b58enc)
		lua_pushliteral (L, ""); 
		return 1;
	} else if (bln > B58MAXLN) {  
		LERR("string too long");
	}
	eln = B58MAXENCLN; // eln must be set to buffer size before calling b58enc
	bool r = b58enc(buf, &eln, b, bln);
	if (!r) LERR("b58encode error");
	eln = eln - 1;  // b58enc add \0 at the end of the encode string
	lua_pushlstring (L, buf, eln); 
	return 1;
}


int ll_b58decode(lua_State *L) {
	// lua api: b58decode(encstr) => str | (nil, error msg)
	size_t bln, eln;
	unsigned char buf[B58MAXENCLN]; 	// buffer to receive decoded string
	const char *e = luaL_checklstring(L,1,&eln); // encoded data
	if (eln == 0) { // empty string special case 
		lua_pushliteral (L, ""); 
		return 1;
	} else if (eln > B58MAXENCLN) {
		lua_pushnil (L);
		lua_pushfstring(L, "string too long");
		return 2;
	}
	bln = B58MAXENCLN; // give the result buffer size to b58tobin
	bool r = b58tobin(buf, &bln, e, eln);
	if (!r) { 
		lua_pushnil (L);
		lua_pushfstring(L, "b58decode error");
		return 2;         
	} 
	// b58tobin returns its result at the _end_ of buf!!!
	lua_pushlstring (L, buf+B58MAXENCLN-bln, bln); 
	return 1;
}
