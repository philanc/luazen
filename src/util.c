// Copyright (c) 2018 Phil Leblanc  -- see LICENSE file
// ---------------------------------------------------------------------
// Lua binding to utility functions: randombytes, base64/58 encoding, ...


// ---------------------------------------------------------------------
// interface to the OS Random Number Generator  

#ifdef _WIN32
// ------------------------------
// randombytes()  for windows
// Use the Windows RNG (CryptGenRandom)
// tested with MinGW (2016-07-31)

#include <stdlib.h>  /// for exit() 

#include <windows.h>
#include <wincrypt.h> /* CryptAcquireContext, CryptGenRandom */

int randombytes(unsigned char *x,unsigned long long xlen)
{


  HCRYPTPROV p;
  ULONG i;

if (xlen > 4096) {
		xlen = 4096; 
}
	
  if (CryptAcquireContext(&p, NULL, NULL,
      PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) == FALSE) {
		return(-1); 
  }
  if (CryptGenRandom(p, xlen, (BYTE *)x) == FALSE) {
		return(-1); 
  }
  CryptReleaseContext(p, 0);
  return 0;
}	

#else // unix
// -------------------------------
// use getrandom() or /dev/urandom

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#if defined __GLIBC_PREREQ && !defined __UCLIBC__
#define GLIBC_PREREQ(M, m) (__GLIBC_PREREQ(M, m))
#else
#define GLIBC_PREREQ(M, m) 0
#endif

// the getrandom() detection code below has been provided by Daurnimator 
// (https://github.com/daurnimator)
#ifndef HAVE_GETRANDOM
#define HAVE_GETRANDOM (GLIBC_PREREQ(2,25) && __linux__)
#endif
#if HAVE_GETRANDOM
#include <sys/random.h>
#endif

int randombytes(unsigned char *x, unsigned long long xlen) {
	int fd, i;
	size_t count = (size_t) xlen;

#if HAVE_GETRANDOM
	i = getrandom(x, count, 0);
#else
	fd = open("/dev/urandom",O_RDONLY);
	if (fd == -1) { 
		return -1; 
	}
	i = read(fd, x, count);
	close(fd);
#endif
	if ((i < 0) || (i < count)) { 
		return -1; 
	}
	return 0;
}

#endif

// ---------------------------------------------------------------------

// ---------------------------------------------------------------------


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
extern bool b58tobin(char *bin, size_t *binsz, const char *b58, size_t b58sz);
extern bool b58enc(char *b58, size_t *b58sz, const char *bin, size_t binsz);

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
//-- lua binding functions

static int ll_randombytes(lua_State *L) {
	// Lua API:   randombytes(n)  returns a string with n random bytes 
	// n must be 256 or less.
	// randombytes return nil, error msg  if the RNG fails or if n > 256
	//	
    size_t bufln; 
	unsigned char buf[256];
	lua_Integer li = luaL_checkinteger(L, 1);  // 1st arg
	if ((li > 256 ) || (li < 0)) {
		lua_pushnil (L);
		lua_pushliteral(L, "invalid byte number");
		return 2;      		
	}
	int r = randombytes(buf, li);
	if (r != 0) { 
		lua_pushnil (L);
		lua_pushliteral(L, "random generator error");
		return 2;         
	} 	
    lua_pushlstring (L, buf, li); 
	return 1;
} //randombytes()


//--- xor(input:string, key:string) =>  output:string
//-- obfuscate a string using xor and a key string
//-- output is same length as input
//-- if key is shorter than input, it is repeated as much as necessary
//
static int ll_xor(lua_State *L) {
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

static int ll_b64encode(lua_State *L) {
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

static int ll_b64decode(lua_State *L)		/** decode(s) */
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

static int ll_b58encode(lua_State *L) {
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


static int ll_b58decode(lua_State *L) {
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
	{NULL, NULL},
};

int luaopen_clc_util (lua_State *L) {
	luaL_register (L, "clc.util", llib);
    // 
    lua_pushliteral (L, "VERSION");
	lua_pushliteral (L, VERSION); 
	lua_settable (L, -3);
	return 1;
}




