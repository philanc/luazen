// Copyright (c) 2018 Phil Leblanc  -- see LICENSE file
// ---------------------------------------------------------------------
// base64 encoding 


// ---------------------------------------------------------------------
// lua binding

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lua.h"
#include "lauxlib.h"

# define LERR(msg) return luaL_error(L, msg)

// (exported functions are prefixed with 'll_')

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

int ll_b64encode(lua_State *L) {
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
	   lua_isnoneornil(L, 2) ? B64LINELENGTH : luaL_checkinteger(L, 2)
	); 
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
	case 1: b64encode(&b,s[0],0,0,1);	break;
	case 2: b64encode(&b,s[0],s[1],0,2);	break;
	}
	luaL_pushresult(&b);
	return 1;
}

static void b64decode(luaL_Buffer *b, 
		int c1, int c2, int c3, int c4, int n) {
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

 int ll_b64decode(lua_State *L) {
	// Lua api: b64decode(str)
	// str is the base64-encoded string to decode
	// return the decoded string or nil if str contains 
	// an invalid character (whitespaces and newlines are ignored)
	//
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
		case '=':
		//ph: added 'case 0:' here to allow decoding of non well-formed 
		//    encoded strings (ie. strings with no padding)
		case 0:  
			switch (n) 	{
				case 1: b64decode(&b,t[0],0,0,0,1);       break;
				case 2: b64decode(&b,t[0],t[1],0,0,2);    break;
				case 3: b64decode(&b,t[0],t[1],t[2],0,3); break;
			}
			luaL_pushresult(&b);
			return 1;
		case '\n': 
		case '\r': 
		case '\t': 
		case ' ':
		case '\f': 
		case '\b':
			break;
		default:
			p=strchr(code,c); if (p==NULL) return 0;
			t[n++]= p-code;
			if (n==4) 	{
				b64decode(&b,t[0],t[1],t[2],t[3],4);
				n=0;
			}
			break;
		} //switch(c)
	} //for(;;)
	return 0;
}
