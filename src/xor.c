// Copyright (c) 2018 Phil Leblanc  -- see LICENSE file
// ---------------------------------------------------------------------
// xor


#include <stdlib.h>
#include <assert.h>

#include "lua.h"
#include "lauxlib.h"

# define LERR(msg) return luaL_error(L, msg)

//--- xor(input:string, key:string) =>  output:string
//-- obfuscate a string using xor and a key string
//-- output is same length as input
//-- if key is shorter than input, it is repeated as much as necessary
//
int ll_xor(lua_State *L) {
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
