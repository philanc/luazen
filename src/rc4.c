// Copyright (c) 2018 Phil Leblanc  -- see LICENSE file
// ---------------------------------------------------------------------
// rc4

// ---------------------------------------------------------------------
// Original RC4 code written by Christophe Devine. 

typedef struct {
    unsigned char x, y, m[256];
} rc4_ctx;

void rc4_setup(rc4_ctx *ctx, const unsigned char *key, int length);
void rc4_crypt(rc4_ctx *ctx, const unsigned char *src, unsigned char *dst, int length);

void rc4_setup(
        rc4_ctx *ctx, 
        const unsigned char *key, 
        int keyln) {
    int i, j = 0, k = 0, a;
    unsigned char *m;
    ctx->x = 0;
    ctx->y = 0;
    m = ctx->m;
    for (i = 0; i < 256; i++)
        m[i] = i;
    for (i = 0; i < 256; i++) {
        a = m[i];
        j = (unsigned char)(j + a + key[k]);
        m[i] = m[j]; 
        m[j] = a;
        if (++k >= keyln) 
            k = 0;
    }
}

/**
 * Perform the encrypt/decrypt operation (can use it for either since
 * this is a stream cipher).
 */
void rc4_crypt(
        rc4_ctx *ctx, 
        const unsigned char *src, 
        unsigned char *dst, 
        int srcln) { 
    int i;
    unsigned char *m, x, y, a, b;
    x = ctx->x;
    y = ctx->y;
    m = ctx->m;
    for (i = 0; i < srcln; i++) {
        a = m[++x];
        y += a;
        m[x] = b = m[y];
        m[y] = a;
        dst[i] =  src[i] ^ m[(unsigned char)(a + b)];
    }
    ctx->x = x;
    ctx->y = y;
}

// ---------------------------------------------------------------------
// lua binding


#include <stdlib.h>
#include <assert.h>

#include "lua.h"
#include "lauxlib.h"

# define LERR(msg) return luaL_error(L, msg)


//--- rc4raw() - a rc4 encrypt/decrypt function
//-- see http://en.wikipedia.org/wiki/RC4 for raw rc4 weaknesses
//-- use rc4() instead for regular uses (a rc4-drop implementation)
//
int ll_rc4raw(lua_State *L) {
	size_t sln, kln; 
	const char *src = luaL_checklstring (L, 1, &sln);
	const char *key = luaL_checklstring (L, 2, &kln);
	if (kln != 16)  LERR("bad key size");
	char *dst = (char *) malloc(sln); 
	rc4_ctx ctx;
	rc4_setup(&ctx, key, kln); 
	rc4_crypt(&ctx, src, dst, sln);
	lua_pushlstring (L, dst, sln); 
	free(dst);
	return 1;
}


#define DROPLN 256

//--- rc4() - a rc4-drop encrypt/decrypt function
//-- see http://www.users.zetnet.co.uk/hopwood/crypto/scan/cs.html#RC4-drop
//-- encrypt and drop DROPLN bytes before starting to encrypt the plain text
//
int ll_rc4(lua_State *L) {
    size_t sln, kln; 
    const char *src = luaL_checklstring (L, 1, &sln);
    const char *key = luaL_checklstring (L, 2, &kln);
	if (kln != 16)  LERR("bad key size");
	char drop[DROPLN]; 
	// ensure drop is zeroed
	int i;  for (i=0;  i<DROPLN; i++) drop[i] = 0;
    char *dst = (char *) malloc(sln); 
    rc4_ctx ctx;
    rc4_setup(&ctx, key, kln); 
    // drop initial DROPLN bytes of keystream
    rc4_crypt(&ctx, drop, drop, DROPLN);
    // crypt actual input
    rc4_crypt(&ctx, src, dst, sln);
    lua_pushlstring (L, dst, sln); 
    free(dst);
    return 1;
}

