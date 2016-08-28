
/**
 * An implementation of the RC4/ARC4 algorithm.
 * Originally written by Christophe Devine. 
 */
 
 #include "rc4.h"

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
