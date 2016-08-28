

#ifndef _RC4_H
#define _RC4_H

typedef struct {
    unsigned char x, y, m[256];
} rc4_ctx;

void rc4_setup(rc4_ctx *ctx, const unsigned char *key, int length);
void rc4_crypt(rc4_ctx *ctx, const unsigned char *src, unsigned char *dst, int length);


#endif

