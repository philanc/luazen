// Copyright (c) 2018 Phil Leblanc  -- see LICENSE file
// ---------------------------------------------------------------------
// chacha20-poly1305 authenticated encryption

/*
This is directly extracted from the Monocypher library by Loup Vaillant.
http://loup-vaillant.fr/projects/monocypher/ 

20170805  - updated to Monocypher v1.0.1

Monocypher license is included in file crypto_licenses.md

*/
// -- from monocypher.h

#include <inttypes.h>
#include <stddef.h>


// Chacha20
typedef struct {
    uint32_t input[16]; // current input, unencrypted
    uint32_t pool [16]; // last input, encrypted
    size_t   pool_idx;  // pointer to random_pool
} crypto_chacha_ctx;

// Poly1305
typedef struct {
    uint32_t r[4];   // constant multiplier (from the secret key)
    uint32_t h[5];   // accumulated hash
    uint32_t c[5];   // chunk of the message
    uint32_t pad[4]; // random number added at the end (from the secret key)
    size_t   c_idx;  // How many bytes are there in the chunk.
} crypto_poly1305_ctx;

// Authenticated encryption
typedef struct {
    crypto_chacha_ctx   chacha;
    crypto_poly1305_ctx poly;
    uint64_t            ad_size;
    uint64_t            message_size;
    int                 ad_phase;
} crypto_lock_ctx;
#define crypto_unlock_ctx crypto_lock_ctx

// Authenticated encryption
// ------------------------

// Direct interface
void crypto_lock(uint8_t        mac[16],
                 uint8_t       *cipher_text,
                 const uint8_t  key[32],
                 const uint8_t  nonce[24],
                 const uint8_t *plain_text, size_t text_size);
int crypto_unlock(uint8_t       *plain_text,
                  const uint8_t  key[32],
                  const uint8_t  nonce[24],
                  const uint8_t  mac[16],
                  const uint8_t *cipher_text, size_t text_size);

// Direct interface with additional data
void crypto_lock_aead(uint8_t        mac[16],
                      uint8_t       *cipher_text,
                      const uint8_t  key[32],
                      const uint8_t  nonce[24],
                      const uint8_t *ad        , size_t ad_size,
                      const uint8_t *plain_text, size_t text_size);
int crypto_unlock_aead(uint8_t       *plain_text,
                       const uint8_t  key[32],
                       const uint8_t  nonce[24],
                       const uint8_t  mac[16],
                       const uint8_t *ad         , size_t ad_size,
                       const uint8_t *cipher_text, size_t text_size);

// Incremental interface (encryption)
void crypto_lock_init(crypto_lock_ctx *ctx,
                      const uint8_t    key[32],
                      const uint8_t    nonce[24]);
void crypto_lock_auth_ad(crypto_lock_ctx *ctx,
                         const uint8_t   *message,
                         size_t           message_size);
void crypto_lock_auth_message(crypto_lock_ctx *ctx,
                              const uint8_t *cipher_text, size_t text_size);
void crypto_lock_update(crypto_lock_ctx *ctx,
                        uint8_t         *cipher_text,
                        const uint8_t   *plain_text,
                        size_t           text_size);
void crypto_lock_final(crypto_lock_ctx *ctx, uint8_t mac[16]);

// Incremental interface (decryption)
#define crypto_unlock_init         crypto_lock_init
#define crypto_unlock_auth_ad      crypto_lock_auth_ad
#define crypto_unlock_auth_message crypto_lock_auth_message
void crypto_unlock_update(crypto_unlock_ctx *ctx,
                          uint8_t           *plain_text,
                          const uint8_t     *cipher_text,
                          size_t             text_size);
int crypto_unlock_final(crypto_unlock_ctx *ctx, const uint8_t mac[16]);

////////////////////////////
/// Low level primitives ///
////////////////////////////

// For experts only.  You have been warned.


// Chacha20
// --------

// Specialised hash.
void crypto_chacha20_H(uint8_t       out[32],
                       const uint8_t key[32],
                       const uint8_t in [16]);

void crypto_chacha20_init(crypto_chacha_ctx *ctx,
                          const uint8_t      key[32],
                          const uint8_t      nonce[8]);

void crypto_chacha20_x_init(crypto_chacha_ctx *ctx,
                            const uint8_t      key[32],
                            const uint8_t      nonce[24]);

void crypto_chacha20_set_ctr(crypto_chacha_ctx *ctx, uint64_t ctr);

void crypto_chacha20_encrypt(crypto_chacha_ctx *ctx,
                             uint8_t           *cipher_text,
                             const uint8_t     *plain_text,
                             size_t             text_size);

void crypto_chacha20_stream(crypto_chacha_ctx *ctx,
                            uint8_t *stream, size_t size);


// Poly 1305
// ---------

// Direct interface
void crypto_poly1305(uint8_t        mac[16],
                     const uint8_t *message, size_t message_size,
                     const uint8_t  key[32]);

// Incremental interface
void crypto_poly1305_init  (crypto_poly1305_ctx *ctx, const uint8_t key[32]);
void crypto_poly1305_update(crypto_poly1305_ctx *ctx,
                            const uint8_t *message, size_t message_size);
void crypto_poly1305_final (crypto_poly1305_ctx *ctx, uint8_t mac[16]);




// ---------------------------------------------------------------------
// -- from monocypher.c


#define FOR(i, start, end) for (size_t (i) = (start); (i) < (end); (i)++)
#define WIPE_CTX(ctx)       crypto_wipe(ctx   , sizeof(*(ctx)))
#define WIPE_BUFFER(buffer) crypto_wipe(buffer, sizeof(buffer))
typedef uint8_t  u8;
typedef uint32_t u32;
typedef int32_t  i32;
typedef int64_t  i64;
typedef uint64_t u64;

#define MIN(a, b) ((a) <= (b) ? (a) : (b))

static u32 load24_le(const u8 s[3])
{
    return (u32)s[0]
        | ((u32)s[1] <<  8)
        | ((u32)s[2] << 16);
}

static u32 load32_le(const u8 s[4])
{
    return (u32)s[0]
        | ((u32)s[1] <<  8)
        | ((u32)s[2] << 16)
        | ((u32)s[3] << 24);
}

static u64 load64_le(const u8 s[8])
{
    return load32_le(s) | ((u64)load32_le(s+4) << 32);
}

static void store32_le(u8 out[4], u32 in)
{
    out[0] =  in        & 0xff;
    out[1] = (in >>  8) & 0xff;
    out[2] = (in >> 16) & 0xff;
    out[3] = (in >> 24) & 0xff;
}

static void store64_le(u8 out[8], u64 in)
{
    store32_le(out    , in      );
    store32_le(out + 4, in >> 32);
}

static u64 rotr64(u64 x, u64 n) { return (x >> n) ^ (x << (64 - n)); }
static u32 rotl32(u32 x, u32 n) { return (x << n) ^ (x >> (32 - n)); }

static int neq0(u64 diff)
{   // constant time comparison to zero
    // return diff != 0 ? -1 : 0
    u64 half = (diff >> 32) | ((u32)diff);
    return (1 & ((half - 1) >> 32)) - 1;
}

static u64 x16(const u8 a[16], const u8 b[16])
{
    return (load64_le(a + 0) ^ load64_le(b + 0))
        |  (load64_le(a + 8) ^ load64_le(b + 8));
}
static u64 x32(const u8 a[16],const u8 b[16]){return x16(a,b) | x16(a+16, b+16);}
static u64 x64(const u8 a[64],const u8 b[64]){return x32(a,b) | x32(a+32, b+32);}

static int crypto_verify16(const u8 a[16], const u8 b[16]){ return neq0(x16(a, b)); }
static int crypto_verify32(const u8 a[32], const u8 b[32]){ return neq0(x32(a, b)); }
static int crypto_verify64(const u8 a[64], const u8 b[64]){ return neq0(x64(a, b)); }

static int zerocmp32(const u8 p[32])
{
    u8 zero[32] = {0};
    return crypto_verify32(p, zero);
}

static void crypto_wipe(void *secret, size_t size)
{
    volatile u8 *v_secret = (u8*)secret;
    FOR (i, 0, size) {
        v_secret[i] = 0;
    }
}

/////////////////
/// Chacha 20 ///
/////////////////
#define QUARTERROUND(a, b, c, d)     \
    a += b;  d = rotl32(d ^ a, 16);  \
    c += d;  b = rotl32(b ^ c, 12);  \
    a += b;  d = rotl32(d ^ a,  8);  \
    c += d;  b = rotl32(b ^ c,  7)

static void chacha20_rounds(u32 out[16], const u32 in[16])
{
    // The temporary variables make Chacha20 10% faster.
    u32 t0  = in[ 0];  u32 t1  = in[ 1];  u32 t2  = in[ 2];  u32 t3  = in[ 3];
    u32 t4  = in[ 4];  u32 t5  = in[ 5];  u32 t6  = in[ 6];  u32 t7  = in[ 7];
    u32 t8  = in[ 8];  u32 t9  = in[ 9];  u32 t10 = in[10];  u32 t11 = in[11];
    u32 t12 = in[12];  u32 t13 = in[13];  u32 t14 = in[14];  u32 t15 = in[15];

    FOR (i, 0, 10) { // 20 rounds, 2 rounds per loop.
        QUARTERROUND(t0, t4, t8 , t12); // column 0
        QUARTERROUND(t1, t5, t9 , t13); // column 1
        QUARTERROUND(t2, t6, t10, t14); // column 2
        QUARTERROUND(t3, t7, t11, t15); // column 3
        QUARTERROUND(t0, t5, t10, t15); // diagonal 0
        QUARTERROUND(t1, t6, t11, t12); // diagonal 1
        QUARTERROUND(t2, t7, t8 , t13); // diagonal 2
        QUARTERROUND(t3, t4, t9 , t14); // diagonal 3
    }
    out[ 0] = t0;   out[ 1] = t1;   out[ 2] = t2;   out[ 3] = t3;
    out[ 4] = t4;   out[ 5] = t5;   out[ 6] = t6;   out[ 7] = t7;
    out[ 8] = t8;   out[ 9] = t9;   out[10] = t10;  out[11] = t11;
    out[12] = t12;  out[13] = t13;  out[14] = t14;  out[15] = t15;
}

static void chacha20_init_key(crypto_chacha_ctx *ctx, const u8 key[32])
{
    // constant
    ctx->input[0] = load32_le((u8*)"expa");
    ctx->input[1] = load32_le((u8*)"nd 3");
    ctx->input[2] = load32_le((u8*)"2-by");
    ctx->input[3] = load32_le((u8*)"te k");
    // key
    FOR (i, 0, 8) {
        ctx->input[i+4] = load32_le(key + i*4);
    }
}

static u8 chacha20_pool_byte(crypto_chacha_ctx *ctx)
{
    u32 pool_word = ctx->pool[ctx->pool_idx >> 2];
    u8  pool_byte = pool_word >> (8*(ctx->pool_idx & 3));
    ctx->pool_idx++;
    return pool_byte;
}

// Fill the pool if needed, update the counters
static void chacha20_refill_pool(crypto_chacha_ctx *ctx)
{
    chacha20_rounds(ctx->pool, ctx->input);
    FOR (j, 0, 16) {
        ctx->pool[j] += ctx->input[j];
    }
    ctx->pool_idx = 0;
    ctx->input[12]++;
    if (ctx->input[12] == 0) {
        ctx->input[13]++;
    }
}

void crypto_chacha20_H(u8 out[32], const u8 key[32], const u8 in[16])
{
    crypto_chacha_ctx ctx;
    chacha20_init_key(&ctx, key);
    FOR (i, 0, 4) {
        ctx.input[i+12] = load32_le(in + i*4);
    }
    u32 buffer[16];
    chacha20_rounds(buffer, ctx.input);
    // prevents reversal of the rounds by revealing only half of the buffer.
    FOR (i, 0, 4) {
        store32_le(out      + i*4, buffer[i     ]); // constant
        store32_le(out + 16 + i*4, buffer[i + 12]); // counter and nonce
    }
    WIPE_CTX(&ctx);
    WIPE_BUFFER(buffer);
}

static void chacha20_encrypt(crypto_chacha_ctx *ctx,
                             u8                *cipher_text,
                             const u8          *plain_text,
                             size_t             text_size)
{
    FOR (i, 0, text_size) {
        if (ctx->pool_idx == 64) {
            chacha20_refill_pool(ctx);
        }
        u8 plain = 0;
        if (plain_text != 0) {
            plain = *plain_text;
            plain_text++;
        }
        *cipher_text = chacha20_pool_byte(ctx) ^ plain;
        cipher_text++;
    }
}

void crypto_chacha20_init(crypto_chacha_ctx *ctx,
                          const u8           key[32],
                          const u8           nonce[8])
{
    chacha20_init_key      (ctx, key);     // key
    crypto_chacha20_set_ctr(ctx, 0  );     // counter
    ctx->input[14] = load32_le(nonce + 0); // nonce
    ctx->input[15] = load32_le(nonce + 4); // nonce
}

void crypto_chacha20_x_init(crypto_chacha_ctx *ctx,
                            const u8           key[32],
                            const u8           nonce[24])
{
    u8 derived_key[32];
    crypto_chacha20_H(derived_key, key, nonce);
    crypto_chacha20_init(ctx, derived_key, nonce + 16);
}

void crypto_chacha20_set_ctr(crypto_chacha_ctx *ctx, u64 ctr)
{
    ctx->input[12] = ctr & 0xffffffff;
    ctx->input[13] = ctr >> 32;
    ctx->pool_idx  = 64;  // The random pool (re)starts empty
}

void crypto_chacha20_encrypt(crypto_chacha_ctx *ctx,
                             u8                *cipher_text,
                             const u8          *plain_text,
                             size_t             text_size)
{
    // Align ourselves with block boundaries
    size_t align = MIN(-ctx->pool_idx & 63, text_size);
    chacha20_encrypt(ctx, cipher_text, plain_text, align);
    if (plain_text != 0) {
        plain_text += align;
    }
    cipher_text += align;
    text_size   -= align;

    // Process the message block by block
    FOR (i, 0, text_size >> 6) {  // number of blocks
        chacha20_refill_pool(ctx);
        if (plain_text != 0) {
            FOR (j, 0, 16) {
                u32 plain = load32_le(plain_text);
                store32_le(cipher_text, ctx->pool[j] ^ plain);
                plain_text  += 4;
                cipher_text += 4;
            }
        } else {
            FOR (j, 0, 16) {
                store32_le(cipher_text, ctx->pool[j]);
                cipher_text += 4;
            }
        }
        ctx->pool_idx = 64;
    }
    text_size &= 63;

    // remaining bytes
    chacha20_encrypt(ctx, cipher_text, plain_text, text_size);
}

void crypto_chacha20_stream(crypto_chacha_ctx *ctx,
                            uint8_t *stream, size_t size)
{
    crypto_chacha20_encrypt(ctx, stream, 0, size);
}


/////////////////
/// Poly 1305 ///
/////////////////

// h = (h + c) * r
// preconditions:
//   ctx->h <= 4_ffffffff_ffffffff_ffffffff_ffffffff
//   ctx->c <= 1_ffffffff_ffffffff_ffffffff_ffffffff
//   ctx->r <=   0ffffffc_0ffffffc_0ffffffc_0fffffff
// Postcondition:
//   ctx->h <= 4_ffffffff_ffffffff_ffffffff_ffffffff
static void poly_block(crypto_poly1305_ctx *ctx)
{
    // s = h + c, without carry propagation
    const u64 s0 = ctx->h[0] + (u64)ctx->c[0]; // s0 <= 1_fffffffe
    const u64 s1 = ctx->h[1] + (u64)ctx->c[1]; // s1 <= 1_fffffffe
    const u64 s2 = ctx->h[2] + (u64)ctx->c[2]; // s2 <= 1_fffffffe
    const u64 s3 = ctx->h[3] + (u64)ctx->c[3]; // s3 <= 1_fffffffe
    const u64 s4 = ctx->h[4] + (u64)ctx->c[4]; // s4 <=          5

    // Local all the things!
    const u32 r0 = ctx->r[0];       // r0  <= 0fffffff
    const u32 r1 = ctx->r[1];       // r1  <= 0ffffffc
    const u32 r2 = ctx->r[2];       // r2  <= 0ffffffc
    const u32 r3 = ctx->r[3];       // r3  <= 0ffffffc
    const u32 rr0 = (r0 >> 2) * 5;  // rr0 <= 13fffffb // lose 2 bits...
    const u32 rr1 = (r1 >> 2) + r1; // rr1 <= 13fffffb // rr1 == (r1 >> 2) * 5
    const u32 rr2 = (r2 >> 2) + r2; // rr2 <= 13fffffb // rr1 == (r2 >> 2) * 5
    const u32 rr3 = (r3 >> 2) + r3; // rr3 <= 13fffffb // rr1 == (r3 >> 2) * 5

    // (h + c) * r, without carry propagation
    const u64 x0 = s0*r0 + s1*rr3 + s2*rr2 + s3*rr1 + s4*rr0;//<=97ffffe007fffff8
    const u64 x1 = s0*r1 + s1*r0  + s2*rr3 + s3*rr2 + s4*rr1;//<=8fffffe20ffffff6
    const u64 x2 = s0*r2 + s1*r1  + s2*r0  + s3*rr3 + s4*rr2;//<=87ffffe417fffff4
    const u64 x3 = s0*r3 + s1*r2  + s2*r1  + s3*r0  + s4*rr3;//<=7fffffe61ffffff2
    const u32 x4 = s4 * (r0 & 3); // ...recover 2 bits       //<=               f

    // partial reduction modulo 2^130 - 5
    const u32 u5 = x4 + (x3 >> 32); // u5 <= 7ffffff5
    const u64 u0 = (u5 >>  2) * 5 + (x0 & 0xffffffff);
    const u64 u1 = (u0 >> 32)     + (x1 & 0xffffffff) + (x0 >> 32);
    const u64 u2 = (u1 >> 32)     + (x2 & 0xffffffff) + (x1 >> 32);
    const u64 u3 = (u2 >> 32)     + (x3 & 0xffffffff) + (x2 >> 32);
    const u64 u4 = (u3 >> 32)     + (u5 & 3);

    // Update the hash
    ctx->h[0] = u0 & 0xffffffff; // u0 <= 1_9ffffff0
    ctx->h[1] = u1 & 0xffffffff; // u1 <= 1_97ffffe0
    ctx->h[2] = u2 & 0xffffffff; // u2 <= 1_8fffffe2
    ctx->h[3] = u3 & 0xffffffff; // u3 <= 1_87ffffe4
    ctx->h[4] = u4;              // u4 <=          4
}

// (re-)initializes the input counter and input buffer
static void poly_clear_c(crypto_poly1305_ctx *ctx)
{
    ctx->c[0]  = 0;
    ctx->c[1]  = 0;
    ctx->c[2]  = 0;
    ctx->c[3]  = 0;
    ctx->c_idx = 0;
}

static void poly_take_input(crypto_poly1305_ctx *ctx, u8 input)
{
    size_t word = ctx->c_idx >> 2;
    size_t byte = ctx->c_idx & 3;
    ctx->c[word] |= (u32)input << (byte * 8);
    ctx->c_idx++;
}

static void poly_update(crypto_poly1305_ctx *ctx,
                        const u8 *message, size_t message_size)
{
    FOR (i, 0, message_size) {
        poly_take_input(ctx, message[i]);
        if (ctx->c_idx == 16) {
            poly_block(ctx);
            poly_clear_c(ctx);
        }
    }
}

void crypto_poly1305_init(crypto_poly1305_ctx *ctx, const u8 key[32])
{
    // Initial hash is zero
    FOR (i, 0, 5) {
        ctx->h [i] = 0;
    }
    // add 2^130 to every input block
    ctx->c  [4] = 1;
    poly_clear_c(ctx);
    // load r and pad (r has some of its bits cleared)
    FOR (i, 0, 1) { ctx->r  [0] = load32_le(key           ) & 0x0fffffff; }
    FOR (i, 1, 4) { ctx->r  [i] = load32_le(key + i*4     ) & 0x0ffffffc; }
    FOR (i, 0, 4) { ctx->pad[i] = load32_le(key + i*4 + 16);              }
}

void crypto_poly1305_update(crypto_poly1305_ctx *ctx,
                            const u8 *message, size_t message_size)
{
    // Align ourselves with block boundaries
    size_t align = MIN(-ctx->c_idx & 15, message_size);
    poly_update(ctx, message, align);
    message      += align;
    message_size -= align;

    // Process the message block by block
    size_t nb_blocks = message_size >> 4;
    FOR (i, 0, nb_blocks) {
        ctx->c[0] = load32_le(message +  0);
        ctx->c[1] = load32_le(message +  4);
        ctx->c[2] = load32_le(message +  8);
        ctx->c[3] = load32_le(message + 12);
        poly_block(ctx);
        message += 16;
    }
    if (nb_blocks > 0) {
        poly_clear_c(ctx);
    }
    message_size &= 15;

    // remaining bytes
    poly_update(ctx, message, message_size);
}

void crypto_poly1305_final(crypto_poly1305_ctx *ctx, u8 mac[16])
{
    // Process the last block (if any)
    if (ctx->c_idx != 0) {
        // move the final 1 according to remaining input length
        // (We may add less than 2^130 to the last input block)
        ctx->c[4] = 0;
        poly_take_input(ctx, 1);
        // one last hash update
        poly_block(ctx);
    }

    // check if we should subtract 2^130-5 by performing the
    // corresponding carry propagation.
    const u64 u0 = (u64)5     + ctx->h[0]; // <= 1_00000004
    const u64 u1 = (u0 >> 32) + ctx->h[1]; // <= 1_00000000
    const u64 u2 = (u1 >> 32) + ctx->h[2]; // <= 1_00000000
    const u64 u3 = (u2 >> 32) + ctx->h[3]; // <= 1_00000000
    const u64 u4 = (u3 >> 32) + ctx->h[4]; // <=          5
    // u4 indicates how many times we should subtract 2^130-5 (0 or 1)

    // h + pad, minus 2^130-5 if u4 exceeds 3
    const u64 uu0 = (u4 >> 2) * 5 + ctx->h[0] + ctx->pad[0]; // <= 2_00000003
    const u64 uu1 = (uu0 >> 32)   + ctx->h[1] + ctx->pad[1]; // <= 2_00000000
    const u64 uu2 = (uu1 >> 32)   + ctx->h[2] + ctx->pad[2]; // <= 2_00000000
    const u64 uu3 = (uu2 >> 32)   + ctx->h[3] + ctx->pad[3]; // <= 2_00000000

    store32_le(mac     , uu0);
    store32_le(mac +  4, uu1);
    store32_le(mac +  8, uu2);
    store32_le(mac + 12, uu3);

    WIPE_CTX(ctx);
}

void crypto_poly1305(u8     mac[16],  const u8 *message,
                     size_t message_size, const u8  key[32])
{
    crypto_poly1305_ctx ctx;
    crypto_poly1305_init  (&ctx, key);
    crypto_poly1305_update(&ctx, message, message_size);
    crypto_poly1305_final (&ctx, mac);
}


////////////////////////////////
/// Authenticated encryption ///
////////////////////////////////
static void lock_ad_padding(crypto_lock_ctx *ctx)
{
    static const u8 zero[15] = {0};
    if (ctx->ad_phase) {
        ctx->ad_phase = 0;
        crypto_poly1305_update(&ctx->poly, zero, -ctx->ad_size & 15);
    }
}

void crypto_lock_init(crypto_lock_ctx *ctx, const u8 key[32], const u8 nonce[24])
{
    u8 auth_key[64]; // "Wasting" the whole Chacha block is faster
    ctx->ad_phase     = 1;
    ctx->ad_size      = 0;
    ctx->message_size = 0;
    crypto_chacha20_x_init(&ctx->chacha, key, nonce);
    crypto_chacha20_stream(&ctx->chacha, auth_key, 64);
    crypto_poly1305_init  (&ctx->poly  , auth_key);
    WIPE_BUFFER(auth_key);
}

void crypto_lock_auth_ad(crypto_lock_ctx *ctx, const u8 *msg, size_t msg_size)
{
    crypto_poly1305_update(&ctx->poly, msg, msg_size);
    ctx->ad_size += msg_size;
}

void crypto_lock_auth_message(crypto_lock_ctx *ctx,
                              const u8 *cipher_text, size_t text_size)
{
    lock_ad_padding(ctx);
    ctx->message_size += text_size;
    crypto_poly1305_update(&ctx->poly, cipher_text, text_size);
}

void crypto_lock_update(crypto_lock_ctx *ctx, u8 *cipher_text,
                        const u8 *plain_text, size_t text_size)
{
    crypto_chacha20_encrypt(&ctx->chacha, cipher_text, plain_text, text_size);
    crypto_lock_auth_message(ctx, cipher_text, text_size);
}

void crypto_lock_final(crypto_lock_ctx *ctx, u8 mac[16])
{
    lock_ad_padding(ctx);
    static const u8 zero[15] = {0};
    u8 sizes[16];
    store64_le(sizes + 0, ctx->ad_size);
    store64_le(sizes + 8, ctx->message_size);
    crypto_poly1305_update(&ctx->poly, zero, -ctx->message_size & 15);
    crypto_poly1305_update(&ctx->poly, sizes, 16);
    crypto_poly1305_final (&ctx->poly, mac);
    WIPE_CTX(ctx);
}

void crypto_unlock_update(crypto_lock_ctx *ctx, u8 *plain_text,
                          const u8 *cipher_text, size_t text_size)
{
    crypto_unlock_auth_message(ctx, cipher_text, text_size);
    crypto_chacha20_encrypt(&ctx->chacha, plain_text, cipher_text, text_size);
}

int crypto_unlock_final(crypto_lock_ctx *ctx, const u8 mac[16])
{
    u8 real_mac[16];
    crypto_lock_final(ctx, real_mac);
    int mismatch = crypto_verify16(real_mac, mac);
    WIPE_BUFFER(real_mac);
    return mismatch;
}

void crypto_lock_aead(u8        mac[16],
                      u8       *cipher_text,
                      const u8  key[32],
                      const u8  nonce[24],
                      const u8 *ad        , size_t ad_size,
                      const u8 *plain_text, size_t text_size)
{
    crypto_lock_ctx ctx;
    crypto_lock_init   (&ctx, key, nonce);
    crypto_lock_auth_ad(&ctx, ad, ad_size);
    crypto_lock_update (&ctx, cipher_text, plain_text, text_size);
    crypto_lock_final  (&ctx, mac);
}

int crypto_unlock_aead(u8       *plain_text,
                       const u8  key[32],
                       const u8  nonce[24],
                       const u8  mac[16],
                       const u8 *ad         , size_t ad_size,
                       const u8 *cipher_text, size_t text_size)
{
    crypto_unlock_ctx ctx;
    crypto_unlock_init        (&ctx, key, nonce);
    crypto_unlock_auth_ad     (&ctx, ad, ad_size);
    crypto_unlock_auth_message(&ctx, cipher_text, text_size);
    crypto_chacha_ctx chacha_ctx = ctx.chacha; // avoid the wiping...
    if (crypto_unlock_final(&ctx, mac)) {      // ...that occurs here
        WIPE_CTX(&chacha_ctx);
        return -1; // reject forgeries before wasting our time decrypting
    }
    crypto_chacha20_encrypt(&chacha_ctx, plain_text, cipher_text, text_size);
    WIPE_CTX(&chacha_ctx);
    return 0;
}




// -- end of monocypher content

// ---------------------------------------------------------------------
// lua binding


#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lua.h"
#include "lauxlib.h"

# define LERR(msg) return luaL_error(L, msg)



int ll_xchacha_encrypt(lua_State *L) {
	// Lua API: encrypt(k, n, m [, ninc [, aad ]])  return c
	//  k: key string (32 bytes)
	//  n: nonce string (24 bytes)
	//	m: message (plain text) string 
	//  ninc: optional nonce increment (useful when encrypting a long message
	//       as a sequence of block). The same parameter n can be used for 
	//       the sequence. ninc is added to n for each block, so the actual
	//       nonce used for each block encryption is distinct.
	//       ninc defaults to 0 (the nonce n is used as-is)
	//  aad: prefix additional data (not encrypted, prepended to the 
	//       encrypted message). default to the empty string
	//  return encrypted text string c with aad prefix 
	//  (c includes the 16-byte MAC: #c = #aad + #m + 16)
	int r;
	int xchacha_flag = 0; // 0 => Chacha20, 1 => XChacha20
	size_t mln, nln, kln, aadln, cln, bufln;
	const char *k = luaL_checklstring(L,1,&kln);
	const char *n = luaL_checklstring(L,2,&nln);	
	const char *m = luaL_checklstring(L,3,&mln);	
	uint64_t ninc = luaL_optinteger(L, 4, 0);	
	const char *aad = luaL_optlstring(L,5,"",&aadln);
	if (nln == 24) xchacha_flag = 1;
	else if (nln == 16) xchacha_flag = 0;
	else LERR("bad nonce size");
	if (kln != 32) LERR("bad key size");
	bufln = aadln + mln + 16;
	unsigned char * buf = malloc(bufln);
	char actn[24]; // actual nonce ("n + ninc")
	memcpy(actn, n, nln); 
	// addition modulo 2^64 over the first 8 bytes of n
	// (overflow not an issue: uint addition overflow _is_ defined)
	(*(uint64_t *) actn) = (*(uint64_t *) actn) + ninc;
	memcpy(buf, aad, aadln); // copy aad prefix
	// xchacha
	crypto_lock_aead(
		buf+aadln+mln, // ptr to mac
		buf+aadln,     // ptr to encrypted text
		k, actn, aad, aadln, m, mln);
	lua_pushlstring (L, buf, bufln); 
	free(buf);
	return 1;
} // ll_xchacha_encrypt()

int ll_xchacha_decrypt(lua_State *L) {
	// Lua API: decrypt(k, n, c [, ninc [, aadln ]]) 
	//     return (m, aad) or (nil, msg)
	//  k: key string (32 bytes)
	//  n: nonce string (24 or 16 bytes)
	//	c: encrypted message string 
	//  ninc: optional nonce increment (see above. defaults to 0)
	//  aadln: length of the AD prefix (default to 0)
	//  return (plain text, aad) or (nil, errmsg) if MAC is not valid
	int r = 0;
	int xchacha_flag = 0; // 0 => Chacha20, 1 => XChacha20
	size_t cln, nln, kln, boxln, mln;
	const char *k = luaL_checklstring(L, 1, &kln);
	const char *n = luaL_checklstring(L, 2, &nln);	
	const char *c = luaL_checklstring(L, 3, &cln);	
	uint64_t ninc = luaL_optinteger(L, 4, 0);	
	size_t aadln = luaL_optinteger(L, 5, 0);	
	if (nln == 24) xchacha_flag = 1;
	else if (nln == 16) xchacha_flag = 0;
	else LERR("bad nonce size");
	if (kln != 32) LERR("bad key size");
	boxln = cln - aadln;
	unsigned char * buf = malloc(boxln);
	char actn[24]; // actual nonce "n + ninc"
	memcpy(actn, n, nln); 
	(*(uint64_t *) actn) = (*(uint64_t *) actn) + ninc;
	mln = cln - aadln - 16;
	r = crypto_unlock_aead(
			buf,
			k, actn,
			c + cln - 16,  // mac address (last 16 bytes of encrypted message)
			c, aadln,  // aad is at the beginning of c
			c + aadln, mln); // encrypted text, text size
			
	if (r != 0) { 
		free(buf); 
		lua_pushnil (L);
		lua_pushliteral(L, "decrypt error");
		return 2;         
	} 
	lua_pushlstring (L, buf, mln); 
	lua_pushlstring (L, c, aadln); 
	free(buf);
	return 2;
} // ll_xchacha_decrypt()


