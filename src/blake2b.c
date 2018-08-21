// Copyright (c) 2018 Phil Leblanc  -- see LICENSE file
// ---------------------------------------------------------------------
// blake2b

/*
This is directly extracted from the Monocypher library by Loup Vaillant.
http://loup-vaillant.fr/projects/monocypher/ 

20170805  - updated to Monocypher v1.0.1

Monocypher license is included in file crypto_licenses.md

*/
// -- from monocypher.h

#include <inttypes.h>
#include <stddef.h>

// Blake2b context.  Do not rely on its contents or its size, they
// may change without notice.
typedef struct {
    uint64_t hash[8];
    uint64_t input_offset[2];
    uint64_t input[16];
    size_t   input_idx;
    size_t   hash_size;
} crypto_blake2b_ctx;

void crypto_blake2b_general_init(crypto_blake2b_ctx *ctx, size_t hash_size,
                                 const uint8_t      *key, size_t key_size);

void crypto_blake2b_init(crypto_blake2b_ctx *ctx);

void crypto_blake2b_update(crypto_blake2b_ctx *ctx,
                           const uint8_t *message, size_t message_size);

void crypto_blake2b_final(crypto_blake2b_ctx *ctx, uint8_t *hash);

void crypto_blake2b_general(uint8_t       *hash    , size_t hash_size,
                            const uint8_t *key     , size_t key_size, // optional
                            const uint8_t *message , size_t message_size);

void crypto_blake2b(uint8_t hash[64],
                    const uint8_t *message, size_t message_size);

// -- from monocypher.c

#define FOR(i, start, end) for (size_t (i) = (start); (i) < (end); (i)++)
typedef uint8_t  u8;
typedef uint32_t u32;
typedef int32_t  i32;
typedef int64_t  i64;
typedef uint64_t u64;

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
    return (u64)s[0]
        | ((u64)s[1] <<  8)
        | ((u64)s[2] << 16)
        | ((u64)s[3] << 24)
        | ((u64)s[4] << 32)
        | ((u64)s[5] << 40)
        | ((u64)s[6] << 48)
        | ((u64)s[7] << 56);
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
    out[0] =  in        & 0xff;
    out[1] = (in >>  8) & 0xff;
    out[2] = (in >> 16) & 0xff;
    out[3] = (in >> 24) & 0xff;
    out[4] = (in >> 32) & 0xff;
    out[5] = (in >> 40) & 0xff;
    out[6] = (in >> 48) & 0xff;
    out[7] = (in >> 56) & 0xff;
}

static u64 rotr64(u64 x, u64 n) { return (x >> n) ^ (x << (64 - n)); }
static u32 rotl32(u32 x, u32 n) { return (x << n) ^ (x >> (32 - n)); }

static int crypto_memcmp(const u8 *p1, const u8 *p2, size_t n)
{
    unsigned diff = 0;
    FOR (i, 0, n) {
        diff |= (p1[i] ^ p2[i]);
    }
    return (1 & ((diff - 1) >> 8)) - 1;
}

static int crypto_zerocmp(const u8 *p, size_t n)
{
    unsigned diff = 0;
    FOR (i, 0, n) {
        diff |= p[i];
    }
    return (1 & ((diff - 1) >> 8)) - 1;
}


////////////////
/// Blake2 b /// (taken from the reference
////////////////  implentation in RFC 7693)

static const u64 iv[8] = {
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
};

// increment the input offset
static void blake2b_incr(crypto_blake2b_ctx *ctx)
{
    u64   *x = ctx->input_offset;
    size_t y = ctx->input_idx;
    x[0] += y;
    if (x[0] < y) {
        x[1]++;
    }
}

static void blake2b_set_input(crypto_blake2b_ctx *ctx, u8 input)
{
    size_t word = ctx->input_idx / 8;
    size_t byte = ctx->input_idx % 8;
    ctx->input[word] |= (u64)input << (byte * 8);
    ctx->input_idx++;
}

static void blake2b_compress(crypto_blake2b_ctx *ctx, int is_last_block)
{
    static const u8 sigma[12][16] = {
        {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
        { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
        { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
        {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
        {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
        {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
        { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
        { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
        {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
        { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
        {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
        { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    };

    // init work vector
    u64 v[16];
    FOR (i, 0, 8) {
        v[i  ] = ctx->hash[i];
        v[i+8] = iv[i];
    }
    v[12] ^= ctx->input_offset[0];
    v[13] ^= ctx->input_offset[1];
    if (is_last_block) {
        v[14] = ~v[14];
    }

    // mangle work vector
    uint64_t *input = ctx->input;
    FOR (i, 0, 12) {
#define BLAKE2_G(v, a, b, c, d, x, y)                       \
        v[a] += v[b] + x;  v[d] = rotr64(v[d] ^ v[a], 32);  \
        v[c] += v[d];      v[b] = rotr64(v[b] ^ v[c], 24);  \
        v[a] += v[b] + y;  v[d] = rotr64(v[d] ^ v[a], 16);  \
        v[c] += v[d];      v[b] = rotr64(v[b] ^ v[c], 63);  \

        BLAKE2_G(v, 0, 4,  8, 12, input[sigma[i][ 0]], input[sigma[i][ 1]]);
        BLAKE2_G(v, 1, 5,  9, 13, input[sigma[i][ 2]], input[sigma[i][ 3]]);
        BLAKE2_G(v, 2, 6, 10, 14, input[sigma[i][ 4]], input[sigma[i][ 5]]);
        BLAKE2_G(v, 3, 7, 11, 15, input[sigma[i][ 6]], input[sigma[i][ 7]]);
        BLAKE2_G(v, 0, 5, 10, 15, input[sigma[i][ 8]], input[sigma[i][ 9]]);
        BLAKE2_G(v, 1, 6, 11, 12, input[sigma[i][10]], input[sigma[i][11]]);
        BLAKE2_G(v, 2, 7,  8, 13, input[sigma[i][12]], input[sigma[i][13]]);
        BLAKE2_G(v, 3, 4,  9, 14, input[sigma[i][14]], input[sigma[i][15]]);
    }
    // update hash
    FOR (i, 0, 8) {
        ctx->hash[i] ^= v[i] ^ v[i+8];
    }
}

static void blake2b_reset_input(crypto_blake2b_ctx *ctx)
{
    FOR(i, 0, 16) {
        ctx->input[i] = 0;
    }
    ctx->input_idx = 0;
}

static void blake2b_end_block(crypto_blake2b_ctx *ctx)
{
    if (ctx->input_idx == 128) {  // If buffer is full,
        blake2b_incr(ctx);        // update the input offset
        blake2b_compress(ctx, 0); // and compress the (not last) block
        blake2b_reset_input(ctx);
    }
}

void crypto_blake2b_general_init(crypto_blake2b_ctx *ctx, size_t hash_size,
                                 const u8           *key, size_t key_size)
{
    // initial hash
    FOR (i, 0, 8) {
        ctx->hash[i] = iv[i];
    }
    ctx->hash[0] ^= 0x01010000 ^ (key_size << 8) ^ hash_size;

    ctx->input_offset[0] = 0;         // begining of the input, no offset
    ctx->input_offset[1] = 0;         // begining of the input, no offset
    ctx->input_idx       = 0;         // buffer is empty
    ctx->hash_size       = hash_size; // remember the hash size we want
    blake2b_reset_input(ctx);         // clear the input buffer

    // if there is a key, the first block is that key
    if (key_size > 0) {
        crypto_blake2b_update(ctx, key, key_size);
        ctx->input_idx = 128;
    }
}

void crypto_blake2b_init(crypto_blake2b_ctx *ctx)
{
    crypto_blake2b_general_init(ctx, 64, 0, 0);
}

void crypto_blake2b_update(crypto_blake2b_ctx *ctx,
                           const u8 *message, size_t message_size)
{
    // Align ourselves with 8 byte words
    while (ctx->input_idx % 8 != 0 && message_size > 0) {
        blake2b_set_input(ctx, *message);
        message++;
        message_size--;
    }

    // Process the input 8 bytes at a time
    size_t nb_words  = message_size / 8;
    size_t remainder = message_size % 8;
    FOR (i, 0, nb_words) {
        blake2b_end_block(ctx);
        ctx->input[ctx->input_idx / 8] = load64_le(message);
        message        += 8;
        ctx->input_idx += 8;
    }

    // Load the remainder
    if (remainder != 0) {
        blake2b_end_block(ctx);
    }
    FOR (i, 0, remainder) {
        blake2b_set_input(ctx, message[i]);
    }
}

void crypto_blake2b_final(crypto_blake2b_ctx *ctx, u8 *hash)
{
    blake2b_incr(ctx);        // update the input offset
    blake2b_compress(ctx, 1); // compress the last block
    size_t nb_words  = ctx->hash_size / 8;
    FOR (i, 0, nb_words) {
        store64_le(hash + i*8, ctx->hash[i]);
    }
    FOR (i, nb_words * 8, ctx->hash_size) {
        hash[i] = (ctx->hash[i / 8] >> (8 * (i % 8))) & 0xff;
    }
}

void crypto_blake2b_general(u8       *hash   , size_t hash_size,
                            const u8 *key    , size_t key_size,
                            const u8 *message, size_t message_size)
{
    crypto_blake2b_ctx ctx;
    crypto_blake2b_general_init(&ctx, hash_size, key, key_size);
    crypto_blake2b_update(&ctx, message, message_size);
    crypto_blake2b_final(&ctx, hash);
}

void crypto_blake2b(u8 hash[64], const u8 *message, size_t message_size)
{
    crypto_blake2b_general(hash, 64, 0, 0, message, message_size);
}










////////////////
/// Argon2 i ///
////////////////

///  allow to build without Argon2i function
#ifndef NOARGON

// references to R, Z, Q etc. come from the spec

// Argon2 operates on 1024 byte blocks.
typedef struct { u64 a[128]; } block;

static u32 min(u32 a, u32 b) { return a <= b ? a : b; }

// updates a blake2 hash with a 32 bit word, little endian.
static void blake_update_32(crypto_blake2b_ctx *ctx, u32 input)
{
    u8 buf[4];
    store32_le(buf, input);
    crypto_blake2b_update(ctx, buf, 4);
}

static void load_block(block *b, const u8 bytes[1024])
{
    FOR (i, 0, 128) {
        b->a[i] = load64_le(bytes + i*8);
    }
}

static void store_block(u8 bytes[1024], const block *b)
{
    FOR (i, 0, 128) {
        store64_le(bytes + i*8, b->a[i]);
    }
}

static void copy_block(block *o,const block*in){FOR(i,0,128) o->a[i] = in->a[i];}
static void  xor_block(block *o,const block*in){FOR(i,0,128) o->a[i]^= in->a[i];}

// Hash with a virtually unlimited digest size.
// Doesn't extract more entropy than the base hash function.
// Mainly used for filling a whole kilobyte block with pseudo-random bytes.
// (One could use a stream cipher with a seed hash as the key, but
//  this would introduce another dependency —and point of failure.)
static void extended_hash(u8       *digest, u32 digest_size,
                          const u8 *input , u32 input_size)
{
    crypto_blake2b_ctx ctx;
    crypto_blake2b_general_init(&ctx, min(digest_size, 64), 0, 0);
    blake_update_32            (&ctx, digest_size);
    crypto_blake2b_update      (&ctx, input, input_size);
    crypto_blake2b_final       (&ctx, digest);

    if (digest_size > 64) {
        // the conversion to u64 avoids integer overflow on
        // ludicrously big hash sizes.
        u32 r   = (((u64)digest_size + 31) / 32) - 2;
        u32 i   =  1;
        u32 in  =  0;
        u32 out = 32;
        while (i < r) {
            // Input and output overlap. This is intentional
            crypto_blake2b(digest + out, digest + in, 64);
            i   +=  1;
            in  += 32;
            out += 32;
        }
        crypto_blake2b_general(digest + out, digest_size - (32 * r),
                               0, 0, // no key
                               digest + in , 64);
    }
}

#define LSB(x) ((x) & 0xffffffff)
#define G(a, b, c, d)                                            \
    a += b + 2 * LSB(a) * LSB(b);  d ^= a;  d = rotr64(d, 32);   \
    c += d + 2 * LSB(c) * LSB(d);  b ^= c;  b = rotr64(b, 24);   \
    a += b + 2 * LSB(a) * LSB(b);  d ^= a;  d = rotr64(d, 16);   \
    c += d + 2 * LSB(c) * LSB(d);  b ^= c;  b = rotr64(b, 63)
#define ROUND(v0,  v1,  v2,  v3,  v4,  v5,  v6,  v7,    \
              v8,  v9, v10, v11, v12, v13, v14, v15)    \
    G(v0, v4,  v8, v12);  G(v1, v5,  v9, v13);          \
    G(v2, v6, v10, v14);  G(v3, v7, v11, v15);          \
    G(v0, v5, v10, v15);  G(v1, v6, v11, v12);          \
    G(v2, v7,  v8, v13);  G(v3, v4,  v9, v14)

// Core of the compression function G.  Computes Z from R in place.
static void g_rounds(block *work_block)
{
    // column rounds (work_block = Q)
    for (int i = 0; i < 128; i += 16) {
        ROUND(work_block->a[i     ], work_block->a[i +  1],
              work_block->a[i +  2], work_block->a[i +  3],
              work_block->a[i +  4], work_block->a[i +  5],
              work_block->a[i +  6], work_block->a[i +  7],
              work_block->a[i +  8], work_block->a[i +  9],
              work_block->a[i + 10], work_block->a[i + 11],
              work_block->a[i + 12], work_block->a[i + 13],
              work_block->a[i + 14], work_block->a[i + 15]);
    }
    // row rounds (work_block = Z)
    for (int i = 0; i < 16; i += 2) {
        ROUND(work_block->a[i      ], work_block->a[i +   1],
              work_block->a[i +  16], work_block->a[i +  17],
              work_block->a[i +  32], work_block->a[i +  33],
              work_block->a[i +  48], work_block->a[i +  49],
              work_block->a[i +  64], work_block->a[i +  65],
              work_block->a[i +  80], work_block->a[i +  81],
              work_block->a[i +  96], work_block->a[i +  97],
              work_block->a[i + 112], work_block->a[i + 113]);
    }
}

// The compression function G (copy version for the first pass)
static void g_copy(block *result, const block *x, const block *y)
{
    block tmp;
    copy_block(&tmp  , x   ); // tmp    = X
    xor_block (&tmp  , y   ); // tmp    = X ^ Y = R
    copy_block(result, &tmp); // result = R         (only difference with g_xor)
    g_rounds  (&tmp);         // tmp    = Z
    xor_block (result, &tmp); // result = R ^ Z
}

// The compression function G (xor version for subsequent passes)
static void g_xor(block *result, const block *x, const block *y)
{
    block tmp;
    copy_block(&tmp  , x   ); // tmp    = X
    xor_block (&tmp  , y   ); // tmp    = X ^ Y = R
    xor_block (result, &tmp); // result = R ^ old   (only difference with g_copy)
    g_rounds  (&tmp);         // tmp    = Z
    xor_block (result, &tmp); // result = R ^ old ^ Z
}

// unary version of the compression function.
// The missing argument is implied zero.
// Does the transformation in place.
static void unary_g(block *work_block)
{
    // work_block == R
    block tmp;
    copy_block(&tmp, work_block); // tmp        = R
    g_rounds(work_block);         // work_block = Z
    xor_block(work_block, &tmp);  // work_block = Z ^ R
}

// Argon2i uses a kind of stream cipher to determine which reference
// block it will take to synthesise the next block.  This context hold
// that stream's state.  (It's very similar to Chacha20.  The block b
// is anologous to Chacha's own pool)
typedef struct {
    block b;
    u32 pass_number;
    u32 slice_number;
    u32 nb_blocks;
    u32 nb_iterations;
    u32 ctr;
    u32 offset;
} gidx_ctx;

// The block in the context will determine array indices. To avoid
// timing attacks, it only depends on public information.  No looking
// at a previous block to seed the next.  This makes offline attacks
// easier, but timing attacks are the bigger threat in many settings.
static void gidx_refresh(gidx_ctx *ctx)
{
    // seed the begining of the block...
    ctx->b.a[0] = ctx->pass_number;
    ctx->b.a[1] = 0;  // lane number (we have only one)
    ctx->b.a[2] = ctx->slice_number;
    ctx->b.a[3] = ctx->nb_blocks;
    ctx->b.a[4] = ctx->nb_iterations;
    ctx->b.a[5] = 1;  // type: Argon2i
    ctx->b.a[6] = ctx->ctr;
    FOR (i, 7, 128) { ctx->b.a[i] = 0; } // ...then zero the rest out

    // Shuffle the block thus: ctx->b = G((G(ctx->b, zero)), zero)
    // (G "square" function), to get cheap pseudo-random numbers.
    unary_g(&(ctx->b));
    unary_g(&(ctx->b));
}

static void gidx_init(gidx_ctx *ctx,
                      u32 pass_number, u32 slice_number,
                      u32 nb_blocks,   u32 nb_iterations)
{
    ctx->pass_number   = pass_number;
    ctx->slice_number  = slice_number;
    ctx->nb_blocks     = nb_blocks;
    ctx->nb_iterations = nb_iterations;
    ctx->ctr           = 0;

    // Offset from the begining of the segment.  For the first slice
    // of the first pass, we start at the *third* block, so the offset
    // starts at 2, not 0.
    if (pass_number != 0 || slice_number != 0) {
        ctx->offset = 0;
    } else {
        ctx->offset = 2;
        ctx->ctr++;         // Compensates for missed lazy creation
        gidx_refresh(ctx);  // at the start of gidx_next()
    }
}

static u32 gidx_next(gidx_ctx *ctx)
{
    // lazily creates the offset block we need
    if (ctx->offset % 128 == 0) {
        ctx->ctr++;
        gidx_refresh(ctx);
    }
    u32 index  = ctx->offset % 128; // save index  for current call
    u32 offset = ctx->offset;       // save offset for current call
    ctx->offset++;                  // update offset for next call

    // Computes the area size.
    // Pass 0 : all already finished segments plus already constructed
    //          blocks in this segment
    // Pass 1+: 3 last segments plus already constructed
    //          blocks in this segment.  THE SPEC SUGGESTS OTHERWISE.
    //          I CONFORM TO THE REFERENCE IMPLEMENTATION.
    int first_pass  = ctx->pass_number == 0;
    u32 slice_size  = ctx->nb_blocks / 4;
    u32 nb_segments = first_pass ? ctx->slice_number : 3;
    u32 area_size   = nb_segments * slice_size + offset - 1;

    // Computes the starting position of the reference area.
    // CONTRARY TO WHAT THE SPEC SUGGESTS, IT STARTS AT THE
    // NEXT SEGMENT, NOT THE NEXT BLOCK.
    u32 next_slice = ((ctx->slice_number + 1) % 4) * slice_size;
    u32 start_pos  = first_pass ? 0 : next_slice;

    // Generate offset from J1 (no need for J2, there's only one lane)
    u64 j1         = ctx->b.a[index] & 0xffffffff; // pseudo-random number
    u64 x          = (j1 * j1)       >> 32;
    u64 y          = (area_size * x) >> 32;
    u64 z          = (area_size - 1) - y;
    return (start_pos + z) % ctx->nb_blocks;
}

// Main algorithm
void crypto_argon2i(u8       *hash,      u32 hash_size,
                    void     *work_area, u32 nb_blocks, u32 nb_iterations,
                    const u8 *password,  u32 password_size,
                    const u8 *salt,      u32 salt_size,
                    const u8 *key,       u32 key_size,
                    const u8 *ad,        u32 ad_size)
{
    // work area seen as blocks (must be suitably aligned)
    block *blocks = (block*)work_area;
    {
        crypto_blake2b_ctx ctx;
        crypto_blake2b_init(&ctx);

        blake_update_32      (&ctx, 1            ); // p: number of threads
        blake_update_32      (&ctx, hash_size    );
        blake_update_32      (&ctx, nb_blocks    );
        blake_update_32      (&ctx, nb_iterations);
        blake_update_32      (&ctx, 0x13         ); // v: version number
        blake_update_32      (&ctx, 1            ); // y: Argon2i
        blake_update_32      (&ctx,           password_size);
        crypto_blake2b_update(&ctx, password, password_size);
        blake_update_32      (&ctx,           salt_size);
        crypto_blake2b_update(&ctx, salt,     salt_size);
        blake_update_32      (&ctx,           key_size);
        crypto_blake2b_update(&ctx, key,      key_size);
        blake_update_32      (&ctx,           ad_size);
        crypto_blake2b_update(&ctx, ad,       ad_size);

        u8 initial_hash[72]; // 64 bytes plus 2 words for future hashes
        crypto_blake2b_final(&ctx, initial_hash);

        // fill first 2 blocks
        block   tmp_block;
        u8 hash_area[1024];
        store32_le(initial_hash + 64, 0); // first  additional word
        store32_le(initial_hash + 68, 0); // second additional word
        extended_hash(hash_area, 1024, initial_hash, 72);
        load_block(&tmp_block, hash_area);
        copy_block(blocks, &tmp_block);

        store32_le(initial_hash + 64, 1); // slight modification
        extended_hash(hash_area, 1024, initial_hash, 72);
        load_block(&tmp_block, hash_area);
        copy_block(blocks + 1, &tmp_block);
    }

    // Actual number of blocks
    nb_blocks -= nb_blocks % 4; // round down to 4 p (p == 1 thread)
    const u32 segment_size = nb_blocks / 4;

    // fill (then re-fill) the rest of the blocks
    FOR (pass_number, 0, nb_iterations) {
        int first_pass = pass_number == 0;

        FOR (segment, 0, 4) {
            gidx_ctx ctx;
            gidx_init(&ctx, pass_number, segment, nb_blocks, nb_iterations);

            // On the first segment of the first pass,
            // blocks 0 and 1 are already filled.
            // We use the offset to skip them.
            u32 start_offset  = first_pass && segment == 0 ? 2 : 0;
            u32 segment_start = segment * segment_size + start_offset;
            u32 segment_end   = (segment + 1) * segment_size;
            FOR (current_block, segment_start, segment_end) {
                u32 reference_block = gidx_next(&ctx);
                u32 previous_block  = current_block == 0
                                    ? nb_blocks - 1
                                    : current_block - 1;
                block *c = blocks + current_block;
                block *p = blocks + previous_block;
                block *r = blocks + reference_block;
                if (first_pass) { g_copy(c, p, r); }
                else            { g_xor (c, p, r); }
            }
        }
    }
    // hash the very last block with H' into the output hash
    u8 final_block[1024];
    store_block(final_block, blocks + (nb_blocks - 1));
    extended_hash(hash, hash_size, final_block, 1024);
}


#endif /// NOARGON

// -- end of monocypher content




// ---------------------------------------------------------------------
// lua binding


#include <stdlib.h>
#include <assert.h>

#include "lua.h"
#include "lauxlib.h"

# define LERR(msg) return luaL_error(L, msg)

int ll_blake2b(lua_State *L) {
	// compute the hash of a string
	// lua api:  blake2b(m [, digln [, key]]) return digest
	// m: the string to be hashed
	// digln: the optional length of the digest to be computed 
	// (between 1 and 64) - default value is 64
	// key: an optional secret key, allowing blake2b to work as a MAC 
	//    (if provided, key length must be between 1 and 64)
	//    default is no key
	// digest: the blake2b hash as a string (string length is digln,
	// so default hash is a 64-byte string)
	size_t mln; 
	size_t keyln = 0; 
	const char *m = luaL_checklstring (L, 1, &mln);
	int digln = luaL_optinteger(L, 2, 64);
	const char *key = luaL_optlstring(L, 3, NULL, &keyln);
	if ((keyln < 0)||(keyln > 64)) LERR("bad key size");
	if ((digln < 1)||(digln > 64)) LERR("bad digest size");
	char digest[64];
	crypto_blake2b_general(digest, digln, key, keyln, m, mln);
	lua_pushlstring (L, digest, digln); 
	return 1;
}// ll_blake2b

// argon2i password derivation
//
#ifndef NOARGON

int ll_argon2i(lua_State *L) {
	// Lua API: argon2i(pw, salt, nkb, niters) => k
	// pw: the password string
	// salt: some entropy as a string (typically 16 bytes)
	// nkb:  number of kilobytes used in RAM (as large as possible)
	// niters: number of iterations (as large as possible, >= 10)
	//  return k, a key string (32 bytes)
	size_t pwln, saltln, kln, mln;
	const char *pw = luaL_checklstring(L,1,&pwln);
	const char *salt = luaL_checklstring(L,2,&saltln);	
	int nkb = luaL_checkinteger(L,3);	
	int niters = luaL_checkinteger(L,4);	
	unsigned char k[32];
	size_t worksize = nkb * 1024;
	unsigned char *work= malloc(worksize);
	crypto_argon2i(	k, 32, work, nkb, niters,
					pw, pwln, salt, saltln, 
					"", 0, "", 0 	// optional key and additional data
					);

	lua_pushlstring (L, k, 32); 
	free(work);
	return 1;
} // ll_argon2i()
#endif
