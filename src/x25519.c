// Copyright (c) 2018 Phil Leblanc  -- see LICENSE file
// ---------------------------------------------------------------------
// 
//  ec25519 DH key exchanghe and ed25519 signature

/*
This is directly extracted from the Monocypher library by Loup Vaillant.
http://loup-vaillant.fr/projects/monocypher/ 
Monocypher license is included in file crypto_licenses.md

20170805  - updated to Monocypher v1.0.1

The hash function used for the digital signature is sha512

According to Loup Vaillant, the code is taken from the SUPERCOP ref10
implementation by Daniel Bernstein (public domain)

*/

// -- from monocypher.h

#include <inttypes.h>
#include <stddef.h>

#include "sha2.h"


// ---------------------------------------------------------------------
// -- from monocypher.c

// --use sha512
#define HASH crypto_sha512

#define COMBINE1(x, y) x ## y
#define COMBINE2(x, y) COMBINE1(x, y)
#define HASH_CTX    COMBINE2(HASH, _ctx)
#define HASH_INIT   COMBINE2(HASH, _init)
#define HASH_UPDATE COMBINE2(HASH, _update)
#define HASH_FINAL  COMBINE2(HASH, _final)

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


////////////////////////////////////
/// Arithmetic modulo 2^255 - 19 ///
////////////////////////////////////

//  Taken from Supercop's ref10 implementation.
//  A bit bigger than TweetNaCl, over 4 times faster.

// field element
typedef i32 fe[10];

static void fe_0   (fe h) {                     FOR(i,0,10) h[i] = 0;          }
static void fe_1   (fe h) {          h[0] = 1;  FOR(i,1,10) h[i] = 0;          }
static void fe_neg (fe h,const fe f)           {FOR(i,0,10) h[i] = -f[i];      }
static void fe_add (fe h,const fe f,const fe g){FOR(i,0,10) h[i] = f[i] + g[i];}
static void fe_sub (fe h,const fe f,const fe g){FOR(i,0,10) h[i] = f[i] - g[i];}
static void fe_copy(fe h,const fe f)           {FOR(i,0,10) h[i] = f[i];       }

static void fe_cswap(fe f, fe g, int b)
{
    FOR (i, 0, 10) {
        i32 x = (f[i] ^ g[i]) & -b;
        f[i] = f[i] ^ x;
        g[i] = g[i] ^ x;
    }
}

static void fe_carry(fe h, i64 t[10])
{
    i64 c0, c1, c2, c3, c4, c5, c6, c7, c8, c9;
    c9 = (t[9] + (i64) (1<<24)) >> 25; t[0] += c9 * 19; t[9] -= c9 * (1 << 25);
    c1 = (t[1] + (i64) (1<<24)) >> 25; t[2] += c1;      t[1] -= c1 * (1 << 25);
    c3 = (t[3] + (i64) (1<<24)) >> 25; t[4] += c3;      t[3] -= c3 * (1 << 25);
    c5 = (t[5] + (i64) (1<<24)) >> 25; t[6] += c5;      t[5] -= c5 * (1 << 25);
    c7 = (t[7] + (i64) (1<<24)) >> 25; t[8] += c7;      t[7] -= c7 * (1 << 25);
    c0 = (t[0] + (i64) (1<<25)) >> 26; t[1] += c0;      t[0] -= c0 * (1 << 26);
    c2 = (t[2] + (i64) (1<<25)) >> 26; t[3] += c2;      t[2] -= c2 * (1 << 26);
    c4 = (t[4] + (i64) (1<<25)) >> 26; t[5] += c4;      t[4] -= c4 * (1 << 26);
    c6 = (t[6] + (i64) (1<<25)) >> 26; t[7] += c6;      t[6] -= c6 * (1 << 26);
    c8 = (t[8] + (i64) (1<<25)) >> 26; t[9] += c8;      t[8] -= c8 * (1 << 26);
    FOR (i, 0, 10) { h[i] = t[i]; }
}

static void fe_frombytes(fe h, const u8 s[32])
{
    i64 t[10]; // intermediate result (may overflow 32 bits)
    t[0] =  load32_le(s);
    t[1] =  load24_le(s +  4) << 6;
    t[2] =  load24_le(s +  7) << 5;
    t[3] =  load24_le(s + 10) << 3;
    t[4] =  load24_le(s + 13) << 2;
    t[5] =  load32_le(s + 16);
    t[6] =  load24_le(s + 20) << 7;
    t[7] =  load24_le(s + 23) << 5;
    t[8] =  load24_le(s + 26) << 4;
    t[9] = (load24_le(s + 29) & 8388607) << 2;
    fe_carry(h, t);
}

static void fe_mul_small(fe h, const fe f, i32 g)
{
    i64 t[10];
    FOR(i, 0, 10) {
        t[i] = f[i] * (i64) g;
    }
    fe_carry(h, t);
}
static void fe_mul121666(fe h, const fe f) { fe_mul_small(h, f, 121666); }
static void fe_mul973324(fe h, const fe f) { fe_mul_small(h, f, 973324); }

static void fe_mul(fe h, const fe f, const fe g)
{
    // Everything is unrolled and put in temporary variables.
    // We could roll the loop, but that would make curve25519 twice as slow.
    i32 f0 = f[0]; i32 f1 = f[1]; i32 f2 = f[2]; i32 f3 = f[3]; i32 f4 = f[4];
    i32 f5 = f[5]; i32 f6 = f[6]; i32 f7 = f[7]; i32 f8 = f[8]; i32 f9 = f[9];
    i32 g0 = g[0]; i32 g1 = g[1]; i32 g2 = g[2]; i32 g3 = g[3]; i32 g4 = g[4];
    i32 g5 = g[5]; i32 g6 = g[6]; i32 g7 = g[7]; i32 g8 = g[8]; i32 g9 = g[9];
    i32 F1 = f1*2; i32 F3 = f3*2; i32 F5 = f5*2; i32 F7 = f7*2; i32 F9 = f9*2;
    i32 G1 = g1*19;  i32 G2 = g2*19;  i32 G3 = g3*19;
    i32 G4 = g4*19;  i32 G5 = g5*19;  i32 G6 = g6*19;
    i32 G7 = g7*19;  i32 G8 = g8*19;  i32 G9 = g9*19;

    i64 h0 = f0*(i64)g0 + F1*(i64)G9 + f2*(i64)G8 + F3*(i64)G7 + f4*(i64)G6
        +    F5*(i64)G5 + f6*(i64)G4 + F7*(i64)G3 + f8*(i64)G2 + F9*(i64)G1;
    i64 h1 = f0*(i64)g1 + f1*(i64)g0 + f2*(i64)G9 + f3*(i64)G8 + f4*(i64)G7
        +    f5*(i64)G6 + f6*(i64)G5 + f7*(i64)G4 + f8*(i64)G3 + f9*(i64)G2;
    i64 h2 = f0*(i64)g2 + F1*(i64)g1 + f2*(i64)g0 + F3*(i64)G9 + f4*(i64)G8
        +    F5*(i64)G7 + f6*(i64)G6 + F7*(i64)G5 + f8*(i64)G4 + F9*(i64)G3;
    i64 h3 = f0*(i64)g3 + f1*(i64)g2 + f2*(i64)g1 + f3*(i64)g0 + f4*(i64)G9
        +    f5*(i64)G8 + f6*(i64)G7 + f7*(i64)G6 + f8*(i64)G5 + f9*(i64)G4;
    i64 h4 = f0*(i64)g4 + F1*(i64)g3 + f2*(i64)g2 + F3*(i64)g1 + f4*(i64)g0
        +    F5*(i64)G9 + f6*(i64)G8 + F7*(i64)G7 + f8*(i64)G6 + F9*(i64)G5;
    i64 h5 = f0*(i64)g5 + f1*(i64)g4 + f2*(i64)g3 + f3*(i64)g2 + f4*(i64)g1
        +    f5*(i64)g0 + f6*(i64)G9 + f7*(i64)G8 + f8*(i64)G7 + f9*(i64)G6;
    i64 h6 = f0*(i64)g6 + F1*(i64)g5 + f2*(i64)g4 + F3*(i64)g3 + f4*(i64)g2
        +    F5*(i64)g1 + f6*(i64)g0 + F7*(i64)G9 + f8*(i64)G8 + F9*(i64)G7;
    i64 h7 = f0*(i64)g7 + f1*(i64)g6 + f2*(i64)g5 + f3*(i64)g4 + f4*(i64)g3
        +    f5*(i64)g2 + f6*(i64)g1 + f7*(i64)g0 + f8*(i64)G9 + f9*(i64)G8;
    i64 h8 = f0*(i64)g8 + F1*(i64)g7 + f2*(i64)g6 + F3*(i64)g5 + f4*(i64)g4
        +    F5*(i64)g3 + f6*(i64)g2 + F7*(i64)g1 + f8*(i64)g0 + F9*(i64)G9;
    i64 h9 = f0*(i64)g9 + f1*(i64)g8 + f2*(i64)g7 + f3*(i64)g6 + f4*(i64)g5
        +    f5*(i64)g4 + f6*(i64)g3 + f7*(i64)g2 + f8*(i64)g1 + f9*(i64)g0;

#define CARRY                                                             \
    i64 c0, c1, c2, c3, c4, c5, c6, c7, c8, c9;                           \
    c0 = (h0 + (i64) (1<<25)) >> 26; h1 += c0;      h0 -= c0 * (1 << 26); \
    c4 = (h4 + (i64) (1<<25)) >> 26; h5 += c4;      h4 -= c4 * (1 << 26); \
    c1 = (h1 + (i64) (1<<24)) >> 25; h2 += c1;      h1 -= c1 * (1 << 25); \
    c5 = (h5 + (i64) (1<<24)) >> 25; h6 += c5;      h5 -= c5 * (1 << 25); \
    c2 = (h2 + (i64) (1<<25)) >> 26; h3 += c2;      h2 -= c2 * (1 << 26); \
    c6 = (h6 + (i64) (1<<25)) >> 26; h7 += c6;      h6 -= c6 * (1 << 26); \
    c3 = (h3 + (i64) (1<<24)) >> 25; h4 += c3;      h3 -= c3 * (1 << 25); \
    c7 = (h7 + (i64) (1<<24)) >> 25; h8 += c7;      h7 -= c7 * (1 << 25); \
    c4 = (h4 + (i64) (1<<25)) >> 26; h5 += c4;      h4 -= c4 * (1 << 26); \
    c8 = (h8 + (i64) (1<<25)) >> 26; h9 += c8;      h8 -= c8 * (1 << 26); \
    c9 = (h9 + (i64) (1<<24)) >> 25; h0 += c9 * 19; h9 -= c9 * (1 << 25); \
    c0 = (h0 + (i64) (1<<25)) >> 26; h1 += c0;      h0 -= c0 * (1 << 26); \
    h[0] = h0;  h[1] = h1;  h[2] = h2;  h[3] = h3;  h[4] = h4;            \
    h[5] = h5;  h[6] = h6;  h[7] = h7;  h[8] = h8;  h[9] = h9;            \

    CARRY;
}

// we could use fe_mul() for this, but this is significantly faster
static void fe_sq(fe h, const fe f)
{
    i32 f0 = f[0]; i32 f1 = f[1]; i32 f2 = f[2]; i32 f3 = f[3]; i32 f4 = f[4];
    i32 f5 = f[5]; i32 f6 = f[6]; i32 f7 = f[7]; i32 f8 = f[8]; i32 f9 = f[9];
    i32 f0_2  = f0*2;   i32 f1_2  = f1*2;   i32 f2_2  = f2*2;   i32 f3_2 = f3*2;
    i32 f4_2  = f4*2;   i32 f5_2  = f5*2;   i32 f6_2  = f6*2;   i32 f7_2 = f7*2;
    i32 f5_38 = f5*38;  i32 f6_19 = f6*19;  i32 f7_38 = f7*38;
    i32 f8_19 = f8*19;  i32 f9_38 = f9*38;

    i64 h0 = f0  *(i64)f0    + f1_2*(i64)f9_38 + f2_2*(i64)f8_19
        +    f3_2*(i64)f7_38 + f4_2*(i64)f6_19 + f5  *(i64)f5_38;
    i64 h1 = f0_2*(i64)f1    + f2  *(i64)f9_38 + f3_2*(i64)f8_19
        +    f4  *(i64)f7_38 + f5_2*(i64)f6_19;
    i64 h2 = f0_2*(i64)f2    + f1_2*(i64)f1    + f3_2*(i64)f9_38
        +    f4_2*(i64)f8_19 + f5_2*(i64)f7_38 + f6  *(i64)f6_19;
    i64 h3 = f0_2*(i64)f3    + f1_2*(i64)f2    + f4  *(i64)f9_38
        +    f5_2*(i64)f8_19 + f6  *(i64)f7_38;
    i64 h4 = f0_2*(i64)f4    + f1_2*(i64)f3_2  + f2  *(i64)f2
        +    f5_2*(i64)f9_38 + f6_2*(i64)f8_19 + f7  *(i64)f7_38;
    i64 h5 = f0_2*(i64)f5    + f1_2*(i64)f4    + f2_2*(i64)f3
        +    f6  *(i64)f9_38 + f7_2*(i64)f8_19;
    i64 h6 = f0_2*(i64)f6    + f1_2*(i64)f5_2  + f2_2*(i64)f4
        +    f3_2*(i64)f3    + f7_2*(i64)f9_38 + f8  *(i64)f8_19;
    i64 h7 = f0_2*(i64)f7    + f1_2*(i64)f6    + f2_2*(i64)f5
        +    f3_2*(i64)f4    + f8  *(i64)f9_38;
    i64 h8 = f0_2*(i64)f8    + f1_2*(i64)f7_2  + f2_2*(i64)f6
        +    f3_2*(i64)f5_2  + f4  *(i64)f4    + f9  *(i64)f9_38;
    i64 h9 = f0_2*(i64)f9    + f1_2*(i64)f8    + f2_2*(i64)f7
        +    f3_2*(i64)f6    + f4  *(i64)f5_2;

    CARRY;
}

// This could be simplified, but it would be slower
static void fe_invert(fe out, const fe z)
{
    fe t0, t1, t2, t3;
    fe_sq(t0, z );
    fe_sq(t1, t0);
    fe_sq(t1, t1);
    fe_mul(t1,  z, t1);
    fe_mul(t0, t0, t1);
    fe_sq(t2, t0);                                fe_mul(t1 , t1, t2);
    fe_sq(t2, t1); FOR (i, 1,   5) fe_sq(t2, t2); fe_mul(t1 , t2, t1);
    fe_sq(t2, t1); FOR (i, 1,  10) fe_sq(t2, t2); fe_mul(t2 , t2, t1);
    fe_sq(t3, t2); FOR (i, 1,  20) fe_sq(t3, t3); fe_mul(t2 , t3, t2);
    fe_sq(t2, t2); FOR (i, 1,  10) fe_sq(t2, t2); fe_mul(t1 , t2, t1);
    fe_sq(t2, t1); FOR (i, 1,  50) fe_sq(t2, t2); fe_mul(t2 , t2, t1);
    fe_sq(t3, t2); FOR (i, 1, 100) fe_sq(t3, t3); fe_mul(t2 , t3, t2);
    fe_sq(t2, t2); FOR (i, 1,  50) fe_sq(t2, t2); fe_mul(t1 , t2, t1);
    fe_sq(t1, t1); FOR (i, 1,   5) fe_sq(t1, t1); fe_mul(out, t1, t0);
}

// This could be simplified, but it would be slower
void fe_pow22523(fe out, const fe z)
{
    fe t0, t1, t2;
    fe_sq(t0, z);
    fe_sq(t1,t0);                   fe_sq(t1, t1);  fe_mul(t1, z, t1);
    fe_mul(t0, t0, t1);
    fe_sq(t0, t0);                                  fe_mul(t0, t1, t0);
    fe_sq(t1, t0);  FOR (i, 1,   5) fe_sq(t1, t1);  fe_mul(t0, t1, t0);
    fe_sq(t1, t0);  FOR (i, 1,  10) fe_sq(t1, t1);  fe_mul(t1, t1, t0);
    fe_sq(t2, t1);  FOR (i, 1,  20) fe_sq(t2, t2);  fe_mul(t1, t2, t1);
    fe_sq(t1, t1);  FOR (i, 1,  10) fe_sq(t1, t1);  fe_mul(t0, t1, t0);
    fe_sq(t1, t0);  FOR (i, 1,  50) fe_sq(t1, t1);  fe_mul(t1, t1, t0);
    fe_sq(t2, t1);  FOR (i, 1, 100) fe_sq(t2, t2);  fe_mul(t1, t2, t1);
    fe_sq(t1, t1);  FOR (i, 1,  50) fe_sq(t1, t1);  fe_mul(t0, t1, t0);
    fe_sq(t0, t0);  FOR (i, 1,   2) fe_sq(t0, t0);  fe_mul(out, t0, z);
}

static void fe_tobytes(u8 s[32], const fe h)
{
    i32 t[10];
    FOR (i, 0, 10) {
        t[i] = h[i];
    }
    i32 q = (19 * t[9] + (((i32) 1) << 24)) >> 25;
    FOR (i, 0, 5) {
        q += t[2*i  ]; q >>= 26;
        q += t[2*i+1]; q >>= 25;
    }
    t[0] += 19 * q;

    i32 c0 = t[0] >> 26; t[1] += c0; t[0] -= c0 * (1 << 26);
    i32 c1 = t[1] >> 25; t[2] += c1; t[1] -= c1 * (1 << 25);
    i32 c2 = t[2] >> 26; t[3] += c2; t[2] -= c2 * (1 << 26);
    i32 c3 = t[3] >> 25; t[4] += c3; t[3] -= c3 * (1 << 25);
    i32 c4 = t[4] >> 26; t[5] += c4; t[4] -= c4 * (1 << 26);
    i32 c5 = t[5] >> 25; t[6] += c5; t[5] -= c5 * (1 << 25);
    i32 c6 = t[6] >> 26; t[7] += c6; t[6] -= c6 * (1 << 26);
    i32 c7 = t[7] >> 25; t[8] += c7; t[7] -= c7 * (1 << 25);
    i32 c8 = t[8] >> 26; t[9] += c8; t[8] -= c8 * (1 << 26);
    i32 c9 = t[9] >> 25;             t[9] -= c9 * (1 << 25);

    store32_le(s +  0, ((u32)t[0] >>  0) | ((u32)t[1] << 26));
    store32_le(s +  4, ((u32)t[1] >>  6) | ((u32)t[2] << 19));
    store32_le(s +  8, ((u32)t[2] >> 13) | ((u32)t[3] << 13));
    store32_le(s + 12, ((u32)t[3] >> 19) | ((u32)t[4] <<  6));
    store32_le(s + 16, ((u32)t[5] >>  0) | ((u32)t[6] << 25));
    store32_le(s + 20, ((u32)t[6] >>  7) | ((u32)t[7] << 19));
    store32_le(s + 24, ((u32)t[7] >> 13) | ((u32)t[8] << 12));
    store32_le(s + 28, ((u32)t[8] >> 20) | ((u32)t[9] <<  6));
}

//  Parity check.  Returns 0 if even, 1 if odd
static int fe_isnegative(const fe f)
{
    u8 s[32];
    fe_tobytes(s, f);
    return s[0] & 1;
}

static int fe_isnonzero(const fe f)
{
    u8 s[32];
    fe_tobytes(s, f);
    return crypto_zerocmp(s, 32);
}

///////////////
/// X-25519 /// Taken from Supercop's ref10 implementation.
///////////////

static void trim_scalar(u8 s[32])
{
    s[ 0] &= 248;
    s[31] &= 127;
    s[31] |= 64;
}

static void x25519_ladder(const fe x1, fe x2, fe z2, fe x3, fe z3,
                          const u8 scalar[32])
{
    // Montgomery ladder
    // In projective coordinates, to avoid divisons: x = X / Z
    // We don't care about the y coordinate, it's only 1 bit of information
    fe_1(x2);        fe_0(z2); // "zero" point
    fe_copy(x3, x1); fe_1(z3); // "one"  point
    int swap = 0;
    for (int pos = 254; pos >= 0; --pos) {
        // constant time conditional swap before ladder step
        int b = (scalar[pos / 8] >> (pos & 7)) & 1;
        swap ^= b; // xor trick avoids swapping at the end of the loop
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);
        swap = b;  // anticipates one last swap after the loop

        // Montgomery ladder step: replaces (P2, P3) by (P2*2, P2+P3)
        // with differential addition
        fe t0, t1;
        fe_sub(t0, x3, z3);  fe_sub(t1, x2, z2);    fe_add(x2, x2, z2);
        fe_add(z2, x3, z3);  fe_mul(z3, t0, x2);    fe_mul(z2, z2, t1);
        fe_sq (t0, t1    );  fe_sq (t1, x2    );    fe_add(x3, z3, z2);
        fe_sub(z2, z3, z2);  fe_mul(x2, t1, t0);    fe_sub(t1, t1, t0);
        fe_sq (z2, z2    );  fe_mul121666(z3, t1);  fe_sq (x3, x3    );
        fe_add(t0, t0, z3);  fe_mul(z3, x1, z2);    fe_mul(z2, t1, t0);
    }
    // last swap is necessary to compensate for the xor trick
    // Note: after this swap, P3 == P2 + P1.
    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);
}

int crypto_x25519(u8       shared_secret   [32],
                  const u8 your_secret_key [32],
                  const u8 their_public_key[32])
{
    // computes the scalar product
    fe x1;
    fe_frombytes(x1, their_public_key);

    // restrict the possible scalar values
    u8 e[32];
    FOR (i, 0, 32) {
        e[i] = your_secret_key[i];
    }
    trim_scalar(e);

    // computes the actual scalar product (the result is in x2 and z2)
    fe x2, z2, x3, z3;
    x25519_ladder(x1, x2, z2, x3, z3, e);

    // normalises the coordinates: x == X / Z
    fe_invert(z2, z2);
    fe_mul(x2, x2, z2);
    fe_tobytes(shared_secret, x2);

    // Returns -1 if the input is all zero
    // (happens with some malicious public keys)
    return -1 - crypto_zerocmp(shared_secret, 32);
}

void crypto_x25519_public_key(u8       public_key[32],
                              const u8 secret_key[32])
{
    static const u8 base_point[32] = {9};
    crypto_x25519(public_key, secret_key, base_point);
}


///////////////
/// Ed25519 ///
///////////////

// Point in a twisted Edwards curve,
// in extended projective coordinates.
// x = X/Z, y = Y/Z, T = XY/Z
typedef struct { fe X; fe Y; fe Z; fe T; } ge;

static void ge_from_xy(ge *p, const fe x, const fe y)
{
    FOR (i, 0, 10) {
        p->X[i] = x[i];
        p->Y[i] = y[i];
    }
    fe_1  (p->Z);
    fe_mul(p->T, x, y);
}

static void ge_tobytes(u8 s[32], const ge *h)
{
    fe recip, x, y;
    fe_invert(recip, h->Z);
    fe_mul(x, h->X, recip);
    fe_mul(y, h->Y, recip);
    fe_tobytes(s, y);
    s[31] ^= fe_isnegative(x) << 7;
}

// Variable time! s must not be secret!
static int ge_frombytes_neg(ge *h, const u8 s[32])
{
    static const fe d = {
        -10913610, 13857413, -15372611, 6949391, 114729,
        -8787816, -6275908, -3247719, -18696448, -12055116
    } ;
    static const fe sqrtm1 = {
        -32595792, -7943725, 9377950, 3500415, 12389472,
        -272473, -25146209, -2005654, 326686, 11406482
    } ;
    fe u, v, v3, vxx, check;
    fe_frombytes(h->Y, s);
    fe_1(h->Z);
    fe_sq(u, h->Y);            // y^2
    fe_mul(v, u, d);
    fe_sub(u, u, h->Z);        // u = y^2-1
    fe_add(v, v, h->Z);        // v = dy^2+1

    fe_sq(v3, v);
    fe_mul(v3, v3, v);         // v3 = v^3
    fe_sq(h->X, v3);
    fe_mul(h->X, h->X, v);
    fe_mul(h->X, h->X, u);     // x = uv^7

    fe_pow22523(h->X, h->X);   // x = (uv^7)^((q-5)/8)
    fe_mul(h->X, h->X, v3);
    fe_mul(h->X, h->X, u);     // x = uv^3(uv^7)^((q-5)/8)

    fe_sq(vxx, h->X);
    fe_mul(vxx, vxx, v);
    fe_sub(check, vxx, u);     // vx^2-u
    if (fe_isnonzero(check)) {
        fe_add(check, vxx, u); // vx^2+u
        if (fe_isnonzero(check)) return -1;
        fe_mul(h->X, h->X, sqrtm1);
    }

    if (fe_isnegative(h->X) == (s[31] >> 7)) {
        fe_neg(h->X, h->X);
    }
    fe_mul(h->T, h->X, h->Y);
    return 0;
}

static void ge_add(ge *s, const ge *p, const ge *q)
{
    static const fe D2 = { // - 2 * 121665 / 121666
        0x2b2f159, 0x1a6e509, 0x22add7a, 0x0d4141d, 0x0038052,
        0x0f3d130, 0x3407977, 0x19ce331, 0x1c56dff, 0x0901b67
    };
    fe a, b, c, d, e, f, g, h;
    //  A = (Y1-X1) * (Y2-X2)
    //  B = (Y1+X1) * (Y2+X2)
    fe_sub(a, p->Y, p->X);  fe_sub(h, q->Y, q->X);  fe_mul(a, a, h);
    fe_add(b, p->X, p->Y);  fe_add(h, q->X, q->Y);  fe_mul(b, b, h);
    fe_mul(c, p->T, q->T);  fe_mul(c, c, D2  );  //  C = T1 * k * T2
    fe_add(d, p->Z, p->Z);  fe_mul(d, d, q->Z);  //  D = Z1 * 2 * Z2
    fe_sub(e, b, a);     //  E  = B - A
    fe_sub(f, d, c);     //  F  = D - C
    fe_add(g, d, c);     //  G  = D + C
    fe_add(h, b, a);     //  H  = B + A
    fe_mul(s->X, e, f);  //  X3 = E * F
    fe_mul(s->Y, g, h);  //  Y3 = G * H
    fe_mul(s->Z, f, g);  //  Z3 = F * G
    fe_mul(s->T, e, h);  //  T3 = E * H
}

// Performing the scalar multiplication directly in Twisted Edwards
// space woud be simpler, but also slower.  So we do it in Montgomery
// space instead.  The sign of the Y coordinate however gets lost in
// translation, so we use a dirty trick to recover it.
static void ge_scalarmult(ge *p, const ge *q, const u8 scalar[32])
{
    // sqrt(-486664)
    static const fe K = { 54885894, 25242303, 55597453,  9067496, 51808079,
                          33312638, 25456129, 14121551, 54921728,  3972023 };

    // convert q to montgomery format
    fe x1, y1, z1, x2, z2, x3, z3, t1, t2, t3, t4;
    fe_sub(z1, q->Z, q->Y);  fe_mul(z1, z1, q->X);  fe_invert(z1, z1);
    fe_add(t1, q->Z, q->Y);
    fe_mul(x1, q->X, t1  );  fe_mul(x1, x1, z1);
    fe_mul(y1, q->Z, t1  );  fe_mul(y1, y1, z1);  fe_mul(y1, K, y1);
    fe_1(z1); // implied in the ladder, needed to convert back.

    // montgomery scalarmult
    x25519_ladder(x1, x2, z2, x3, z3, scalar);

    // Recover the y coordinate (Katsuyuki Okeya & Kouichi Sakurai, 2001)
    // Note the shameless reuse of x1: (x1, y1, z1) will correspond to
    // what was originally (x2, z2).
    fe_mul(t1, x1, z2);  // t1 = x1 * z2
    fe_add(t2, x2, t1);  // t2 = x2 + t1
    fe_sub(t3, x2, t1);  // t3 = x2 − t1
    fe_sq (t3, t3);      // t3 = t3^2
    fe_mul(t3, t3, x3);  // t3 = t3 * x3
    fe_mul973324(t1, z2);// t1 = 2a * z2
    fe_add(t2, t2, t1);  // t2 = t2 + t1
    fe_mul(t4, x1, x2);  // t4 = x1 * x2
    fe_add(t4, t4, z2);  // t4 = t4 + z2
    fe_mul(t2, t2, t4);  // t2 = t2 * t4
    fe_mul(t1, t1, z2);  // t1 = t1 * z2
    fe_sub(t2, t2, t1);  // t2 = t2 − t1
    fe_mul(t2, t2, z3);  // t2 = t2 * z3
    fe_add(t1, y1, y1);  // t1 = y1 + y1
    fe_mul(t1, t1, z2);  // t1 = t1 * z2
    fe_mul(t1, t1, z3);  // t1 = t1 * z3
    fe_mul(x1, t1, x2);  // x1 = t1 * x2
    fe_sub(y1, t2, t3);  // y1 = t2 − t3
    fe_mul(z1, t1, z2);  // z1 = t1 * z2

    // convert back to twisted edwards
    fe_sub(t1  , x1, z1);
    fe_add(t2  , x1, z1);
    fe_mul(x1  , K , x1);
    fe_mul(p->X, x1, t2);
    fe_mul(p->Y, y1, t1);
    fe_mul(p->Z, y1, t2);
    fe_mul(p->T, x1, t1);
}

static void ge_scalarmult_base(ge *p, const u8 scalar[32])
{
    // Calls the general ge_scalarmult() with the base point.
    // Other implementations use a precomputed table, but it
    // takes way too much code.
    static const fe X = {
        0x325d51a, 0x18b5823, 0x0f6592a, 0x104a92d, 0x1a4b31d,
        0x1d6dc5c, 0x27118fe, 0x07fd814, 0x13cd6e5, 0x085a4db};
    static const fe Y = {
        0x2666658, 0x1999999, 0x0cccccc, 0x1333333, 0x1999999,
        0x0666666, 0x3333333, 0x0cccccc, 0x2666666, 0x1999999};
    ge base_point;
    ge_from_xy(&base_point, X, Y);
    ge_scalarmult(p, &base_point, scalar);
}

static void modL(u8 *r, i64 x[64])
{
    static const  u64 L[32] = { 0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
                                0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10 };
    for (unsigned i = 63; i >= 32; i--) {
        i64 carry = 0;
        FOR (j, i-32, i-12) {
            x[j] += carry - 16 * x[i] * L[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry * (1 << 8);
        }
        x[i-12] += carry;
        x[i] = 0;
    }
    i64 carry = 0;
    FOR(i, 0, 32) {
        x[i] += carry - (x[31] >> 4) * L[i];
        carry = x[i] >> 8;
        x[i] &= 255;
    }
    FOR(i, 0, 32) {
        x[i] -= carry * L[i];
    }
    FOR(i, 0, 32) {
        x[i+1] += x[i] >> 8;
        r[i  ]  = x[i] & 255;
    }
}

static void reduce(u8 r[64])
{
    i64 x[64];
    FOR(i, 0, 64) {
        x[i] = (u64) r[i];
        r[i] = 0;
    }
    modL(r, x);
}

// hashes R || A || M, reduces it modulo L
static void hash_ram(u8 k[64], const u8 R[32], const u8 A[32],
                     const u8 *M, size_t M_size)
{
    HASH_CTX ctx;
    HASH_INIT  (&ctx);
    HASH_UPDATE(&ctx, R , 32    );
    HASH_UPDATE(&ctx, A , 32    );
    HASH_UPDATE(&ctx, M , M_size);
    HASH_FINAL (&ctx, k);
    reduce(k);
}

void crypto_sign_public_key(u8       public_key[32],
                            const u8 secret_key[32])
{
    u8 a[64];
    HASH(a, secret_key, 32);
    trim_scalar(a);
    ge A;
    ge_scalarmult_base(&A, a);
    ge_tobytes(public_key, &A);
}

void crypto_sign(u8        signature[64],
                 const u8  secret_key[32],
                 const u8  public_key[32],
                 const u8 *message, size_t message_size)
{
    u8 a[64], *prefix = a + 32;
    HASH(a, secret_key, 32);
    trim_scalar(a);

    u8 pk_buf[32];
    const u8 *pk = public_key;
    if (public_key == 0) {
        crypto_sign_public_key(pk_buf, secret_key);
        pk = pk_buf;
    }

    // Constructs the "random" nonce from the secret key and message.
    // An actual random number would work just fine, and would save us
    // the trouble of hashing the message twice.  If we did that
    // however, the user could fuck it up and reuse the nonce.
    u8 r[64];
    HASH_CTX ctx;
    HASH_INIT  (&ctx);
    HASH_UPDATE(&ctx, prefix , 32          );
    HASH_UPDATE(&ctx, message, message_size);
    HASH_FINAL (&ctx, r);
    reduce(r);

    // first half of the signature = "random" nonce times basepoint
    ge R;
    ge_scalarmult_base(&R, r);
    ge_tobytes(signature, &R);

    u8 h_ram[64];
    hash_ram(h_ram, signature, pk, message, message_size);

    i64 s[64]; // s = r + h_ram * a
    FOR(i,  0, 32) { s[i] = (u64) r[i]; }
    FOR(i, 32, 64) { s[i] = 0;          }
    FOR(i,  0, 32) {
        FOR(j, 0, 32) {
            s[i+j] += h_ram[i] * (u64) a[j];
        }
    }
    modL(signature + 32, s);  // second half of the signature = s
}

int crypto_check(const u8  signature[64],
                 const u8  public_key[32],
                 const u8 *message,  size_t message_size)
{
    ge A, p, sB, diff;
    u8 h_ram[64], R_check[32];
    if (ge_frombytes_neg(&A, public_key)) {       // -A
        return -1;
    }
    hash_ram(h_ram, signature, public_key, message, message_size);
    ge_scalarmult(&p, &A, h_ram);                 // p    = -A*h_ram
    ge_scalarmult_base(&sB, signature + 32);
    ge_add(&diff, &p, &sB);                       // diff = s - A*h_ram
    ge_tobytes(R_check, &diff);
    return crypto_memcmp(signature, R_check, 32); // R == s - A*h_ram ? OK : fail
}








// ---------------------------------------------------------------------
// lua binding


#include <stdlib.h>
#include <assert.h>

#include "lua.h"
#include "lauxlib.h"

#define LERR(msg) return luaL_error(L, msg)



//----------------------------------------------------------------------
// curve25519 functions

int ll_ec25519_public_key(lua_State *L) {
	// return the public key associated to a secret key
	// lua api:  x25519_public_key(sk) return pk
	// sk: a secret key (can be any random value)
	// pk: the matching public key
	size_t skln;
	unsigned char pk[32];
	const char *sk = luaL_checklstring(L,1,&skln); // secret key
	if (skln != 32) LERR("bad sk size");
	crypto_x25519_public_key(pk, sk);
	lua_pushlstring (L, pk, 32); 
	return 1;
}//lz_x25519_public_key()

int ll_ec25519_shared_secret(lua_State *L) {
	// DH key exchange: compute a shared secret
	// lua api:  lock_key(sk, pk) => k
	// (!! reversed order compared to nacl box_beforenm() !!)
	// sk: "your" secret key
	// pk: "their" public key
	// return the session key k
	// --Note: In order to make the session key more uniformly distributed,
	// the shared secret generated by x25519 is hashed by blake2b.
	// (blake2b plays here the same role as HSalsa20 in nacl box_beforenm())
	size_t pkln, skln;
	unsigned char k[32];
	const char *sk = luaL_checklstring(L,1,&skln); // your secret key
	const char *pk = luaL_checklstring(L,2,&pkln); // their public key
	if (pkln != 32) LERR("bad pk size");
	if (skln != 32) LERR("bad sk size");

    unsigned char shared_secret[32];
	/// replace crypto_chacha20_H with crypto_blake2b_general
    int status = crypto_x25519(shared_secret, sk, pk);
	
	
    //~ crypto_blake2b_general(k, 32, 0, 0, shared_secret, 32);	
	//~ lua_pushlstring(L, k, 32); 
	
	lua_pushlstring(L, shared_secret, 32); 
	return 1;   
	
}// ll_x25519_shared_secret()


//----------------------------------------------------------------------
// ed25519 signature functions

int ll_ed25519_public_key(lua_State *L) {
	// return the public key associated to an ed25519 secret key
	// lua api:  sign_public_key(sk) return pk
	// sk: a secret key (can be any random value)
	// pk: the matching public key
	size_t skln;
	unsigned char pk[32];
	const char *sk = luaL_checklstring(L,1,&skln); // secret key
	if (skln != 32) LERR("bad sk size");
	crypto_sign_public_key(pk, sk);
	lua_pushlstring (L, pk, 32); 
	return 1;
}//ll_ed25519_public_key()

int ll_ed25519_sign(lua_State *L) {
	// sign a text with a secret key
	// Lua API: sign(sk, pk, m) return sig
	//  sk: key string (32 bytes)
	//  pk: associated public key string (32 bytes)
	//	m: message to sign (string)
	//  return signature (a 64-byte string)
	size_t mln, skln, pkln;
	const char *sk = luaL_checklstring(L,1,&skln);
	const char *pk = luaL_checklstring(L,2,&pkln);
	const char *m = luaL_checklstring(L,3,&mln);	
	if (skln != 32) LERR("bad key size");
	if (pkln != 32) LERR("bad pub key size");
	unsigned char sig[64];
	crypto_sign(sig, sk, pk, m, mln);
	lua_pushlstring (L, sig, 64); 
	return 1;
} // ll_ed25519_sign()

int ll_ed25519_check(lua_State *L) {
	// check a text signature with a public key
	// Lua API: check(sig, pk, m) return boolean
	//  sig: signature string (64 bytes)
	//  pk: public key string (32 bytes)
	//	m: message to verify (string)
	//  return true if the signature match, or false
	int r;
	size_t mln, pkln, sigln;
	const char *sig = luaL_checklstring(L,1,&sigln);
	const char *pk = luaL_checklstring(L,2,&pkln);
	const char *m = luaL_checklstring(L,3,&mln);	
	if (sigln != 64) LERR("bad signature size");
	if (pkln != 32) LERR("bad key size");
	r = crypto_check(sig, pk, m, mln);
	// r == 0 if the signature matches
	lua_pushboolean (L, (r == 0)); 
	return 1;
} // ll_ed25519_check()



