// Copyright (c) 2018 Phil Leblanc  -- see LICENSE file
// ---------------------------------------------------------------------
// lzf - a Lua binding to Marc Alexander Lehmann LZF library

//-- The LZF code included here is copyrighted and licensed under 
//-- the following terms:

/*
 * Copyright (c) 2000-2008 Marc Alexander Lehmann <schmorp@schmorp.de>
 * 
 * Redistribution and use in source and binary forms, with or without modifica-
 * tion, are permitted provided that the following conditions are met:
 * 
 *   1.  Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 * 
 *   2.  Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MER-
 * CHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO
 * EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPE-
 * CIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTH-
 * ERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Alternatively, the contents of this file may be used under the terms of
 * the GNU General Public License ("GPL") version 2 or any later version,
 * in which case the provisions of the GPL are applicable instead of
 * the above. If you wish to allow the use of your version of this file
 * only under the terms of the GPL and not to allow others to use your
 * version of this file under the BSD license, indicate your decision
 * by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL. If you do not delete the
 * provisions above, a recipient may use your version of this file under
 * either the BSD or the GPL.
 */

//-- content of original file lzfP.h

/*
 * Size of hashtable is (1 << HLOG) * sizeof (char *)
 * decompression is independent of the hash table size
 * the difference between 15 and 14 is very small
 * for small blocks (and 14 is usually a bit faster).
 * For a low-memory/faster configuration, use HLOG == 13;
 * For best compression, use 15 or 16 (or more, up to 22).
 */
#ifndef HLOG
# define HLOG 16
#endif

/*
 * Sacrifice very little compression quality in favour of compression speed.
 * This gives almost the same compression as the default code, and is
 * (very roughly) 15% faster. This is the preferred mode of operation.
 */
#ifndef VERY_FAST
# define VERY_FAST 1
#endif

/*
 * Sacrifice some more compression quality in favour of compression speed.
 * (roughly 1-2% worse compression for large blocks and
 * 9-10% for small, redundant, blocks and >>20% better speed in both cases)
 * In short: when in need for speed, enable this for binary data,
 * possibly disable this for text data.
 */
#ifndef ULTRA_FAST
# define ULTRA_FAST 0
#endif

/*
 * Unconditionally aligning does not cost very much, so do it if unsure
 */
#ifndef STRICT_ALIGN
# define STRICT_ALIGN !(defined(__i386) || defined (__amd64))
#endif

/*
 * You may choose to pre-set the hash table (might be faster on some
 * modern cpus and large (>>64k) blocks, and also makes compression
 * deterministic/repeatable when the configuration otherwise is the same).
 */
#ifndef INIT_HTAB
# define INIT_HTAB 0
#endif

/*
 * Avoid assigning values to errno variable? for some embedding purposes
 * (linux kernel for example), this is necessary. NOTE: this breaks
 * the documentation in lzf.h. Avoiding errno has no speed impact.
 */
#ifndef AVOID_ERRNO
# define AVOID_ERRNO 0
#endif

/*
 * Whether to pass the LZF_STATE variable as argument, or allocate it
 * on the stack. For small-stack environments, define this to 1.
 * NOTE: this breaks the prototype in lzf.h.
 */
#ifndef LZF_STATE_ARG
# define LZF_STATE_ARG 0
#endif

/*
 * Whether to add extra checks for input validity in lzf_decompress
 * and return EINVAL if the input stream has been corrupted. This
 * only shields against overflowing the input buffer and will not
 * detect most corrupted streams.
 * This check is not normally noticeable on modern hardware
 * (<1% slowdown), but might slow down older cpus considerably.
 */
#ifndef CHECK_INPUT
# define CHECK_INPUT 1
#endif

/*
 * Whether to store pointers or offsets inside the hash table. On
 * 64 bit architetcures, pointers take up twice as much space,
 * and might also be slower. Default is to autodetect.
 */
/*#define LZF_USER_OFFSETS autodetect */

/*****************************************************************************/
/* nothing should be changed below */

#ifdef __cplusplus
# include <cstring>
# include <climits>
using namespace std;
#else
# include <string.h>
# include <limits.h>
#endif

#ifndef LZF_USE_OFFSETS
# if defined (WIN32)
#  define LZF_USE_OFFSETS defined(_M_X64)
# else
#  if __cplusplus > 199711L
#   include <cstdint>
#  else
#   include <stdint.h>
#  endif
#  define LZF_USE_OFFSETS (UINTPTR_MAX > 0xffffffffU)
# endif
#endif

typedef unsigned char u8;

#if LZF_USE_OFFSETS
# define LZF_HSLOT_BIAS ((const u8 *)in_data)
  typedef unsigned int LZF_HSLOT;
#else
# define LZF_HSLOT_BIAS 0
  typedef const u8 *LZF_HSLOT;
#endif

typedef LZF_HSLOT LZF_STATE[1 << (HLOG)];

#if !STRICT_ALIGN
/* for unaligned accesses we need a 16 bit datatype. */
# if USHRT_MAX == 65535
    typedef unsigned short u16;
# elif UINT_MAX == 65535
    typedef unsigned int u16;
# else
#  undef STRICT_ALIGN
#  define STRICT_ALIGN 1
# endif
#endif

#if ULTRA_FAST
# undef VERY_FAST
#endif


//-- content of original file lzf_c.c

#define HSIZE (1 << (HLOG))

/*
 * don't play with this unless you benchmark!
 * the data format is not dependent on the hash function.
 * the hash function might seem strange, just believe me,
 * it works ;)
 */
#ifndef FRST
# define FRST(p) (((p[0]) << 8) | p[1])
# define NEXT(v,p) (((v) << 8) | p[2])
# if ULTRA_FAST
#  define IDX(h) ((( h             >> (3*8 - HLOG)) - h  ) & (HSIZE - 1))
# elif VERY_FAST
#  define IDX(h) ((( h             >> (3*8 - HLOG)) - h*5) & (HSIZE - 1))
# else
#  define IDX(h) ((((h ^ (h << 5)) >> (3*8 - HLOG)) - h*5) & (HSIZE - 1))
# endif
#endif
/*
 * IDX works because it is very similar to a multiplicative hash, e.g.
 * ((h * 57321 >> (3*8 - HLOG)) & (HSIZE - 1))
 * the latter is also quite fast on newer CPUs, and compresses similarly.
 *
 * the next one is also quite good, albeit slow ;)
 * (int)(cos(h & 0xffffff) * 1e6)
 */

#if 0
/* original lzv-like hash function, much worse and thus slower */
# define FRST(p) (p[0] << 5) ^ p[1]
# define NEXT(v,p) ((v) << 5) ^ p[2]
# define IDX(h) ((h) & (HSIZE - 1))
#endif

#define        MAX_LIT        (1 <<  5)
#define        MAX_OFF        (1 << 13)
#define        MAX_REF        ((1 << 8) + (1 << 3))

#if __GNUC__ >= 3
# define expect(expr,value)         __builtin_expect ((expr),(value))
# define inline                     inline
#else
# define expect(expr,value)         (expr)
# define inline                     static
#endif

#define expect_false(expr) expect ((expr) != 0, 0)
#define expect_true(expr)  expect ((expr) != 0, 1)

/*
 * compressed format
 *
 * 000LLLLL <L+1>    ; literal, L+1=1..33 octets
 * LLLooooo oooooooo ; backref L+1=1..7 octets, o+1=1..4096 offset
 * 111ooooo LLLLLLLL oooooooo ; backref L+8 octets, o+1=1..4096 offset
 *
 */

unsigned int
lzf_compress (const void *const in_data, unsigned int in_len,
	      void *out_data, unsigned int out_len
#if LZF_STATE_ARG
              , LZF_STATE htab
#endif
              )
{
#if !LZF_STATE_ARG
  LZF_STATE htab;
#endif
  const u8 *ip = (const u8 *)in_data;
        u8 *op = (u8 *)out_data;
  const u8 *in_end  = ip + in_len;
        u8 *out_end = op + out_len;
  const u8 *ref;

  /* off requires a type wide enough to hold a general pointer difference.
   * ISO C doesn't have that (size_t might not be enough and ptrdiff_t only
   * works for differences within a single object). We also assume that no
   * no bit pattern traps. Since the only platform that is both non-POSIX
   * and fails to support both assumptions is windows 64 bit, we make a
   * special workaround for it.
   */
#if defined (WIN32) && defined (_M_X64)
  unsigned __int64 off; /* workaround for missing POSIX compliance */
#else
  unsigned long off;
#endif
  unsigned int hval;
  int lit;

  if (!in_len || !out_len)
    return 0;

#if INIT_HTAB
  memset (htab, 0, sizeof (htab));
#endif

  lit = 0; op++; /* start run */

  hval = FRST (ip);
  while (ip < in_end - 2)
    {
      LZF_HSLOT *hslot;

      hval = NEXT (hval, ip);
      hslot = htab + IDX (hval);
      ref = *hslot + LZF_HSLOT_BIAS; *hslot = ip - LZF_HSLOT_BIAS;

      if (1
#if INIT_HTAB
          && ref < ip /* the next test will actually take care of this, but this is faster */
#endif
          && (off = ip - ref - 1) < MAX_OFF
          && ref > (u8 *)in_data
          && ref[2] == ip[2]
#if STRICT_ALIGN
          && ((ref[1] << 8) | ref[0]) == ((ip[1] << 8) | ip[0])
#else
          && *(u16 *)ref == *(u16 *)ip
#endif
        )
        {
          /* match found at *ref++ */
          unsigned int len = 2;
          unsigned int maxlen = in_end - ip - len;
          maxlen = maxlen > MAX_REF ? MAX_REF : maxlen;

          if (expect_false (op + 3 + 1 >= out_end)) /* first a faster conservative test */
            if (op - !lit + 3 + 1 >= out_end) /* second the exact but rare test */
              return 0;

          op [- lit - 1] = lit - 1; /* stop run */
          op -= !lit; /* undo run if length is zero */

          for (;;)
            {
              if (expect_true (maxlen > 16))
                {
                  len++; if (ref [len] != ip [len]) break;
                  len++; if (ref [len] != ip [len]) break;
                  len++; if (ref [len] != ip [len]) break;
                  len++; if (ref [len] != ip [len]) break;

                  len++; if (ref [len] != ip [len]) break;
                  len++; if (ref [len] != ip [len]) break;
                  len++; if (ref [len] != ip [len]) break;
                  len++; if (ref [len] != ip [len]) break;

                  len++; if (ref [len] != ip [len]) break;
                  len++; if (ref [len] != ip [len]) break;
                  len++; if (ref [len] != ip [len]) break;
                  len++; if (ref [len] != ip [len]) break;

                  len++; if (ref [len] != ip [len]) break;
                  len++; if (ref [len] != ip [len]) break;
                  len++; if (ref [len] != ip [len]) break;
                  len++; if (ref [len] != ip [len]) break;
                }

              do
                len++;
              while (len < maxlen && ref[len] == ip[len]);

              break;
            }

          len -= 2; /* len is now #octets - 1 */
          ip++;

          if (len < 7)
            {
              *op++ = (off >> 8) + (len << 5);
            }
          else
            {
              *op++ = (off >> 8) + (  7 << 5);
              *op++ = len - 7;
            }

          *op++ = off;

          lit = 0; op++; /* start run */

          ip += len + 1;

          if (expect_false (ip >= in_end - 2))
            break;

#if ULTRA_FAST || VERY_FAST
          --ip;
# if VERY_FAST && !ULTRA_FAST
          --ip;
# endif
          hval = FRST (ip);

          hval = NEXT (hval, ip);
          htab[IDX (hval)] = ip - LZF_HSLOT_BIAS;
          ip++;

# if VERY_FAST && !ULTRA_FAST
          hval = NEXT (hval, ip);
          htab[IDX (hval)] = ip - LZF_HSLOT_BIAS;
          ip++;
# endif
#else
          ip -= len + 1;

          do
            {
              hval = NEXT (hval, ip);
              htab[IDX (hval)] = ip - LZF_HSLOT_BIAS;
              ip++;
            }
          while (len--);
#endif
        }
      else
        {
          /* one more literal byte we must copy */
          if (expect_false (op >= out_end))
            return 0;

          lit++; *op++ = *ip++;

          if (expect_false (lit == MAX_LIT))
            {
              op [- lit - 1] = lit - 1; /* stop run */
              lit = 0; op++; /* start run */
            }
        }
    }

  if (op + 3 > out_end) /* at most 3 bytes can be missing here */
    return 0;

  while (ip < in_end)
    {
      lit++; *op++ = *ip++;

      if (expect_false (lit == MAX_LIT))
        {
          op [- lit - 1] = lit - 1; /* stop run */
          lit = 0; op++; /* start run */
        }
    }

  op [- lit - 1] = lit - 1; /* end run */
  op -= !lit; /* undo run if length is zero */

  return op - (u8 *)out_data;
}

//-- content of original file lzf_d.c


#if AVOID_ERRNO
# define SET_ERRNO(n)
#else
# include <errno.h>
# define SET_ERRNO(n) errno = (n)
#endif

#if USE_REP_MOVSB /* small win on amd, big loss on intel */
#if (__i386 || __amd64) && __GNUC__ >= 3
# define lzf_movsb(dst, src, len)                \
   asm ("rep movsb"                              \
        : "=D" (dst), "=S" (src), "=c" (len)     \
        :  "0" (dst),  "1" (src),  "2" (len));
#endif
#endif

unsigned int 
lzf_decompress (const void *const in_data,  unsigned int in_len,
                void             *out_data, unsigned int out_len)
{
  u8 const *ip = (const u8 *)in_data;
  u8       *op = (u8 *)out_data;
  u8 const *const in_end  = ip + in_len;
  u8       *const out_end = op + out_len;

  do
    {
      unsigned int ctrl = *ip++;

      if (ctrl < (1 << 5)) /* literal run */
        {
          ctrl++;

          if (op + ctrl > out_end)
            {
              SET_ERRNO (E2BIG);
              return 0;
            }

#if CHECK_INPUT
          if (ip + ctrl > in_end)
            {
              SET_ERRNO (EINVAL);
              return 0;
            }
#endif

#ifdef lzf_movsb
          lzf_movsb (op, ip, ctrl);
#else
          switch (ctrl)
            {
              case 32: *op++ = *ip++; case 31: *op++ = *ip++; case 30: *op++ = *ip++; case 29: *op++ = *ip++;
              case 28: *op++ = *ip++; case 27: *op++ = *ip++; case 26: *op++ = *ip++; case 25: *op++ = *ip++;
              case 24: *op++ = *ip++; case 23: *op++ = *ip++; case 22: *op++ = *ip++; case 21: *op++ = *ip++;
              case 20: *op++ = *ip++; case 19: *op++ = *ip++; case 18: *op++ = *ip++; case 17: *op++ = *ip++;
              case 16: *op++ = *ip++; case 15: *op++ = *ip++; case 14: *op++ = *ip++; case 13: *op++ = *ip++;
              case 12: *op++ = *ip++; case 11: *op++ = *ip++; case 10: *op++ = *ip++; case  9: *op++ = *ip++;
              case  8: *op++ = *ip++; case  7: *op++ = *ip++; case  6: *op++ = *ip++; case  5: *op++ = *ip++;
              case  4: *op++ = *ip++; case  3: *op++ = *ip++; case  2: *op++ = *ip++; case  1: *op++ = *ip++;
            }
#endif
        }
      else /* back reference */
        {
          unsigned int len = ctrl >> 5;

          u8 *ref = op - ((ctrl & 0x1f) << 8) - 1;

#if CHECK_INPUT
          if (ip >= in_end)
            {
              SET_ERRNO (EINVAL);
              return 0;
            }
#endif
          if (len == 7)
            {
              len += *ip++;
#if CHECK_INPUT
              if (ip >= in_end)
                {
                  SET_ERRNO (EINVAL);
                  return 0;
                }
#endif
            }

          ref -= *ip++;

          if (op + len + 2 > out_end)
            {
              SET_ERRNO (E2BIG);
              return 0;
            }

          if (ref < (u8 *)out_data)
            {
              SET_ERRNO (EINVAL);
              return 0;
            }

#ifdef lzf_movsb
          len += 2;
          lzf_movsb (op, ref, len);
#else
          switch (len)
            {
              default:
                len += 2;

                if (op >= ref + len)
                  {
                    /* disjunct areas */
                    memcpy (op, ref, len);
                    op += len;
                  }
                else
                  {
                    /* overlapping, use octte by octte copying */
                    do
                      *op++ = *ref++;
                    while (--len);
                  }

                break;

              case 9: *op++ = *ref++;
              case 8: *op++ = *ref++;
              case 7: *op++ = *ref++;
              case 6: *op++ = *ref++;
              case 5: *op++ = *ref++;
              case 4: *op++ = *ref++;
              case 3: *op++ = *ref++;
              case 2: *op++ = *ref++;
              case 1: *op++ = *ref++;
              case 0: *op++ = *ref++; /* two octets more */
                      *op++ = *ref++;
            }
#endif
        }
    }
  while (ip < in_end);

  return op - (u8 *)out_data;
}

//=========================================================
// lua binding

#include <stdlib.h>

#include "lua.h"
#include "lauxlib.h"


int ll_lzf(lua_State *L) {
    size_t sln, bufln; 
    unsigned int dstln;
    const char *s = luaL_checklstring (L, 1, &sln);
	// special case for empty string:  lzf_compress cannot handle it.
	// => return an empty string
	if (sln == 0) {
		lua_pushlstring (L, s, sln); 
		return 1;  		
	}
    const size_t headln = sizeof(sln); 
    bufln =  sln + (sln/5) + 20 ;
    char *buf = malloc(bufln); 
    //store compressed data at dstbuf
    //1st headln bytes in buf used to store uncompressed length
    char *dstbuf = buf + headln; 
    *((size_t *) buf) = sln;  //!!ENDIANNESS DEPENDANT!!
	dstln = bufln - headln ; //dstln must be set to buf ln upon entry
    unsigned int r = lzf_compress(s, sln, dstbuf, dstln); 
    if (r == 0) {
		free(buf); 
        lua_pushnil (L);
		lua_pushfstring (L, "luazen: lzf compress error (E2BIG) %d", r);
        return 2;         
    }
    lua_pushlstring (L, buf, headln + r); 
    free(buf);
    return 1;    
}

int ll_unlzf(lua_State *L) {
    size_t sln, bufln; 
    unsigned int dstln;
    const char *s = luaL_checklstring (L, 1, &sln);
	// special case for empty string:  return an empty string
	if (sln == 0) {
		lua_pushlstring (L, s, sln); 
		return 1;  		
	}	
    const size_t headln = sizeof(sln); 
    // 1st headln bytes i s are uncompressed data length
    bufln = (*((size_t *) s));  // !!ENDIANNESS DEPENDANT!!
	bufln += 20 ;  // ...just in case some room needed for null at end...
    char *buf = malloc(bufln); 
    const char *src = s + headln; 
	dstln = bufln - headln ; //dstln must be set to buf ln upon entry
    unsigned int r = lzf_decompress(src, sln - headln, buf, dstln); 
    if (r == 0) {
		free(buf);
        lua_pushnil (L);
		lua_pushfstring (L, "luazen: lzf decompress error (E2BIG or EINVAL) %d", r);
        return 2;         
    }
    lua_pushlstring (L, buf, r); 
    free(buf);
    return 1;    
}

