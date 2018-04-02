// Copyright (c) 2018 Phil Leblanc  -- see LICENSE file
// ---------------------------------------------------------------------
// blz - a Lua binding to Joergen Ibsen BriefLZ library

//-- The  BriefLZ code included here is copyrighted and licensed under 
//-- the following terms:

/*
 * BriefLZ - small fast Lempel-Ziv
 *
 * C safe depacker
 *
 * Copyright (c) 2002-2016 Joergen Ibsen
 *
 * This software is provided 'as-is', without any express or implied
 * warranty. In no event will the authors be held liable for any damages
 * arising from the use of this software.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, subject to the following restrictions:
 *
 *   1. The origin of this software must not be misrepresented; you must
 *      not claim that you wrote the original software. If you use this
 *      software in a product, an acknowledgment in the product
 *      documentation would be appreciated but is not required.
 *
 *   2. Altered source versions must be plainly marked as such, and must
 *      not be misrepresented as being the original software.
 *
 *   3. This notice may not be removed or altered from any source
 *      distribution.
 */

//-- content of original file brieflz.h

#define BLZ_VER_MAJOR 1        /**< Major version number */
#define BLZ_VER_MINOR 1        /**< Minor version number */
#define BLZ_VER_PATCH 0        /**< Patch version number */
#define BLZ_VER_STRING "1.1.0" /**< Version number as a string */

#ifdef BLZ_DLL
#  if defined(_WIN32) || defined(__CYGWIN__)
#    ifdef BLZ_DLL_EXPORTS
#      define BLZ_API __declspec(dllexport)
#    else
#      define BLZ_API __declspec(dllimport)
#    endif
#    define BLZ_LOCAL
#  else
#    if __GNUC__ >= 4
#      define BLZ_API __attribute__ ((visibility ("default")))
#      define BLZ_LOCAL __attribute__ ((visibility ("hidden")))
#    else
#      define BLZ_API
#      define BLZ_LOCAL
#    endif
#  endif
#else
#  define BLZ_API
#  define BLZ_LOCAL
#endif

/**
 * Return value on error.
 *
 * @see blz_depack_safe
 */
#ifndef BLZ_ERROR
#  define BLZ_ERROR ((unsigned long) (-1))
#endif

/**
 * Get required size of `workmem` buffer.
 *
 * @see blz_pack
 *
 * @param src_size number of bytes to compress
 * @return required size in bytes of `workmem` buffer
 */
BLZ_API unsigned long
blz_workmem_size(unsigned long src_size);

/**
 * Get bound on compressed data size.
 *
 * @see blz_pack
 *
 * @param src_size number of bytes to compress
 * @return maximum size of compressed data
 */
BLZ_API unsigned long
blz_max_packed_size(unsigned long src_size);

/**
 * Compress `src_size` bytes of data from `src` to `dst`.
 *
 * @param src pointer to data
 * @param dst pointer to where to place compressed data
 * @param src_size number of bytes to compress
 * @param workmem pointer to memory for temporary use
 * @return size of compressed data
 */
BLZ_API unsigned long
blz_pack(const void *src, void *dst, unsigned long src_size, void *workmem);

/**
 * Decompress `depacked_size` bytes of data from `src` to `dst`.
 *
 * @param src pointer to compressed data
 * @param dst pointer to where to place decompressed data
 * @param depacked_size size of decompressed data
 * @return size of decompressed data
 */
BLZ_API unsigned long
blz_depack(const void *src, void *dst, unsigned long depacked_size);

/**
 * Decompress `depacked_size` bytes of data from `src` to `dst`.
 *
 * Reads at most `src_size` bytes from `src`.
 * Writes at most `depacked_size` bytes to `dst`.
 *
 * @param src pointer to compressed data
 * @param src_size size of compressed data
 * @param dst pointer to where to place decompressed data
 * @param depacked_size size of decompressed data
 * @return size of decompressed data, `BLZ_ERROR` on error
 */
BLZ_API unsigned long
blz_depack_safe(const void *src, unsigned long src_size,
                void *dst, unsigned long depacked_size);


//----------------------------------------------------------------------
//-- content of original file brieflz.c

#ifndef BLZ_HASH_BITS
#  define BLZ_HASH_BITS 17
#endif

#define LOOKUP_SIZE (1UL << BLZ_HASH_BITS)

#define WORKMEM_SIZE (LOOKUP_SIZE * sizeof(const unsigned char *))

/* Internal data structure */
struct blz_state {
	const unsigned char *src;
	unsigned char *dst;
	unsigned long src_avail;  /// added to use the same blz_state
	unsigned long dst_avail;  /// struc for compress and uncompress
	unsigned char *tagpos;
	unsigned int tag;
	unsigned int bits_left;
};

static void
blz_putbit(struct blz_state *bs, unsigned int bit)
{
	/* Check if tag is full */
	if (!bs->bits_left--) {
		/* store tag */
		bs->tagpos[0] = bs->tag & 0x00FF;
		bs->tagpos[1] = (bs->tag >> 8) & 0x00FF;

		/* init next tag */
		bs->tagpos = bs->dst;
		bs->dst += 2;
		bs->bits_left = 15;
	}

	/* Shift bit into tag */
	bs->tag = (bs->tag << 1) + bit;
}

static void
blz_putgamma(struct blz_state *bs, unsigned long val)
{
	unsigned long mask = val >> 1;

	/* mask = highest_bit(val >> 1) */
	while (mask & (mask - 1)) {
		mask &= mask - 1;
	}

	/* Output gamma2-encoded bits */
	blz_putbit(bs, (val & mask) ? 1 : 0);

	while (mask >>= 1) {
		blz_putbit(bs, 1);
		blz_putbit(bs, (val & mask) ? 1 : 0);
	}

	blz_putbit(bs, 0);
}

static unsigned long
blz_hash4(const unsigned char *s)
{
	unsigned long val = (unsigned long) s[0]
	                 | ((unsigned long) s[1] << 8)
	                 | ((unsigned long) s[2] << 16)
	                 | ((unsigned long) s[3] << 24);

	return ((val * 2654435761UL) & 0xFFFFFFFFUL) >> (32 - BLZ_HASH_BITS);
}

unsigned long
blz_workmem_size(unsigned long src_size)
{
	(void) src_size;

	return WORKMEM_SIZE;
}

unsigned long
blz_max_packed_size(unsigned long src_size)
{
	return src_size + src_size / 8 + 64;
}

unsigned long
blz_pack(const void *src, void *dst, unsigned long src_size, void *workmem)
{
	struct blz_state bs;
	const unsigned char **lookup = (const unsigned char **) workmem;
	const unsigned char *prevsrc = (const unsigned char *) src;
	unsigned long src_avail = src_size;

	/* Check for empty input */
	if (src_avail == 0) {
		return 0;
	}

	/* Initialize lookup[] */
	{
		unsigned long i;

		for (i = 0; i < LOOKUP_SIZE; ++i) {
			lookup[i] = 0;
		}
	}

	bs.src = (const unsigned char *) src;
	bs.dst = (unsigned char *) dst;

	/* First byte verbatim */
	*bs.dst++ = *bs.src++;

	/* Check for 1 byte input */
	if (--src_avail == 0) {
		return 1;
	}

	/* Initialize first tag */
	bs.tagpos = bs.dst;
	bs.dst += 2;
	bs.tag = 0;
	bs.bits_left = 16;

	/* Main compression loop */
	while (src_avail > 4) {
		const unsigned char *p;
		unsigned long len = 0;

		/* Update lookup[] up to current position */
		while (prevsrc < bs.src) {
			lookup[blz_hash4(prevsrc)] = prevsrc;
			prevsrc++;
		}

		/* Look up current position */
		p = lookup[blz_hash4(bs.src)];

		/* Check match */
		if (p) {
			while (len < src_avail && p[len] == bs.src[len]) {
				++len;
			}
		}

		/* Output match or literal */
		if (len > 3) {
			unsigned long off = (unsigned long) (bs.src - p - 1);

			/* Output match tag */
			blz_putbit(&bs, 1);

			/* Output match length */
			blz_putgamma(&bs, len - 2);

			/* Output match offset */
			blz_putgamma(&bs, (off >> 8) + 2);
			*bs.dst++ = off & 0x00FF;

			bs.src += len;
			src_avail -= len;
		}
		else {
			/* Output literal tag */
			blz_putbit(&bs, 0);

			/* Copy literal */
			*bs.dst++ = *bs.src++;
			src_avail--;
		}
	}

	/* Output any remaining literals */
	while (src_avail > 0) {
		/* Output literal tag */
		blz_putbit(&bs, 0);

		/* Copy literal */
		*bs.dst++ = *bs.src++;
		src_avail--;
	}

	/* Shift last tag into position and store */
	bs.tag <<= bs.bits_left;
	bs.tagpos[0] = bs.tag & 0x00FF;
	bs.tagpos[1] = (bs.tag >> 8) & 0x00FF;

	/* Return compressed size */
	return (unsigned long) (bs.dst - (unsigned char *) dst);
}

//----------------------------------------------------------------------
//-- content of original file depacks.c

static int
blz_getbit_safe(struct blz_state *bs, unsigned int *result)
{
	unsigned int bit;

	/* Check if tag is empty */
	if (!bs->bits_left--) {
		if (bs->src_avail < 2) {
			return 0;
		}
		bs->src_avail -= 2;

		/* Load next tag */
		bs->tag = (unsigned int) bs->src[0]
		       | ((unsigned int) bs->src[1] << 8);
		bs->src += 2;
		bs->bits_left = 15;
	}

	/* Shift bit out of tag */
	bit = (bs->tag & 0x8000) ? 1 : 0;
	bs->tag <<= 1;

	*result = bit;

	return 1;
}

static int
blz_getgamma_safe(struct blz_state *bs, unsigned long *result)
{
	unsigned int bit;
	unsigned long v = 1;

	/* Input gamma2-encoded bits */
	do {
		if (!blz_getbit_safe(bs, &bit)) {
			return 0;
		}

		if (v & 0x80000000UL) {
			return 0;
		}

		v = (v << 1) + bit;

		if (!blz_getbit_safe(bs, &bit)) {
			return 0;
		}
	} while (bit);

	*result = v;

	return 1;
}

unsigned long
blz_depack_safe(const void *src, unsigned long src_size,
                void *dst, unsigned long depacked_size)
{
	struct blz_state bs;
	unsigned long dst_size = 1;
	unsigned int bit;

	/* Check for empty input */
	if (depacked_size == 0) {
		return 0;
	}

	bs.src = (const unsigned char *) src;
	bs.src_avail = src_size;
	bs.dst = (unsigned char *) dst;
	bs.dst_avail = depacked_size;
	bs.bits_left = 0;

	/* First byte verbatim */
	if (!bs.src_avail-- || !bs.dst_avail--) {
		return BLZ_ERROR;
	}
	*bs.dst++ = *bs.src++;

	/* Main decompression loop */
	while (dst_size < depacked_size) {
		if (!blz_getbit_safe(&bs, &bit)) {
			return BLZ_ERROR;
		}

		if (bit) {
			unsigned long len;
			unsigned long off;

			/* Input match length and offset */
			if (!blz_getgamma_safe(&bs, &len)) {
				return BLZ_ERROR;
			}
			if (!blz_getgamma_safe(&bs, &off)) {
				return BLZ_ERROR;
			}

			len += 2;
			off -= 2;

			if (off >= 0x00FFFFFFUL) {
				return BLZ_ERROR;
			}

			if (!bs.src_avail--) {
				return BLZ_ERROR;
			}

			off = (off << 8) + (unsigned long) *bs.src++ + 1;

			if (off > depacked_size - bs.dst_avail) {
				return BLZ_ERROR;
			}

			if (len > bs.dst_avail) {
				return BLZ_ERROR;
			}

			bs.dst_avail -= len;

			/* Copy match */
			{
				const unsigned char *p = bs.dst - off;
				unsigned long i;

				for (i = len; i > 0; --i) {
					*bs.dst++ = *p++;
				}
			}

			dst_size += len;
		}
		else {
			/* Copy literal */
			if (!bs.src_avail-- || !bs.dst_avail--) {
				return BLZ_ERROR;
			}
			*bs.dst++ = *bs.src++;

			dst_size++;
		}
	}

	/* Return decompressed size */
	return dst_size;
}

//----------------------------------------------------------------------
// lua binding

#include <stdlib.h>
#include <assert.h>

#include "lua.h"
#include "lauxlib.h"


//----------------------------------------------------------------------
//-- lua binding


static uint32_t load32_le(const uint8_t s[4]) {
    return (uint32_t)s[0]
        | ((uint32_t)s[1] <<  8)
        | ((uint32_t)s[2] << 16)
        | ((uint32_t)s[3] << 24);
}

static void store32_le(uint8_t out[4], uint32_t in) {
    out[0] =  in        & 0xff;
    out[1] = (in >>  8) & 0xff;
    out[2] = (in >> 16) & 0xff;
    out[3] = (in >> 24) & 0xff;
}

int ll_blz(lua_State *L) {
	// Lua API:  compress(s) => c
	// compress string s, return compressed string c
	// or nil, error msg in case of error
	//
	size_t sln, cln, bufln, workln;
	const char *s = luaL_checklstring(L, 1, &sln);	
	assert(sln < 0xffffffff); // fit a uint32
	bufln = blz_max_packed_size(sln) + 4;  // +4 to store s length
	workln = blz_workmem_size(sln);
	char * buf = lua_newuserdata(L, bufln);
	char * work = lua_newuserdata(L, workln);
	cln = blz_pack(s, buf+4, sln, work);
	// prefix compressed string with original s length (stored as LE)
	store32_le(buf, sln);
	lua_pushlstring (L, buf, cln + 4); 	
	return 1;
} //blz()

int ll_unblz(lua_State *L) {
	// Lua API:  uncompress(c) => s | nil, error msg
	// decompress string c, return original string s
	// or nil, error msg in case of decompression error
	//
	size_t sln, cln, bufln, dln;
	const char *c = luaL_checklstring(L, 1, &cln);	
	sln = load32_le(c);  
	bufln = sln + 8;  // have some more space.  ...for what?
	char * buf = lua_newuserdata(L, bufln);
	dln = blz_depack_safe(c + 4, cln - 4, buf, sln);
	if (dln != sln) {
		lua_pushnil (L);
		lua_pushliteral(L, "uncompress error");
		return 2;         
	}
	lua_pushlstring (L, buf, sln); 
	return 1;
} //unblz()
