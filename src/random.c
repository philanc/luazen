// Copyright (c) 2018 Phil Leblanc  -- see LICENSE file
// ---------------------------------------------------------------------
// Lua binding to utility functions: randombytes
// interface to the OS Random Number Generator  

#ifdef _WIN32
// ------------------------------
// randombytes()  for windows
// Use the Windows RNG (CryptGenRandom)
// tested with MinGW (2016-07-31)

#include <stdlib.h>  /// for exit() 

#include <windows.h>
#include <wincrypt.h> /* CryptAcquireContext, CryptGenRandom */

int randombytes(unsigned char *x,unsigned long long xlen)
{


  HCRYPTPROV p;
  ULONG i;

if (xlen > 4096) {
		xlen = 4096; 
}
	
  if (CryptAcquireContext(&p, NULL, NULL,
      PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) == FALSE) {
		return(-1); 
  }
  if (CryptGenRandom(p, xlen, (BYTE *)x) == FALSE) {
		return(-1); 
  }
  CryptReleaseContext(p, 0);
  return 0;
}	

#else // unix
// -------------------------------
// use getrandom() or /dev/urandom

#include <fcntl.h>
#include <unistd.h>

#if defined __GLIBC_PREREQ && !defined __UCLIBC__
#define GLIBC_PREREQ(M, m) (__GLIBC_PREREQ(M, m))
#else
#define GLIBC_PREREQ(M, m) 0
#endif

// the getrandom() detection code below has been provided by Daurnimator 
// (https://github.com/daurnimator)
#ifndef HAVE_GETRANDOM
#define HAVE_GETRANDOM (GLIBC_PREREQ(2,25) && __linux__)
#endif
#if HAVE_GETRANDOM
#include <sys/random.h>
#endif

int randombytes(unsigned char *x, unsigned long long xlen) {
	int fd, i;
	size_t count = (size_t) xlen;

#if HAVE_GETRANDOM
	i = getrandom(x, count, 0);
#else
	fd = open("/dev/urandom",O_RDONLY);
	if (fd == -1) { 
		return -1; 
	}
	i = read(fd, x, count);
	close(fd);
#endif
	if ((i < 0) || (i < count)) { 
		return -1; 
	}
	return 0;
}

#endif

//----------------------------------------------------------------------
//-- lua binding functions

#include "lua.h"
#include "lauxlib.h"



int ll_randombytes(lua_State *L) {
	// Lua API:   randombytes(n)  returns a string with n random bytes 
	// n must be 256 or less.
	// randombytes return nil, error msg  if the RNG fails or if n > 256
	//	
    size_t bufln; 
	unsigned char buf[256];
	lua_Integer li = luaL_checkinteger(L, 1);  // 1st arg
	if ((li > 256 ) || (li < 0)) {
		lua_pushnil (L);
		lua_pushliteral(L, "invalid byte number");
		return 2;      		
	}
	int r = randombytes(buf, li);
	if (r != 0) { 
		lua_pushnil (L);
		lua_pushliteral(L, "random generator error");
		return 2;         
	} 	
    lua_pushlstring (L, buf, li); 
	return 1;
} //randombytes()

