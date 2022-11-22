
// interface to the OS Random Number Generator  

// the getrandom() detection code has been provided by Daurnimator 
// (https://github.com/daurnimator)


#ifdef _WIN32

// ---------------------------------------------------------------------
// randombytes()  for windows - Use the Windows RNG (CryptGenRandom)
// tested with MinGW (2016-07-31)

#include <stdlib.h>  /// for exit() 

#include <windows.h>
#include <wincrypt.h> /* CryptAcquireContext, CryptGenRandom */

int randombytes(unsigned char *x,unsigned long long xlen) {
	HCRYPTPROV p;
	int r = 0;

	if (CryptAcquireContext(&p, NULL, NULL,
	  PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) == FALSE) {
		return(-1); 
	}
	if (CryptGenRandom(p, xlen, (BYTE *)x) == FALSE) {
		r = -1;
	}
	CryptReleaseContext(p, 0);
	return r;
}	

#else // unix
// ---------------------------------------------------------------------
// use getrandom() or /dev/urandom

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#if defined __GLIBC_PREREQ && !defined __UCLIBC__
#define GLIBC_PREREQ(M, m) (__GLIBC_PREREQ(M, m))
#else
#define GLIBC_PREREQ(M, m) 0
#endif

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

#endif  // win32 or unix?
