// interface to the OS Random Number Generator  
// (/dev/urandom or Windows)

#ifdef _WIN32

// ---------------------------------------------------------------------
// randombytes()  for windows - Use the Windows RNG (CryptGenRandom)
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

#else
// ---------------------------------------------------------------------
// use /dev/urandom

// (from nacl-20110221/randombytes/devurandom.c)

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

/* it's really stupid that there isn't a syscall for this */

static int fd = -1;

int randombytes(unsigned char *x,unsigned long long xlen)
{
  int i;

  if (fd == -1) {
	fd = open("/dev/urandom",O_RDONLY);
	if (fd == -1) { return -1; }
}

  while (xlen > 0) {
    if (xlen < 4096) i = xlen; else i = 4096;

    i = read(fd,x,i);
    if (i < 1) {
      sleep(1);
      continue;
    }

    x += i;
    xlen -= i;
  }
  return 0;
}

#endif
