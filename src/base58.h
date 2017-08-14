#ifndef LIBBASE58_H
#define LIBBASE58_H
#include <stdbool.h>
#include <stddef.h>
extern bool b58tobin(char *bin, size_t *binsz, const char *b58, size_t b58sz);
extern bool b58enc(char *b58, size_t *b58sz, const char *bin, size_t binsz);

// max length of a string to encode with base58
#define B58MAXLN 256

// longest 256-byte encoded string is 350 bytes long.
// add a bit (b58enc add \0 at the end of the encoded string)
#define B58MAXENCLN 360

#endif
