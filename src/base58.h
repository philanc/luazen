#ifndef LIBBASE58_H
#define LIBBASE58_H
#include <stdbool.h>
#include <stddef.h>
extern bool b58tobin(char *bin, size_t *binsz, const char *b58, size_t b58sz);
extern bool b58enc(char *b58, size_t *b58sz, const char *bin, size_t binsz);
#endif
