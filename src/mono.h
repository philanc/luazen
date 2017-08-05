

/*

This is directly extracted from the Monocypher library by Loup Vaillant.
http://loup-vaillant.fr/projects/monocypher/ 

20170319  - updated to Monocypher v0.6
20170805  - updated to Monocypher v1.0.1

The code below is copyrighted by Loup Vaillant, 2017.
Monocypher license is included in file crypto_licenses.md

*/

#ifndef MONOCYPHER_H
#define MONOCYPHER_H

#include <inttypes.h>
#include <stddef.h>

// Constant time equality verification
// returns 0 if it matches, -1 otherwise.
int crypto_memcmp(const uint8_t *p1, const uint8_t *p2, size_t n);

// constant time zero comparison.
// returns 0 if the input is all zero, -1 otherwise.
int crypto_zerocmp(const uint8_t *p, size_t n);

////////////////
/// Chacha20 ///  REMOVED
////////////////

/////////////////
/// Poly 1305 ///  REMOVED
/////////////////


////////////////
/// Blake2 b ///
////////////////

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

////////////////
/// Argon2 i ///
////////////////
void crypto_argon2i(uint8_t       *hash,      uint32_t hash_size,     // >= 4
                    void          *work_area, uint32_t nb_blocks,     // >= 8
                    uint32_t       nb_iterations,                     // >= 1
                    const uint8_t *password,  uint32_t password_size,
                    const uint8_t *salt,      uint32_t salt_size,     // >= 8
                    const uint8_t *key,       uint32_t key_size,      // optional
                    const uint8_t *ad,        uint32_t ad_size);      // optional

///////////////
/// X-25519 ///
///////////////
int crypto_x25519(uint8_t       shared_secret   [32],
                  const uint8_t your_secret_key [32],
                  const uint8_t their_public_key[32]);

void crypto_x25519_public_key(uint8_t       public_key[32],
                              const uint8_t secret_key[32]);


/////////////
/// EdDSA ///
/////////////
void crypto_sign_public_key(uint8_t        public_key[32],
                            const uint8_t  secret_key[32]);

void crypto_sign(uint8_t        signature [64],
                 const uint8_t  secret_key[32],
                 const uint8_t  public_key[32], // optional, may be 0
                 const uint8_t *message, size_t message_size);

int crypto_check(const uint8_t  signature [64],
                 const uint8_t  public_key[32],
                 const uint8_t *message, size_t message_size);


////////////////////
/// Key exchange ///  REMOVED
////////////////////


////////////////////////////////
/// Authenticated encryption ///  REMOVED
////////////////////////////////

#endif // MONOCYPHER_H
