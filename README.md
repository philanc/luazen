![CI](https://github.com/philanc/luazen/workflows/CI/badge.svg)

# luazen

[Luazen](https://github.com/philanc/luazen) is a small library with various compression, encoding and 
cryptographic functions for Lua: LZMA compression, base64 encoding, Chacha20 authenticated encryption, curve25519 key exchange, ed25519 signature, md5, sha512 and blake3 hash.

All the functions work on strings, there is no stream or chunked complex interface. All the C code is included. No external dependencies.

### Recent changes

November-2022  version 2.0

* The luazen library has been seriously streamlined. Algorithms that are either legacy, deprecated, not widely used, or that can be replaced with a [pure Lua implementation](https://github.com/philanc/plc have been retired (ascon, base58, blz, lzf, morus, norx, rc4)

* The last luazen version including all these algorithms is v0.16. It can be accessed [here](https://github.com/philanc/luazen/tree/v0.16).

Luazen borrows heavily from other projects. See the License and credits section below.

### Algorithms

[ChaCha20-Poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305) is  a widely used authenticated encryption designed by Dan Bernstein. It is used in many places including TLS, SSH and IPsec

[Blake3](https://blake3.io) is a very fast cryptographic hash function that can also be used as a MAC, key derivation function (KDF) and extendable-output function (XOF). See the [BLAKE3
paper](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf). It has been designed by Jack O'Connor, Jean-Philippe Aumasson, Samuel Neves and Zooko Wilcox-O'Hearn.

[X25519](https://en.wikipedia.org/wiki/Curve25519)  is an elliptic curve-based DH key-exchange algorithm designed by Dan Bernstein. Ed25519 is a digital signature algorithm based on the same curve.  X25519 and Ed25519 are also used in many protocols including TLS and SSH.

[LZMA](https://en.wikipedia.org/wiki/Lempel%E2%80%93Ziv%E2%80%93Markov_chain_algorithm) is an excellent compression algorith designed by Igor Pavlov (of 7z fame).

### API
```
--- LZMA Compression

lzma(str)
	compress string str (LZMA algorithm)
	return the compressed string or (nil, error message)

unlzma(cstr)
	uncompress string cstr
	return the uncompressed string or (nil, error message)


--- Blake3 cryptographic hash

blake3(string, [key [, hashlen]])
	return the blake3 hash of string.
	if key is non-nil, the function returns a keyed hash of
	the string (MAC). key must be a 32-byte string.
	if hashlen is non-null, the function returns a hashlen-long
	hash. The default hash length is 32 bytes. Any length can be 
	requested. 


--- Authenticated encryption

encrypt(key, nonce, plain [, ninc]) => crypted
	authenticated encryption using Xchacha20 and a Poly1305 MAC
	key must be a 32-byte string
	nonce must be a 24-byte string
	plain is the text to encrypt as a string
	ninc: optional nonce increment (useful when encrypting a 
	   long text  as a sequence of block). The same parameter n 
	   can be used for the sequence. ninc is added to n for each
	   block, so the actual nonce used for each block encryption 
	   is distinct.
	   ninc defaults to 0 (the nonce n is used as-is)
	return the encrypted text as a string. The encrypted text
	includes the 16-byte MAC. So  #crypted == #plain + 16
	
decrypt(key, nonce, crypted [, ninc]) => plain
	authenticated decryption - verification of the Poly1305 MAC
	and decryption with Xcahcha20.
	key must be a 32-byte string
	nonce must be a 24-byte string
	crypted is the text to decrypt as a string
	ninc: optional nonce increment (see above. defaults to 0)
	return the decrypted plain text as a string or nil if the MAC 
	verification fails.


--- Curve25519-based Diffie-Hellman key exchange

public_key(sk) => pk
	return the public key associated to a curve25519 secret key
	sk is the secret key as a 32-byte string
	pk is the associated public key as a 32-byte string

	To generate a curve25519 key pair (sk, pk), do:
		sk = randombytes(32)
		pk = public_key(sk)
	
key_exchange(sk, pk) => k
	DH key exchange. Return a session key k used to encrypt 
	or decrypt a text.
	sk is the secret key of the party invoking the function 
	("our secret key"). 
	pk is the public key of the other party 
	("their public key").
	sk, pk and k are 32-byte strings

x25519(s, P1) => s.P1
	raw scalar multiplication over curve25519
	Note: usually this function should not be used directly.
	For DH key exchange, the key_exchange() function above 
	should be used instead.
	--
	s: a scalar as a 32-byte string
	P1: a curve point as a 32-byte string
	return the product s.P1 as a 32-byte string

	
--- Ed25519 signature based on SHA512 (compatible with 
    the original NaCl signature functions) 
    Note that contrary to the sign() and sign_open() NaCl functions, 
    the signature is not prepended to the text ("detached signature")

sha512(m) => digest
	return the sha512 hash of message m as a 64-byte binary string

ed25519_public_key(sk)
	return the public key associated to a secret key
	sk is the secret key as a 32-byte string
	pk is the associated public key as a 32-byte string

	Note: curve25519 keypairs or keys generated by sign_public_key() 
	cannot be used for the ed25519_* signature functions.
	To generate a signature key pair (sk, pk), do:
		sk = randombytes(32)
		pk = ed25519_public_key(sk)

ed25519_sign(sk, pk, text) => sig
	sign a text with a secret key
	sk is the secret key as a 32-byte string
	text is the text to sign as a string
	Return the text signature as a 64-byte string.

ed25519_check(sig, pk, text) => is_valid
	check a text signature with a public key
	sig is the signature to verify, as a 64-byte string
	pk is the public key as a 32-byte string
	text is the signed text
	Return a boolean indicating if the signature is valid or not

--- Utilities

randombytes(n)
	return a string containing n random bytes

b64encode(str [, linelen])
	str is the string to base64-enccode
	linelen is an optional output line length
	(should be be multiple of 4). default is 72.
	if linelen == 0, no '\n' is inserted.

b64decode(str)
	str is the base64-encoded string to decode
	return the decoded string, or nil if str contains 
	an invalid character (whitespaces and newlines are ignored)



```

## Building 

Adjust the Makefile according to your Lua installation (set the LUADIR variable). 

Targets:
```
	make          -- build luazen.so
	make test     -- build luazen.so if needed, 
                         then run test_luazen.lua
	make clean
```

An alternative Lua installation can be specified:
```
	make LUA=/path/to/lua LUAINC=/path/to/lua_include_dir test
```

Rockspec files are also provided to build the previous luazen version (v0.16) and the last github version with Luarocks:
```
	# build version 0.16:
	luarocks build luazen-0.16.rockspec
	
	# build last github version 
	luarocks build luazen-scm-1.rockspec
```


### License and credits

Luazen is distributed under the terms of the MIT License. 

- The luazen library is largely based on the Monocypher library (xchacha, x25519 DH, sha512 and ed25519 signature) Code is public domain - see http://loup-vaillant.fr/projects/monocypher/
- blake3: luazen is based or the [C portable version](https://github.com/BLAKE3-team/BLAKE3/tree/master/c) of the reference Blake3 implementation
- base64 functions by Luiz Henrique de Figueiredo (public domain)
- md5 by Cameron Rich (BSD)

See the licenses or public domain dedication in the source files.

The code from these sources has been more or less modified - all bugs are probably mine!

Copyright (c) 2022  Phil Leblanc 
