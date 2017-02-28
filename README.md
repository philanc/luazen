# luazen

Luazen is a small library with various encoding, compression and 
cryptographic functions. All the functions work on strings, there is no stream or chunked more complex interfaces.

The compression functions are based on the tiny **lzf** library. It is not as efficient as gzip, but much smaller.

Endoding and decoding functions are provided for **base64** and **base58** (for base58, the BitCoin encoding alphabet is used)

Cryptographic functions include **md5**, **sha1**, and **rc4**.

### API
```
--- Compression functions

lzf(str)
	compress string str  (#str must be less than 4 GB)
	return the compressed string or (nil, error message)

unlzf(cstr)
	uncompress string cstr
	return the uncompressed string or (nil, error message)

--- Encoding functions

b64encode(str [, n])
	base64 encode string str. n is an optional integer
	if n > 0, a newline is inserted every n character in the encoded string
	if n == 0, no newline is inserted.
	if not provided, n defaults to 72.
	return the encoded string

b64decode(bstr)
	decode base64-encoded string bstr. Even non well-formed encoded strings (ie.
	strings with no "=" padding) are decoded.
	all whitespace characters in bstr are ignored.
	return the encoded string or nil if the string cannot be decoded

b58encode(str)
	base58 encode string str
	this uses the same alphabet as bitcoin addresses:
	"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	contrary to base64, base58 encodes a string as a long number 
	written in base58. It is not intended to be used for "long" strings
	(more than a couple thousand bytes). No newline is inserted in the
	encoded string.
	return the encoded string or (nil, error message)

b58decode(bstr)
	decode base58-encoded string bstr
	return the decoded string or (nil, error message)

xor(str, key)
	return the byte-to-byte xor of string str with string key.
	the returned string is always the same length as str.
	if key is longer than str, extra key bytes are ignored.
	if key is shorter than str, it is repeated as much as necessary.

--- Cryptographic functions

rc4raw(str, key)
	encrypt (or decrypt, as rc4 is symmetric) string str with string key
	key length must be 16 (or nil, error msg is returned)
	return the encrypted string
	see http://en.wikipedia.org/wiki/RC4 for raw rc4 weaknesses
	rc4(), a rc4-drop implementation, should be used instead for most uses

rc4(str, key)
	this a rc4-drop encryption with a 256-byte drop
	(ie. the rc4 state is initialized by "encrypting" a 256-byte block of
	zero bytes before strating the encyption of the string)
	arguments and return are the same as rc4raw()
	key length must be 16 (or nil, error msg is returned)

md5(str)
	return the md5 hash of string str as a binary string
	(no hex encoding)

sha1(str)
	return the sha1 hash of string str as a binary string
	(no hex encoding)
```

### License

luazen is distributed under the terms of the MIT License. 

The luazen library includes some code from various authors (see src/):
- base64 functions by Luiz Henrique de Figueiredo (public domain)
- base58 functions by Luke Dashjr (MIT)
- md5, sha1 by Cameron Rich (BSD)
- lzf functions by  Marc Alexander Lehmann (BSD, see src/lzf* headers)

(the code from these sources has been significantly modified - all bugs are probably mine!)

Copyright (c) 2016  Phil Leblanc 


	




