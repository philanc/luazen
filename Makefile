# luazen
# ----------------------------------------------------------------------
# adjust the following to the location of your Lua directory
# or include files and executable

LUADIR= ../lua
LUAINC= -I$(LUADIR)/include
LUAEXE= $(LUADIR)/bin/lua

# ----------------------------------------------------------------------
# modular build: the following constants can be defined to include
# the corresponding functions in the luazen library:
#
#   BASE64     Base64 encode/decode
#   BASE58     Base58 encode/decode
#   BLZ        BriefLZ compress/uncompress
#   LZF        LZF compress/uncompress
#   LZMA       LZMA compress/uncompress
#   NORX       Norx AEAD encrypt/decrypt
#   CHACHA     Xchacha20 AEAD encrypt/decrypt
#   RC4        RC4 encrypt/decrypt
#   MD5        MD5 hash
#   BLAKE      Blake2b hash, Argon2i key derivation
#   SHA2       SHA2-512 hash
#   X25519     Ec25519 key exchange and ed25519 signature functions
#   MORUS      Morus AEAD encrypt/decrypt
#   ASCON      Ascon128a AEAD encrypt/decrypt
#
# the list of functions for the default build:
FUNCS= -DBASE64 -DLZMA  \
       -DMD5 -DBLAKE -DX25519 -DMORUS \
       -DBASE58 -DBLZ -DNORX -DCHACHA \
       -DRC4  -DSHA2  -DASCON -DLZF
       


CC= gcc
AR= ar

CFLAGS= -Os -fPIC $(LUAINC) $(FUNCS)
LDFLAGS= -fPIC 

OBJS= \
	random.o base64.o base58.o \
	blz.o  lzf.o  lzma.o  \
	norx.o md5.o rc4.o xor.o blake2b.o  \
	sha2.o x25519.o chacha.o morus.o  ascon.o \
	Alloc.o LzFind.o LzmaDec.o LzmaEnc.o LzmaLib.o

all: luazen.so

luazen.so: luazen.a
	$(CC) -shared -o luazen.so $(LDFLAGS) luazen.o luazen.a
	strip luazen.so
	rm -f *.o


luazen.a: src/*.c src/lzma/*.c src/lzma/*.h
	$(CC) -c $(CFLAGS) src/*.c
	$(CC) -c $(CFLAGS)  -D_7ZIP_ST  src/lzma/*.c
	$(AR) rcu luazen.a $(OBJS)

test: test/test_luazen.lua luazen.so
	$(LUAEXE) test/test_luazen.lua
	
clean:
	rm -f *.o *.a *.so *.dll *.so 

.PHONY: clean test

