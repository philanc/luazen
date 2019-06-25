
# ----------------------------------------------------------------------
# adjust the following to the location of your Lua directory
# or include files and executable

LUADIR= ../lua
LUAINC= -I$(LUADIR)/include
LUAEXE= $(LUADIR)/bin/lua

# ----------------------------------------------------------------------

CC= gcc
AR= ar

CFLAGS= -Os -fPIC $(LUAINC)  -D_7ZIP_ST
LDFLAGS= -fPIC 

OBJS= \
	random.o base64.o base58.o \
	blz.o  lzf.o  lzma.o  \
	norx.o md5.o rc4.o xor.o blake2b.o  \
	sha2.o x25519.o chacha.o morus.o  ascon.o 

all: luazen.so

luazen.so: luazen.a
	$(CC) -shared -o luazen.so $(LDFLAGS) luazen.o luazen.a
	strip luazen.so

luazen.a: src/*.c 
	$(CC) -c $(CFLAGS) src/*.c
	$(AR) rcu luazen.a $(OBJS)

test: test/test_luazen.lua luazen.so
	$(LUAEXE) test/test_luazen.lua
	
clean:
	rm -f *.o *.a *.so *.dll *.so 

.PHONY: clean test

