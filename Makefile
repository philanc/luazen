# luazen
# ----------------------------------------------------------------------
# adjust the following to the location of your Lua directory
# or include files and executable

LUADIR= ../lua
LUAINC= -I$(LUADIR)/include
LUAEXE= $(LUADIR)/bin/lua

CC= gcc
AR= ar

CFLAGS= -Os -fPIC $(LUAINC) $(FUNCS)
LDFLAGS= -fPIC 

OBJS= \
	Alloc.o LzFind.o LzmaDec.o LzmaEnc.o LzmaLib.o lualzma.o \
	monocypher.o monocypher-ed25519.o luamonocypher.o \
	base64.o md5.o random.o

all: luazen.so

luazen.so: luazen.a
	$(CC) -shared -o luazen.so $(LDFLAGS) luazen.o luazen.a
	strip luazen.so
	rm -f *.o

luazen.a: src/*.c src/lzma/*.c src/lzma/*.h src/mono/*.h src/mono/*.h
	$(CC) -c $(CFLAGS) src/*.c
	$(CC) -c $(CFLAGS) -I./mono src/mono/*.c
	$(CC) -c $(CFLAGS)  -D_7ZIP_ST  -I./lzma src/lzma/*.c
	$(AR) rcu luazen.a $(OBJS)

test: test/test_luazen.lua luazen.so
	$(LUAEXE) test/test_luazen.lua
	
clean:
	rm -f *.o *.a *.so *.dll *.so 

.PHONY: clean test

