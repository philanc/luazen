
# ----------------------------------------------------------------------
# adjust the following to the location of your Lua directory
# or include files and executable

LUADIR= ../lua
LUAINC= -I$(LUADIR)/include
LUAEXE= $(LUADIR)/bin/lua

# ----------------------------------------------------------------------

CC= gcc

CFLAGS= -Os -fPIC $(LUAINC) 
LDFLAGS= -fPIC

LUAZEN_O= luazen.o base58.o lzf_c.o lzf_d.o norx.o mono.o \
          md5.o rc4.o randombytes.o \
		  brieflz.o depacks.o

luazen.so:  src/*.c src/*.h
	$(CC) -c $(CFLAGS) src/*.c
	$(CC) -shared $(LDFLAGS) -o luazen.so $(LUAZEN_O)

test:  luazen.so
	$(LUAEXE) test/test_luazen.lua
	
clean:
	rm -f *.o *.so *.dll

.PHONY: clean test

