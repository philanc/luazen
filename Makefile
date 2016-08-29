
# ----------------------------------------------------------------------
# adjust the following to the location of your Lua include file

INCFLAGS= -I../lua/include

# ----------------------------------------------------------------------

CC= gcc
AR= ar

CFLAGS= -Os -fPIC $(INCFLAGS) 
LDFLAGS= -fPIC

LUAZEN_O= luazen.o base58.o lzf_c.o lzf_d.o md5.o rabbit.o rc4.o sha1.o

luazen.so:  src/*.c src/*.h
	$(CC) -c $(CFLAGS) src/*.c
	$(CC) -shared $(LDFLAGS) -o luazen.so $(LUAZEN_O)

clean:
	rm -f *.o *.a *.so

.PHONY: clean

