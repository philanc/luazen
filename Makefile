
# ----------------------------------------------------------------------
# adjust the following to the location of your Lua include file

INCFLAGS= -I../lua/include

# ----------------------------------------------------------------------

CC= gcc
AR= ar

CFLAGS= -Os -fPIC $(INCFLAGS) 
LDFLAGS= -fPIC

LUATWEETNACL_O= luatweetnacl.o randombytes.o tweetnacl.o

tweetnacl.so:  *.c *.h
	$(CC) -c $(CFLAGS) *.c
	$(CC) -shared $(LDFLAGS) -o luatweetnacl.so $(LUATWEETNACL_O)

clean:
	rm -f *.o *.a *.so

.PHONY: clean

