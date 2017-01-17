uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')

OBJECTS=crypto.o
ifeq ($(uname_S),Darwin)
	OS_LIBS = ""
	OBJECTS += fmemopen.o
endif
ifeq ($(uname_S),Linux)
	OS_LIBS = -lm -lbsd
	FMEMOPEN = ""
endif

CC=clang
CFLAGS=-Wall -I/usr/local/opt/openssl/include -I. -g
LIBS=-L/usr/local/opt/openssl/lib -lcrypto $(OS_LIBS)
DEPS=crypto.h

all:

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

challenge-%: challenge-%.o $(OBJECTS)
	$(CC) $(CFLAGS) $(LIBS) -o $@ $^

test: test.o crypto.o
	$(CC) $(CFLAGS) $(LIBS) -o $@ $^

.PHONY: clean
.PRECIOUS: %.o

clean:
	rm -rf challenge-? challenge-1? *.o *.dSYM
