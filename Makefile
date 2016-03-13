CC=cc
CFLAGS=-Wall -I/usr/local/opt/openssl/include -I. -g -fstandalone-debug
LIBS=-L/usr/local/opt/openssl/lib -lcrypto
DEPS=crypto.h

all:

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

challenge-%: challenge-%.o crypto.o
	$(CC) $(CFLAGS) $(LIBS) -o $@ $^

test: test.o crypto.o
	$(CC) $(CFLAGS) $(LIBS) -o $@ $^

.PHONY: clean
.PRECIOUS: %.o

clean:
	rm -f challenge-? challenge-1? *.o
