CC=cc
CFLAGS=-Wall -I/usr/local/opt/openssl/include -I.
LIBS=-L/usr/local/opt/openssl/lib -lcrypto
DEPS=crypto.h

all:

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

challenge-%: challenge-%.o crypto.o
	$(CC) $(CFLAGS) $(LIBS) -o $@ $^

test: test.o crypto.o
	$(CC) $(CFLAGS) $(LIBS) -o $@ $^

.PHONY: clean

clean:
	rm -f challenge-? challenge-1? *.o
