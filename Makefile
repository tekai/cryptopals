CC=cc
CFLAGS=-Wall -lcrypto -L/usr/local/opt/openssl/lib -I/usr/local/opt/openssl/include -I.
DEPS = crypto.h

all:

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

challenge-9: challenge-9.o crypto.o
	$(CC) $(CFLAGS) -o $@ $^

challenge-%: challenge-%.c
	$(CC) $(CFLAGS) -o $@ $@.c


.PHONY: clean

clean:
	rm -f challenge-7 challenge-8
