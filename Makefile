CC=cc
CFLAGS=-Wall -lcrypto -L/usr/local/opt/openssl/lib -I/usr/local/opt/openssl/include

challenge-%:
	$(CC) $(CFLAGS) -o $@ $@.c

all:

clean:
	rm -f challenge-7