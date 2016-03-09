#ifndef CRYPTO_H
#define CRYPTO_H

void unhex(char *, uint8_t *, size_t);
int pkcs7_pad(char *, uint8_t);
int base64_decode(const unsigned char *, const int, unsigned char *, int *);
int base64_encode(const char *, const size_t, char**);
int do_crypt(FILE *, FILE *, int);

#endif /* CRYPTO_H */
