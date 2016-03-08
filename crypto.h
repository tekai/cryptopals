#ifndef CRYPTO_H
#define CRYPTO_H

int pkcs7_pad(char *, uint8_t);
int base64_decode(const unsigned char *, const int, unsigned char *, int *);
int do_crypt(FILE *, FILE *, int);

#endif /* CRYPTO_H */
