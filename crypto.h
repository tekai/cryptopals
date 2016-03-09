#ifndef CRYPTO_H
#define CRYPTO_H

void unhex(char *, uint8_t *, size_t);
void dohex(uint8_t *, char *, size_t);
int pkcs7_pad(char *, uint8_t);
int base64_decode(const unsigned char *, const int, uint8_t *, int *);
int base64_encode(const uint8_t *, const size_t, char**);
int do_crypt(FILE *, FILE *, int);

#endif /* CRYPTO_H */
