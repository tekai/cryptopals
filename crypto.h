#ifndef CRYPTO_H
#define CRYPTO_H

void unhex(char *, uint8_t *, size_t);
void dohex(uint8_t *, char *, size_t);
void arr_xor(uint8_t *, uint8_t *, size_t);
int pkcs7_pad(uint8_t *, uint8_t, uint8_t);
int base64_decode(const unsigned char *, const int, uint8_t *, int *);
int base64_encode(const uint8_t *, const size_t, char**);
int do_crypt(FILE *, FILE *, int);
int aes_cbc(FILE *, FILE *, int);
int aes_128_cbc(FILE *, FILE *, int, uint8_t *, uint8_t *);
int aes_128_ecb(FILE *, FILE *, int, uint8_t *, size_t *);
unsigned int detect_ecb(uint8_t *, size_t, uint8_t);
size_t detect_block_size(uint8_t *, size_t, size_t *);

#endif /* CRYPTO_H */
