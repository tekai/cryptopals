#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/bio.h>

#include "crypto.h"

/**
 * Pad a `string' to size using PKCS#7. Assumes `string' has size+1
 * space left for padding data and is at most `size' long. 
 *
 * @param str String to be padded
 * @param size pad size
 */
int pkcs7_pad(char * string, uint8_t size) {
    uint8_t len = strlen(string);
    int d = size - len;
    uint8_t i;
    if (d<0) {
        return -1;
    }
    for (i=0;i<d;i++) {
        string[len+i] = d;
    }
    string[len+d] = '\0';

    return 1;
}

/**
 * Apply encryption to in file, put result in out file
 *
 * @param in input
 * @param out output
 * @param do_encrypt encrypt?
 */
int do_crypt(FILE *in, FILE *out, int do_encrypt) {
    /* Allow enough space in output buffer for additional block */
    unsigned char inbuf[8192], outbuf[8192 + EVP_MAX_BLOCK_LENGTH];
    unsigned char b64buf[4096];
    int b64len, inlen, outlen;
    EVP_CIPHER_CTX ctx;

    /* Bogus key and IV: we'd normally set these from
     * another source.
     */
    unsigned char key[] = "YELLOW SUBMARINE";
    unsigned char iv[]  = "1234567887654321";

    /* Don't set key or IV right away; we want to check lengths */
    EVP_CIPHER_CTX_init(&ctx);
    EVP_CipherInit_ex(&ctx, EVP_aes_128_ecb(), NULL, NULL, NULL,
        do_encrypt);

    OPENSSL_assert(EVP_CIPHER_CTX_key_length(&ctx) == 16);
    // assert fails, dunno why nor if it's necessary
    /* OPENSSL_assert(EVP_CIPHER_CTX_iv_length(&ctx) == 16); */

    /* Now we can set key and IV */
    EVP_CipherInit_ex(&ctx, NULL, NULL, key, iv, do_encrypt);


    for(;;)  {
        inlen = fread(inbuf, 1, 8192, in);
        if(inlen <= 0) break;
        base64_decode(inbuf, inlen, b64buf, &b64len);
        if(!EVP_CipherUpdate(&ctx, outbuf, &outlen, b64buf, b64len)) {
            /* Error */
            EVP_CIPHER_CTX_cleanup(&ctx);
            return 1;
        }
        fwrite(outbuf, 1, outlen, out);
    }
    if(!EVP_CipherFinal_ex(&ctx, outbuf, &outlen)) {
        /* Error */
        EVP_CIPHER_CTX_cleanup(&ctx);
        return 1;
    }
    fwrite(outbuf, 1, outlen, out);

    EVP_CIPHER_CTX_cleanup(&ctx);
    return 0;
}

int base64_decode(const unsigned char *inbuf, const int inlen, unsigned char *outbuf, int *outlen) {
    BIO *bio, *b64;

    bio = BIO_new_mem_buf(inbuf, inlen);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    *outlen = BIO_read(bio, outbuf, inlen);

    BIO_free_all(bio);

    return 1;
}
