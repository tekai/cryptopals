#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <openssl/evp.h>
/* #include "openssl/ssl.h" */
/* #include "openssl/err.h" */
int do_crypt(FILE *, FILE *, int);

int main(int argc, char** argv) {
    FILE *in;
    FILE *out;

    // INPUT
    if (argc > 1) {
        if( access( argv[1], R_OK ) != -1 ) {
            in = fopen(argv[1], "r");
        } else {
            fprintf(stderr, "Can't open input: %s\n", argv[1]);
            return 1;
        }
    }
    else {
        in = stdin;
    }
    // OUTPUT
    if (argc > 2) {
        if( access( argv[2], R_OK ) != -1 ) {
            out = fopen(argv[2], "r");
        } else {
            fprintf(stderr, "Can't open input: %s\n", argv[1]);
            return 1;
        }
    }
    else {
        out = stdout;
    }
    /*
    fprintf(stdout, "ARGC: %d\n", argc);
    while (argc--) {
        fprintf(stdout, "ARGV[%d]: %s\n", argc, argv[argc]);
        }
    */
    do_crypt(in, out, 0);
    return 0;
}

int do_crypt(FILE *in, FILE *out, int do_encrypt) {
    /* Allow enough space in output buffer for additional block */
    unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;
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
        inlen = fread(inbuf, 1, 1024, in);
        if(inlen <= 0) break;
        if(!EVP_CipherUpdate(&ctx, outbuf, &outlen, inbuf, inlen)) {
            /* Error */
            EVP_CIPHER_CTX_cleanup(&ctx);
            return 0;
        }
        fwrite(outbuf, 1, outlen, out);
    }
    if(!EVP_CipherFinal_ex(&ctx, outbuf, &outlen)) {
        /* Error */
        EVP_CIPHER_CTX_cleanup(&ctx);
        return 0;
    }
    fwrite(outbuf, 1, outlen, out);

    EVP_CIPHER_CTX_cleanup(&ctx);
    return 1;
}
