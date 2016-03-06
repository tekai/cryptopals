#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

int do_crypt(FILE *, FILE *, int);
size_t calcDecodeLength(const char*);
int Base64Decode(char*, unsigned char**, size_t*);

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

/*
Base64Decode code from https://gist.github.com/barrysteyn/7308212
The MIT License (MIT)

Copyright (c) 2013 Barry Steyn

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

size_t calcDecodeLength(const char* b64input) { //Calculates the length of a decoded string
	size_t len = strlen(b64input),
		padding = 0;

	if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
		padding = 2;
	else if (b64input[len-1] == '=') //last char is =
		padding = 1;

	return (len*3)/4 - padding;
}

int Base64Decode(char* b64message, unsigned char** buffer, size_t* length) { //Decodes a base64 encoded string
	BIO *bio, *b64;

	int decodeLen = calcDecodeLength(b64message);
	*buffer = (unsigned char*)malloc(decodeLen + 1);
	(*buffer)[decodeLen] = '\0';

	bio = BIO_new_mem_buf(b64message, -1);
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
	*length = BIO_read(bio, *buffer, strlen(b64message));
	assert(*length == decodeLen); //length should equal decodeLen, else something went horribly wrong
	BIO_free_all(bio);

	return (0); //success
}
