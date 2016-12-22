#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include "crypto.h"

/**
 * Convert hex string into data
 *
 * @param hex input hex data
 * @param out output buffer
 * @param len Length of the hex string
 */
void unhex(char * hex, uint8_t * out, size_t len) {
    size_t i;
    char c[3] = "00";
    for (i=0;i<len;i+=2) {
        c[0] = hex[i];
        c[1] = hex[i+1];
        out[i/2] = (char) strtol(c, NULL, 16);
    }
}

/**
 * @param
 * @param len length of raw
 */
void dohex(uint8_t * raw, char * out, size_t len) {
    size_t i;
    for (i=0;i<len;i++) {
        sprintf(out+(i*2), "%02x", raw[i]);
    }
}

/**
 * xor dest with src
 */
void arr_xor(uint8_t * dest, uint8_t * src, size_t len) {
    size_t i;
    for (i=0;i<len;i++) {
        dest[i] = dest[i] ^ src[i];
    }
}

/**
 * Pad a `string' to size using PKCS#7. Assumes `string' has size+1
 * space left for padding data and is at most `size' long.
 *
 * @param str Data to be padded
 * @param arrlen length of the data
 * @param size pad size
 */
int pkcs7_pad(uint8_t * arr, uint8_t arrlen, uint8_t padlen) {
    int d = padlen - arrlen;
    uint8_t i;
    if (d<0) {
        return -1;
    }
    for (i=0;i<d;i++) {
        arr[arrlen+i] = d;
    }
    return 1;
}

/**
 * Decode Base64 using OpenSSL
 *
 * @param inbuf input string
 * @param inlen length the input
 * @param outbuf byte array for the output
 * @param outlen length of the output
 */
int base64_decode(const unsigned char *inbuf, const int inlen, uint8_t *outbuf, int *outlen) {
    BIO *bio, *b64;

    bio = BIO_new_mem_buf(inbuf, inlen);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    *outlen = BIO_read(bio, outbuf, inlen);

    BIO_free_all(bio);

    return 1;
}


/**
 * Encode Base64 using OpenSSL
 *
 * @param inbuf input byte array
 * @param length the input
 * @param out pointer to output, copy to use the data
 */
int base64_encode(const uint8_t *inbuf, const size_t length, char** out) {
	BIO *bio, *b64;
	BUF_MEM *bufferPtr;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	/* BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line */
	BIO_write(bio, inbuf, length);
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &bufferPtr);
	BIO_set_close(bio, BIO_NOCLOSE);
	BIO_free_all(bio);

	*out=(*bufferPtr).data;

	return (0); //success
}


int aes_128_ecb(FILE *in, FILE *out, int do_encrypt, uint8_t *key) {
    /* Allow enough space in output buffer for additional block */
    unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;
    EVP_CIPHER_CTX ctx;

    /* Don't set key right away; we want to check lengths */
    EVP_CIPHER_CTX_init(&ctx);
    EVP_CipherInit_ex(&ctx, EVP_aes_128_ecb(), NULL, NULL, NULL,
        do_encrypt);

    OPENSSL_assert(EVP_CIPHER_CTX_key_length(&ctx) == 16);

    /* Now we can set key*/
    EVP_CipherInit_ex(&ctx, NULL, NULL, key, NULL, do_encrypt);


    for(;;)  {
        inlen = fread(inbuf, 1, 1024, in);
        if(inlen <= 0) break;
        if(!EVP_CipherUpdate(&ctx, outbuf, &outlen, inbuf, inlen)) {
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

/**
 * Apply encryption to in file, put result in out file
 *
 * @param in input
 * @param out output
 * @param do_encrypt encrypt?
 */
int aes_cbc(FILE *in, FILE *out, int do_encrypt) {
    uint8_t key[] = "YELLOW SUBMARINE";
    uint8_t iv[]  = {
        '\x0', '\x0', '\x0', '\x0', '\x0', '\x0', '\x0', '\x0',
        '\x0', '\x0', '\x0', '\x0', '\x0', '\x0', '\x0', '\x0',
    };

    return aes_128_cbc(in, out, do_encrypt, key, iv);
}

/**
 * Apply encryption to in file, put result in out file
 *
 * @param in input
 * @param out output
 * @param do_encrypt encrypt?
 */
int aes_128_cbc(FILE *in, FILE *out, int do_encrypt, uint8_t *key, uint8_t *iv) {
    /* Allow enough space in output buffer for additional block */
    /* AES block size is 128 bits = 16 bytes*/
    const uint8_t BLOCK_SIZE = 16;
    uint8_t inbuf[BLOCK_SIZE], outbuf[BLOCK_SIZE + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen=0,padded=0;
    EVP_CIPHER_CTX ctx;

    /* Bogus key and IV: we'd normally set these from
     * another source.
     */
    uint8_t last[BLOCK_SIZE];
    memcpy(last, iv, BLOCK_SIZE);
    /* Don't set key or IV right away; we want to check lengths */
    EVP_CIPHER_CTX_init(&ctx);
    EVP_CipherInit_ex(&ctx, EVP_aes_128_ecb(), NULL, NULL, NULL,
        do_encrypt);
    EVP_CIPHER_CTX_set_key_length(&ctx, 16);
    OPENSSL_assert(EVP_CIPHER_CTX_key_length(&ctx) == 16);

    /* Now we can set key and IV */
    EVP_CipherInit_ex(&ctx, NULL, NULL, key, iv, do_encrypt);
    // disable padding, so CipherUpdate does output sth.
    EVP_CIPHER_CTX_set_padding(&ctx, 0);

    for(;;)  {
        inlen = fread(inbuf, 1, BLOCK_SIZE, in);
        if (outlen > 0) {
            if (!do_encrypt && inlen <= 0) {
                uint8_t p = outbuf[outlen-1];
                outlen = outlen - (int) p;
            }
            fwrite(outbuf, 1, outlen, out);
        }

        if (inlen <= 0) {
            break;
        }
        if (do_encrypt) {
            if (inlen < BLOCK_SIZE) {
                pkcs7_pad(inbuf, inlen, BLOCK_SIZE);
                padded = 1;
            }
            arr_xor(inbuf, last, BLOCK_SIZE);
        }
        if (!EVP_CipherUpdate(&ctx, outbuf, &outlen, inbuf, BLOCK_SIZE)) {
            /* Error */
            EVP_CIPHER_CTX_cleanup(&ctx);
            return 1;
        }
        if (do_encrypt) {
            memcpy(last, outbuf, BLOCK_SIZE);
        }
        else {
            arr_xor(outbuf, last, BLOCK_SIZE);
            memcpy(last, inbuf, BLOCK_SIZE);
        }
    }
    // if there's been no padding, add a whole block of padding
    if (do_encrypt && !padded) {
        pkcs7_pad(inbuf, 0, BLOCK_SIZE);
        arr_xor(inbuf, last, BLOCK_SIZE);
        if (!EVP_CipherUpdate(&ctx, outbuf, &outlen, inbuf, BLOCK_SIZE)) {
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
    if (outlen > 0) {
        fprintf(stderr, "something went wrong\n");
        EVP_CIPHER_CTX_cleanup(&ctx);
        return 1;
    }
    EVP_CIPHER_CTX_cleanup(&ctx);
    return 0;
}

unsigned int detect_ecb(byte *buf, size_t length) {
    uint8_t BLOCK_SIZE = 16;
    size_t chunks;
    unsigned int ecb = 0;
    size_t i,j,h;

    chunks = length/BLOCK_SIZE;
    for (i=0;i < chunks-1; i++) {
        h = 0;
        for (j=i+1; j < chunks; j++) {
            if (bcmp(buf + i*BLOCK_SIZE, buf + j*BLOCK_SIZE, BLOCK_SIZE) == 0) {
                ecb++;
            }
        }
    }

    return ecb;
}
