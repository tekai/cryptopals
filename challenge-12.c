#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <math.h>

#include "crypto.h"
#include "fmemopen.h"

int oracle(uint8_t *in, size_t inlen, uint8_t *out, size_t outlen, size_t * enclen) {
    uint8_t buf[8192];
    uint8_t key[16];
    uint8_t *inbuf;
    FILE *s_in, *s_out;
    size_t b64len = 0;
    // base64 encoded padding data for the challenge
    const unsigned char b64[] =
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\n"
        "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\n"
        "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\n"
        "YnkK";

    // decode into buf
    base64_decode(b64, strlen(b64), buf, &b64len);

    // some key ... should be random
    unhex("d9a6ef8423d06d3fc69795e75494114a", key, 16);

    // input buffer for encryption
    inbuf = malloc((inlen+b64len)*sizeof(uint8_t));

    // copy data & padding into inbuf
    memcpy(inbuf, in, inlen);
    memcpy(inbuf+inlen, buf, b64len);

    // open in & out as file pointers
    s_in  = fmemopen(inbuf, inlen+b64len, "r");
    s_out = fmemopen(out, outlen, "w");

    // encrypt
    aes_128_ecb(s_in, s_out, 1, key, enclen);

    // clean up
    fclose(s_in);
    fclose(s_out);
    free(inbuf);

    return 1;
}

/**
 * Detect the minimal block size of ECB. The input contains at the start
 * two neighbouring blocks with the same data. Determine the size of the
 * block.
 *
 * @param buf input
 * @param length of the input
 *
 * @returns block size or 0
 */
unsigned int detect_block_size(byte *buf, size_t length) {
    uint8_t BLOCK_SIZE = 0;
    size_t max_size = floor((length/2));
    size_t i;


    for (i=1;i<=max_size;i++) {
        if (bcmp(buf + 0*i, buf + 1*i, i) == 0) {
            BLOCK_SIZE=i;
            break;
        }
    }

    return BLOCK_SIZE;
}


int main(int argc, char** argv) {

    uint8_t * data = NULL;
    size_t inlen;
    // max extra data from oracle, plus 1 block of padding
    size_t outlen = 8192;
    size_t enclen = 0;
    size_t block_size = 0;
    size_t i, j;
    uint8_t *out;
    uint8_t *search;
    uint8_t ok = 0;

    out = calloc(outlen, sizeof(uint8_t));

    oracle(data, 0, out, outlen, &enclen);
    data = calloc(enclen, sizeof(uint8_t));
    inlen = enclen;
    for (i=1;i < inlen; i++) {
        oracle(data, 2*i, out, outlen, &enclen);
        block_size = detect_block_size(out, enclen);
        if (block_size > 0
                && detect_ecb(out, enclen, block_size)) {
            ok = 1;
            printf("block size: %zu\n", block_size);
            break;
        }
    }
    
    if (ok) {
        search = calloc(inlen, sizeof(uint8_t));

        uint8_t k;
        for (j = inlen-1; j > 0; j--) {
            k = inlen - 1;
            // generate data to search for
            oracle(data, j, out, outlen, &enclen);

            // store search
            memcpy(search, out, inlen);

            // try each ascii char & cmp with search
            uint8_t c=0;
            for (c=1; c < 128; c++) {

                // modify data to contain current char
                data[k] = c;
                /* printf(format, data); */

                // encrypt
                oracle(data, inlen, out, outlen, &enclen);

                // compare
                if (bcmp(search, out, inlen) == 0) {
                    printf("%c", c);
                    for (k=j;k<inlen;k++) {
                        data[k-1] = data[k];
                    }
                    break;
                }
            }
        }
        printf("\n");

        free(search);
    }

    free(data);
    free(out);

    return 0;
}

