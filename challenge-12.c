#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <math.h>

#include "crypto.h"
#include "fmemopen.h"

int oracle(uint8_t *in, size_t inlen, uint8_t *out, size_t * outlen) {
    uint8_t buf[8192];
    uint8_t key[16];
    size_t b64len = 0;
    FILE *s_in, *s_out;
    const unsigned char b64[] =
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\n"
        "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\n"
        "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\n"
        "YnkK";


    base64_decode(b64, strlen(b64), buf, &b64len);

    unhex("d9a6ef8423d06d3fc69795e75494114a", key, 16);

    uint8_t *inbuf = malloc((inlen+b64len)*sizeof(uint8_t));

    memcpy(inbuf, in, inlen);
    memcpy(inbuf+inlen, buf, b64len);

    s_in  = fmemopen(inbuf, inlen+b64len, "r");
    s_out = fmemopen(out, *outlen, "w");
    aes_128_ecb(s_in, s_out, 1, key);

    fclose(s_in);
    fclose(s_out);

    return 1;
}

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

    uint8_t data[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    uint8_t format[] = "AAAAAAAAAAAAAAAA";
    size_t inlen  = strlen((char*)data);
    // max extra data from oracle, plus 1 block of padding
    size_t outlen = 8192;
    size_t block_size = 0;
    size_t i, j;
    uint8_t *out;
    uint8_t *search;
    uint8_t ok = 0;

    out = calloc(outlen, sizeof(uint8_t));

    for (i=1;i < inlen/2; i++) {
        oracle(data, 2*i, out, &outlen);
        block_size = detect_block_size(out, outlen);
        if (block_size > 0
                && detect_ecb(out, outlen, block_size)) {
            ok = 1;
            printf("block size: %zu\n", block_size);
            break;
        }
    }
    if (ok) {
        sprintf(format, "\ndata: %%1.%zus\n", block_size);
        search = calloc(block_size, sizeof(uint8_t));

        uint8_t k;
        for (j = block_size-1; j > 0; j--) {
            k = block_size - 1;
            // generate data to search for
            oracle(data, j, out, &outlen);

            // store search
            memcpy(search, out, block_size);

            // try each ascii char & cmp with search
            uint8_t c=0;
            for (c=1; c < 128; c++) {

                // modify data to contain current char
                data[k] = c;
                /* printf(format, data); */

                // encrypt
                oracle(data, block_size, out, &outlen);

                // compare
                if (memcmp(search, out, block_size) == 0) {
                    printf("%c", c, c);
                    for (k=j;k<block_size;k++) {
                        data[k-1] = data[k];
                    }
                    break;
                }
            }
        }
        printf("\n");

        free(search);
    }
    /* char * hex = malloc((outlen*2+1)*sizeof(char)); */
    /* hex[outlen*2] = '\0'; */
    /* dohex(out, hex, outlen); */
    /* puts(hex); */

    free(out);
    /* free(hex); */
    return 0;
}

