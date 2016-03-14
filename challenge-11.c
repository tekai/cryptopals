#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>

#include "crypto.h"
#include "fmemopen.h"

int oracle(uint8_t *in, size_t inlen, uint8_t *out, size_t * outlen) {
    uint8_t key[16];
    uint8_t iv[16];

    int padl = rand() % 6 + 5;
    int padr = rand() % 6 + 5;
    uint8_t * inbuf = malloc((inlen+padr+padl)*sizeof(uint8_t));
    FILE *s_in  = fmemopen(in, inlen, "r");
    FILE *s_out = fmemopen(out, *outlen, "w");
    *outlen = inlen;
    if (inlen % 16 == 0) {
        *outlen += 16;
    }
    else {
        *outlen += inlen % 16;
    }
    arc4random_buf(key, 16);

    if (rand()%2) {
        aes_128_ecb(s_in, s_out, 1, key);
    }
    else {
        arc4random_buf(iv, 16);
        aes_128_cbc(s_in, s_out, 1, key, iv);
    }
    fclose(s_in);
    fclose(s_out);
    return 1;
}



int main(int argc, char** argv) {
    sranddev();
    /* uint8_t data[] = "Du bist so dumm, du bringst sogar deinem eigenem Hund die Zeitung"; */
    uint8_t data[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    size_t inlen=strlen((char*)data);
    size_t outlen=(inlen+20+16)*sizeof(uint8_t);

    uint8_t *out;
    out = calloc(1, outlen);
    oracle(data, inlen, out, &outlen);
    if (detect_ecb(out, outlen)) {
        puts("ECB was used");
    }
    else {
        puts("CBC was used");
    }
    char * hex = malloc((outlen*2+1)*sizeof(char));
    hex[outlen*2] = '\0';
    dohex(out, hex, outlen);
    puts(hex);

    free(out);
    free(hex);
    return 0;
}

