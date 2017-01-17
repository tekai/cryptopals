#ifdef __linux__
  // for uint8_t etc
  #include <stdint.h>
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>

#include "crypto.h"

int main(int argc, char** argv) {
    char str1[] = "1c0111001f010100061a024b53535009181c";
    char str2[] = "686974207468652062756c6c277320657965";
    uint8_t *raw1, *raw2;
    char *out;
    size_t len = strlen(str1);
    raw1 = malloc((len/2)*sizeof(uint8_t));
    raw2 = malloc((len/2)*sizeof(uint8_t));
    unhex(str1,raw1,len);
    unhex(str2,raw2,len);


    arr_xor(raw1, raw2, len/2);
    out = malloc((len+1)*sizeof(char));
    dohex(raw1, out, len/2);
    out[len] = '\0';

    printf("%s\n", out);
    free(raw1);
    free(raw2);
    free(out);
    return 0;
}


