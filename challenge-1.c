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
    char hex[] = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";

    uint8_t * raw;
    char * b64 = NULL;
    size_t hexlen = strlen(hex);
    raw = malloc((hexlen/2)*sizeof(uint8_t));
    unhex(hex,raw,hexlen);
    base64_encode(raw, hexlen/2, &b64);
    printf("%s\n  becomes\n%s\n", hex, b64);
    free(raw);
    return 0;
}


