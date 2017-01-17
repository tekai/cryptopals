#ifdef __linux__
  // for uint8_t etc
  #include <stdint.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "crypto.h"

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
            out = fopen(argv[2], "w");
        } else {
            fprintf(stderr, "Can't open output: %s\n", argv[1]);
            return 1;
        }
    }
    else {
        out = stdout;
    }

    do_crypt(in, out, 0);
    fclose(in);
    fclose(out);

    return 0;
}

