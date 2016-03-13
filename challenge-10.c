#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>

#include "crypto.h"

int main(int argc, char** argv) {
    FILE *in;
    FILE *out;
    int encrypt = 1;
    uint8_t f_start = 1;

    if (argc > 1 && 0 == strcmp("-d", argv[1])) {
        encrypt = 0;
        f_start++;
    }
    // INPUT
    if (argc > f_start) {
        if (access( argv[f_start], R_OK ) != -1 ) {
            in = fopen(argv[f_start], "r");
        }
        else if (0 == strcmp("-", argv[f_start])) {
            in = stdin;
        }
        else {
            fprintf(stderr, "Can't open input: %s\n", argv[f_start]);
            return 1;
        }
    }
    else {
        in = stdin;
    }
    // OUTPUT
    if (argc > f_start+1) {
        if( access( argv[f_start+1], R_OK ) != -1 ) {
            out = fopen(argv[f_start+1], "w");
        } else {
            fprintf(stderr, "Can't open output: %s\n", argv[2]);
            return 1;
        }
    }
    else {
        out = stdout;
    }

    aes_cbc(in, out, encrypt);
    fclose(in);
    fclose(out);

    return 0;
}


