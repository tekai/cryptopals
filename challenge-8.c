#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

void detect_ecb(char *buf) {
    long int len = strlen(buf);
    uint8_t chunks;
    uint8_t ** c;

    int ecb,i,j,h;
    ecb=0;
    // "shorten" the string by one, removing the \n
    buf[--len] = '\0';

    chunks = len/32;
    c = malloc(chunks*sizeof(uint8_t));
    for (i=0;i < chunks; i++) {
        h = 0;
        for (j=i+1; j < chunks; j++) {
            if (bcmp(buf + i*32, buf + j*32, 32) == 0) {
                h++;
            }
        }
        if (h) {
            ecb = 1;
        }
    }

    if (ecb) {
        for (int i=0;i < len; i+=32) {
            printf("%.*s\n", 32, buf + i);
        }
    }
    free(c);
}

int detect_ecb_lines(FILE *in) {
    char inbuf[1024];
    char * str;
    while ((str = fgets(inbuf, 1024, in))) {
        detect_ecb(inbuf);
    }
    return 0;
}

int main(int argc, char** argv) {
    FILE *in;

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

    detect_ecb_lines(in);

    fclose(in);
    return 0;
}

