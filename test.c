#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "crypto.h"

int main(int argc, char** argv) {
    uint8_t in[] = {'\xff', '\xfe'};
    char out[5] = "aabb";
    dohex(in, out, 2); 
    printf("%x%x = %s\n", in[0], in[1], out);
    return 1;
    char bla[] = "Fuck";
    printf("%lu %lu\n", strlen(bla), sizeof(bla));
    return 1;
    fprintf(stdout, "ARGC: %d\n", argc);
    while (argc--) {
        fprintf(stdout, "ARGV[%d]: %s\n", argc, argv[argc]);
    }
    return 1;
}
