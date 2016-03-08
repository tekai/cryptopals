#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "crypto.h"

int main(int argc, char** argv) {

    char buf[33+1];
    strcpy(buf, "YELLOW SUBMARINE");
    pkcs7_pad(buf, 15);
    printf("%lu %s\n", strlen(buf),buf);
    return 0;
}

