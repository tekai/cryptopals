#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "crypto.h"

int main(int argc, char** argv) {

    char buf[33+1];
    buf[33] = '\0';
    strcpy(buf, "YELLOW SUBMARINE");
    pkcs7_pad((uint8_t *)buf, (uint8_t) strlen(buf), 30);
    printf("%lu %.33s\n", strlen(buf), buf);
    return 0;
}

