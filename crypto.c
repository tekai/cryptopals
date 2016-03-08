#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/**
 * Pad a `string' to size using PKCS#7. Assumes `string' has size+1
 * space left for padding data and is at most `size' long. 
 *
 * @param str String to be padded
 * @param size pad size
 */
int pkcs7_pad(char * string, uint8_t size) {
    uint8_t len = strlen(string);
    int d = size - len;
    uint8_t i;
    if (d<0) {
        return -1;
    }
    for (i=0;i<d;i++) {
        string[len+i] = d;
    }
    string[len+d] = '\0';

    return 1;
}
