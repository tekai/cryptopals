#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <math.h>

#include "crypto.h"
#include "fmemopen.h"

typedef struct _user {
    char email[256];
    size_t uid;
    char role[5];
} USER;


USER* decode_user(char kv) {
    USER * user = malloc(sizeof(USER));
    return user;
}

char* encode_user(USER* user) {
    size_t length = 17; // names + 2& + 3=
    char * uid;
    char * encoded = NULL;

    length += strlen(user->email);
    length += asprintf(&uid, "%zu", user->uid);
    length += strlen(user->role);

    encoded = malloc(length*sizeof(char));

    strcat(encoded, "user=");
    strcat(encoded, user->email);
    strcat(encoded, "&uid=");
    strcat(encoded, uid);
    strcat(encoded, "&role=");
    strcat(encoded, user->role);

    free(uid);

    return encoded;
}

char* profile_for(char * email) {
    USER * user = malloc(sizeof(USER));
    strncpy(user->email, email, 256);
    user->uid = 10;
    strcat(user->role, "user");

    char * str = encode_user(user);

    free(user);

    return str;
}

int oracle(char * email, size_t inlen, uint8_t * out, size_t *outlen) {
    char * data = profile_for(email);
    uint8_t key[] = "Yellow Subm4r1ne";
    FILE *s_in, *s_out;

    s_in  = fmemopen(data, strlen(data), "r");
    s_out = fmemopen(out, *outlen, "w");

    // encrypt
    aes_128_ecb(s_in, s_out, 1, key, outlen);

    // clean up
    fclose(s_out);
    fclose(s_in);
    free(data);

    return 1;
}

int decrypt_oracle(uint8_t * input, size_t inlen) {

    char * data = NULL;
    // max extra data from oracle, plus 1 block of padding
    size_t outlen = 8192;
    size_t i, k;
    uint8_t c;
    uint8_t *out;
    uint8_t *search;

    out = calloc(outlen, sizeof(uint8_t));
    search = calloc(inlen, sizeof(uint8_t));
    data = calloc(inlen, sizeof(uint8_t));
    for (i = inlen; i < inlen; i++) {
        data[i] = 'A';
    }
    for (i = inlen - 1; i > 0; i--) {
        k = inlen - 1;
        // generate data to search for
        oracle(data, i, out, &outlen);

        // store search
        memcpy(search, out, inlen);

        // try each ascii char & cmp with search
        for (c=1; c < 128; c++) {

            // modify data to contain current char
            data[k] = c;

            // encrypt
            oracle(data, inlen, out, &outlen);

            // compare
            if (bcmp(search, out, inlen) == 0) {
                printf("%c", c);
                for (k=i;k<inlen;k++) {
                    data[k-1] = data[k];
                }
                break;
            }
        }
    }
    printf("\n");

    free(search);

    free(data);
    free(out);

    return 0;
}

int main(int argc, char** argv) {
    char email[] = "user@example.org";
    size_t outlen = 2048;
    uint8_t * out;

    out = calloc(outlen, sizeof(uint8_t));
    oracle(email, strlen(email), out, &outlen);

    decrypt_oracle(out, outlen);

    free(out);
}
