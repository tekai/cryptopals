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
    size_t length = 17; // names + 2& + 3= + 0
    char * uid;
    char * encoded = NULL;

    length += strlen(user->email);
    length += asprintf(&uid, "%zu", user->uid);
    length += strlen(user->role);

    encoded = calloc(length, sizeof(char));
    strcat(encoded, "email=");
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
    strncpy(user->role, "user", 5);

    char * str = encode_user(user);

    free(user);

    return str;
}

int oracle(char * email, uint8_t * out, size_t *outlen) {
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
/*
task: decrypt input and create an encrypted profile with role=admin
assumption: I only get the oracle and the encrypted string.
decrypting: when trying to figure out the block size, we'll find that block 2 & 3 will be the same and we need 2*block_size + block_size.
create admin: create blocks with the needed data, stretch email so "&role=" is in one block, "user" is in the next, replace next with a block "admin"
 */
int decrypt_oracle(uint8_t * input, size_t inlen) {

    char * data = NULL;
    // max extra data from oracle, plus 1 block of padding
    size_t outlen = 8192;
    size_t l;
    size_t block_size;
    size_t prefix, postfix;
    size_t i, k;
    uint8_t c;
    uint8_t *out;
    uint8_t *search;
    int ok = 0;

    out = calloc(outlen, sizeof(uint8_t));
    search = calloc(inlen, sizeof(uint8_t));
    // 4*inlen because inlen could be block_size and we need to add two
    // identical blocks but 3 is uneven, so 4 it is
    data = calloc(4*inlen+1, sizeof(uint8_t));
    for (i = 0; i < 4*inlen; i++) {
        data[i] = 'A';
    }
    data[4*inlen] = 0;

    for (i=1;i < 2*inlen; i++) {
        // fool strlen
        data[2*i] = 0;
        // restore old data
        data[2*(i-1)] = 'A';

        l = outlen;
        oracle(data, out, &l);

        block_size = detect_block_size(out, l, &k);
        if (block_size > 0
                && detect_ecb(out, l, block_size)) {
            printf("block size: %zu\n", block_size);
            prefix = k*block_size - (2*i - 2*block_size);
            printf("prefix: %zu\n", prefix);
            // postfix is not exact yet because of padding
            postfix = l - ((2 + k)*block_size);
            ok = 1;
            // restore full length string
            data[2*i] = 'A';
            break;
        }
    }


    // calculate exact postfix length
    // we continue the loop, but single step now
    k = l;
    for (i=2*i+1;i < 4*inlen; i++) {
        // fool strlen
        data[i] = 0;
        // restore old data
        data[i-1] = 'A';

        l = outlen;
        oracle(data, out, &l);
        if (l > k) {
            break;
        }
        postfix--;
    }
    // postfix is exact now
    printf("postfix: %zu\n", postfix);

    if (0&&ok) {
        for (i = inlen - 1; i > 0; i--) {
            k = inlen - 1;
            l = outlen;
            // generate data to search for
            oracle(data, out, &l);

            // store search
            memcpy(search, out, inlen);

            // try each ascii char & cmp with search
            for (c=1; c < 128; c++) {

                // modify data to contain current char
                data[k] = c;

                // encrypt
                l = outlen;
                oracle(data, out, &l);

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
    }

    // cleanup
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
    oracle(email, out, &outlen);

    decrypt_oracle(out, outlen);

    free(out);
}
