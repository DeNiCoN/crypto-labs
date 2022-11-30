#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "shared.h"
#include <openssl/rand.h>

void print_usage(int argc, char* argv[]) {
    printf("Usage:\n%s file key_file\nPrints encrypted file into stdout", argv[0]);
}

int main(int argc, char* argv[]) {
    const EVP_CIPHER* cipher = EVP_aes_128_cbc();
    unsigned char iv[EVP_CIPHER_iv_length(cipher)];
    unsigned char key[EVP_CIPHER_key_length(cipher)];

    if (argc < 3) {
        print_usage(argc, argv);
        return 1;
    }

    FILE* input;
    if (strcmp(argv[1], "-") == 0) {
        input = stdin;
    } else {
        input = fopen(argv[1], "rb");
    }

    if (!input) {
        fprintf(stderr, "ERROR: input fopen error: %s\n", strerror(errno));
        return errno;
    }

    FILE* key_file = fopen(argv[2], "rb");
    if (!key_file) {
        fprintf(stderr, "ERROR: key fopen error: %s\n", strerror(errno));
        return errno;
    }

    if (!fread(key, sizeof(key), 1, key_file)) {
        fprintf(stderr, "ERROR: key fopen error: %s\n", strerror(errno));
        if(ferror(key_file)) {
            perror("Key read error");
            return 1;
        }
        if(feof(key_file)) {
            perror("Key end of file error");
            return 1;
        }
    }

    if (!RAND_bytes(iv, sizeof(iv))) {
        fprintf(stderr, "ERROR: RAND_bytes error: %s\n", strerror(errno));
        return errno;
    }

    do_crypt(input, stdout, cipher, key, iv, 1);

    fclose(input);

    return 0;
}
