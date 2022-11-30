#include "shared.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define BUFSIZE 1024

#define ERR_EVP_CIPHER_INIT -1
#define ERR_EVP_CIPHER_UPDATE -2
#define ERR_EVP_CIPHER_FINAL -3
#define ERR_EVP_CTX_NEW -4

void cleanup(FILE *ifp, FILE *ofp, int rc){
    fclose(ifp);
    fclose(ofp);
    exit(rc);
}

void printOpenSSLError()
{
    BIO *bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);
    char *buf;
    size_t len = BIO_get_mem_data(bio, &buf);
    fwrite(buf,1,len,stderr);
    BIO_free(bio);
}

void do_crypt(FILE *ifp, FILE *ofp, const EVP_CIPHER* cipher_type, unsigned char key[], unsigned char iv[], int encrypt)
{
    int cipher_block_size = EVP_CIPHER_block_size(cipher_type);
    unsigned char in_buf[BUFSIZE], out_buf[BUFSIZE + cipher_block_size];

    int num_bytes_read, out_len;
    EVP_CIPHER_CTX *ctx;

    ctx = EVP_CIPHER_CTX_new();
    if(ctx == NULL){
        fprintf(stderr, "ERROR: EVP_CIPHER_CTX_new failed. OpenSSL error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        cleanup(ifp, ofp, ERR_EVP_CTX_NEW);
    }

    if(!EVP_CipherInit_ex(ctx, cipher_type, NULL, key, iv, encrypt)){
        printOpenSSLError();
        fprintf(stderr, "ERROR: Second EVP_CipherInit_ex failed. OpenSSL error: %s\n",
                ERR_reason_error_string(ERR_get_error()));
        EVP_CIPHER_CTX_cleanup(ctx);
        cleanup(ifp, ofp, ERR_EVP_CIPHER_INIT);
    }

    while(1){
        num_bytes_read = fread(in_buf, sizeof(unsigned char), BUFSIZE, ifp);
        if (ferror(ifp)){
            fprintf(stderr, "ERROR: fread error: %s\n", strerror(errno));
            EVP_CIPHER_CTX_cleanup(ctx);
            cleanup(ifp, ofp, errno);
        }
        if(!EVP_CipherUpdate(ctx, out_buf, &out_len, in_buf, num_bytes_read)){
            fprintf(stderr, "ERROR: EVP_CipherUpdate failed. OpenSSL error: %s\n",
                    ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_cleanup(ctx);
            cleanup(ifp, ofp, ERR_EVP_CIPHER_UPDATE);
        }
        fwrite(out_buf, sizeof(unsigned char), out_len, ofp);
        if (ferror(ofp)) {
            fprintf(stderr, "ERROR: fwrite error: %s\n", strerror(errno));
            EVP_CIPHER_CTX_cleanup(ctx);
            cleanup(ifp, ofp, errno);
        }
        if (num_bytes_read < BUFSIZE) {
            break;
        }
    }

    if(!EVP_CipherFinal_ex(ctx, out_buf, &out_len)){
        fprintf(stderr, "ERROR: EVP_CipherFinal_ex failed. OpenSSL error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_cleanup(ctx);
        cleanup(ifp, ofp, ERR_EVP_CIPHER_FINAL);
    }
    fwrite(out_buf, sizeof(unsigned char), out_len, ofp);
    if (ferror(ofp)) {
        fprintf(stderr, "ERROR: fwrite error: %s\n", strerror(errno));
        EVP_CIPHER_CTX_cleanup(ctx);
        cleanup(ifp, ofp, errno);
    }
    EVP_CIPHER_CTX_cleanup(ctx);
}
