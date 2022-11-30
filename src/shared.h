#ifndef SHARED_H_
#define SHARED_H_
#include <stdio.h>
#include <openssl/evp.h>

void do_crypt(FILE *ifp, FILE *ofp, const EVP_CIPHER* cipher_type, unsigned char key[], unsigned char iv[], int encrypt);


#endif // SHARED_H_
