#ifndef PGP_WRAPPER_H
#define PGP_WRAPPER_H

#include <stddef.h>

int pgp_encrypt(const void *plaintext, size_t plaintext_len, char **ciphertext, size_t *ciphertext_len);
int pgp_decrypt(const char *ciphertext, size_t ciphertext_len, void **plaintext, size_t *plaintext_len);

#endif // PGP_WRAPPER_H
