#ifndef PGP_WRAPPER_H
#define PGP_WRAPPER_H

#include <stddef.h>

/**
 * Encrypts a plaintext buffer using PGP (via gpg cli).
 *
 * @param plaintext Binary or text data to encrypt.
 * @param plaintext_len Length of the plaintext.
 * @param ciphertext Pointer to be set to the newly allocated ciphertext buffer (armor text).
 *                   Must be freed by the caller using free().
 * @param ciphertext_len Set to the length of the ciphertext buffer.
 * @return 0 on success, -1 on failure.
 */
int pgp_encrypt(const void *plaintext, size_t plaintext_len, char **ciphertext, size_t *ciphertext_len);

/**
 * Decrypts a PGP armored ciphertext buffer (via gpg cli).
 *
 * @param ciphertext PGP armored string.
 * @param ciphertext_len Length of the ciphertext.
 * @param plaintext Pointer to be set to the newly allocated decrypted binary payload.
 *                  Must be freed by the caller using free().
 * @param plaintext_len Set to the length of the decrypted payload.
 * @return 0 on success, -1 on failure.
 */
int pgp_decrypt(const char *ciphertext, size_t ciphertext_len, void **plaintext, size_t *plaintext_len);

#endif // PGP_WRAPPER_H
