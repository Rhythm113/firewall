#ifndef AES_WRAPPER_H
#define AES_WRAPPER_H

#include <stddef.h>

/**
 * Encrypts a plaintext buffer using AES-256-CBC.
 * Generates a random IV and prepends it to the ciphertext.
 *
 * @param plaintext Binary or text data to encrypt.
 * @param plaintext_len Length of the plaintext.
 * @param ciphertext Pointer to be set to the newly allocated ciphertext buffer.
 *                   Must be freed by the caller using free().
 * @param ciphertext_len Set to the length of the ciphertext buffer (including IV).
 * @return 0 on success, -1 on failure.
 */
int aes_encrypt(const void *plaintext, size_t plaintext_len, char **ciphertext, size_t *ciphertext_len);

/**
 * Decrypts an AES-256-CBC ciphertext buffer.
 * Extracts the IV from the beginning of the ciphertext buffer.
 *
 * @param ciphertext AES-256-CBC ciphertext bytes.
 * @param ciphertext_len Length of the ciphertext.
 * @param plaintext Pointer to be set to the newly allocated decrypted binary payload.
 *                  Must be freed by the caller using free().
 * @param plaintext_len Set to the length of the decrypted payload.
 * @return 0 on success, -1 on failure.
 */
int aes_decrypt(const char *ciphertext, size_t ciphertext_len, void **plaintext, size_t *plaintext_len);

#endif // AES_WRAPPER_H
