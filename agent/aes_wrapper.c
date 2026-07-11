#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "aes_wrapper.h"

#define AES_KEY_SIZE 32
#define AES_BLOCK_SIZE 16

static const unsigned char aes_key[AES_KEY_SIZE] = "nullsploit_secure_aes_key_2026!";

int aes_encrypt(const void *plaintext, size_t plaintext_len, char **ciphertext, size_t *ciphertext_len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -1;
    }

    unsigned char iv[AES_BLOCK_SIZE];
    if (RAND_bytes(iv, AES_BLOCK_SIZE) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int max_cipher_len = (int)plaintext_len + AES_BLOCK_SIZE;
    unsigned char *out_buf = malloc(AES_BLOCK_SIZE + max_cipher_len);
    if (!out_buf) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Prepend IV to ciphertext
    memcpy(out_buf, iv, AES_BLOCK_SIZE);

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv) != 1) {
        free(out_buf);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len = 0;
    int total_cipher_len = 0;
    if (EVP_EncryptUpdate(ctx, out_buf + AES_BLOCK_SIZE, &len, (const unsigned char *)plaintext, (int)plaintext_len) != 1) {
        free(out_buf);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_cipher_len += len;

    if (EVP_EncryptFinal_ex(ctx, out_buf + AES_BLOCK_SIZE + total_cipher_len, &len) != 1) {
        free(out_buf);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_cipher_len += len;

    EVP_CIPHER_CTX_free(ctx);

    *ciphertext = (char *)out_buf;
    *ciphertext_len = AES_BLOCK_SIZE + total_cipher_len;
    return 0;
}

int aes_decrypt(const char *ciphertext, size_t ciphertext_len, void **plaintext, size_t *plaintext_len) {
    if (ciphertext_len < AES_BLOCK_SIZE) {
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -1;
    }

    unsigned char iv[AES_BLOCK_SIZE];
    memcpy(iv, ciphertext, AES_BLOCK_SIZE);

    const unsigned char *actual_ciphertext = (const unsigned char *)ciphertext + AES_BLOCK_SIZE;
    int actual_cipher_len = (int)ciphertext_len - AES_BLOCK_SIZE;

    unsigned char *out_buf = malloc(actual_cipher_len + AES_BLOCK_SIZE);
    if (!out_buf) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv) != 1) {
        free(out_buf);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len = 0;
    int total_plain_len = 0;
    if (EVP_DecryptUpdate(ctx, out_buf, &len, actual_ciphertext, actual_cipher_len) != 1) {
        free(out_buf);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_plain_len += len;

    if (EVP_DecryptFinal_ex(ctx, out_buf + total_plain_len, &len) != 1) {
        free(out_buf);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_plain_len += len;

    EVP_CIPHER_CTX_free(ctx);

    *plaintext = out_buf;
    *plaintext_len = (size_t)total_plain_len;
    return 0;
}
