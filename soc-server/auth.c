#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <crypt.h>
#include <time.h>
#include <arpa/inet.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "auth.h"

#define WHITELIST_PATH "/etc/soc/whitelist.conf"
#define USERS_PATH "/etc/soc/users.conf"

// Session signing secret (randomized on daemon startup)
static uint8_t session_secret[32];
static int secret_initialized = 0;

// Whitelisted Subnets
struct whitelist_entry {
    uint32_t ip;
    uint8_t mask;
};

static struct whitelist_entry whitelist[256];
static int whitelist_count = 0;

int auth_init(void) {
    // 1. Initialize random session secret
    if (!secret_initialized) {
        if (RAND_bytes(session_secret, sizeof(session_secret)) != 1) {
            // Fallback if OpenSSL RAND fails
            srand(time(NULL));
            for (int i = 0; i < 32; i++) session_secret[i] = rand() % 256;
        }
        secret_initialized = 1;
    }

    // 2. Load whitelist
    whitelist_count = 0;
    FILE *f = fopen(WHITELIST_PATH, "r");
    if (f) {
        char line[128];
        while (fgets(line, sizeof(line), f) && whitelist_count < 256) {
            char *ip_str = strtok(line, " \t\r\n");
            if (!ip_str || ip_str[0] == '#' || ip_str[0] == '\0') continue;

            // Parse CIDR
            char *slash = strchr(ip_str, '/');
            int mask = 32;
            if (slash) {
                *slash = '\0';
                mask = atoi(slash + 1);
            }

            struct in_addr addr;
            if (inet_pton(AF_INET, ip_str, &addr) == 1) {
                whitelist[whitelist_count].ip = addr.s_addr;
                whitelist[whitelist_count].mask = (uint8_t)mask;
                whitelist_count++;
            }
        }
        fclose(f);
        printf("[auth] Loaded %d whitelisted subnets\n", whitelist_count);
    } else {
        // Fallback: If no whitelist file, allow localhost by default so it's usable
        struct in_addr addr;
        inet_pton(AF_INET, "127.0.0.1", &addr);
        whitelist[0].ip = addr.s_addr;
        whitelist[0].mask = 32;
        whitelist_count = 1;
        printf("[auth] Whitelist file not found. Defaulted to allowing 127.0.0.1\n");
    }

    return 0;
}

int auth_check_ip(const char *ip) {
    struct in_addr client_addr;
    if (inet_pton(AF_INET, ip, &client_addr) != 1) {
        return 0; // Invalid IP format is blocked
    }

    // Loop through whitelist
    for (int i = 0; i < whitelist_count; i++) {
        uint32_t mask_val = whitelist[i].mask == 0 ? 0 : (~0U << (32 - whitelist[i].mask));
        if (whitelist[i].mask == 32) {
            if (whitelist[i].ip == client_addr.s_addr) return 1;
        } else {
            uint32_t masked_client = ntohl(client_addr.s_addr) & mask_val;
            uint32_t masked_wl = ntohl(whitelist[i].ip) & mask_val;
            if (masked_client == masked_wl) return 1;
        }
    }

    return 0; // Not found in whitelist
}

int auth_verify_login(const char *username, const char *password) {
    FILE *f = fopen(USERS_PATH, "r");
    if (!f) {
        perror("[auth] Failed to open users file");
        return -1;
    }

    char line[256];
    int success = -1;

    while (fgets(line, sizeof(line), f)) {
        char *user_part = strtok(line, ":");
        char *hash_part = strtok(NULL, " \t\r\n");

        if (user_part && hash_part && strcmp(user_part, username) == 0) {
            // Verify password using glibc crypt()
            // crypt() handles bcrypt ($2a$, $2y$, etc.) if passed as the hash settings
            char *crypt_res = crypt(password, hash_part);
            if (crypt_res && strcmp(crypt_res, hash_part) == 0) {
                success = 0; // Match!
            }
            break;
        }
    }
    fclose(f);
    return success;
}

void auth_generate_session_token(const char *username, char *token_out, size_t max_len) {
    time_t expiry = time(NULL) + (8 * 3600); // 8 hours expiry
    char message[256];
    snprintf(message, sizeof(message), "%s:%lld", username, (long long)expiry);

    // Compute HMAC-SHA256
    unsigned int hmac_len = 0;
    uint8_t hmac_res[32];
    HMAC(EVP_sha256(), session_secret, sizeof(session_secret), 
         (unsigned char *)message, strlen(message), hmac_res, &hmac_len);

    char hmac_hex[65];
    for (int i = 0; i < 32; i++) {
        sprintf(hmac_hex + (i * 2), "%02x", hmac_res[i]);
    }
    hmac_hex[64] = '\0';

    snprintf(token_out, max_len, "%s:%lld:%s", username, (long long)expiry, hmac_hex);
}

int auth_verify_session_token(const char *token, char *username_out, size_t max_len) {
    char token_copy[512];
    strncpy(token_copy, token, sizeof(token_copy) - 1);
    token_copy[sizeof(token_copy) - 1] = '\0';

    char *username = strtok(token_copy, ":");
    char *expiry_str = strtok(NULL, ":");
    char *token_hmac = strtok(NULL, " \t\r\n");

    if (!username || !expiry_str || !token_hmac) return -1;

    // Check expiry
    time_t expiry = (time_t)atoll(expiry_str);
    if (time(NULL) >= expiry) {
        return -1; // Expired
    }

    // Recompute HMAC
    char message[256];
    snprintf(message, sizeof(message), "%s:%lld", username, (long long)expiry);

    unsigned int hmac_len = 0;
    uint8_t hmac_res[32];
    HMAC(EVP_sha256(), session_secret, sizeof(session_secret), 
         (unsigned char *)message, strlen(message), hmac_res, &hmac_len);

    char expected_hmac[65];
    for (int i = 0; i < 32; i++) {
        sprintf(expected_hmac + (i * 2), "%02x", hmac_res[i]);
    }
    expected_hmac[64] = '\0';

    // Verify HMAC match
    if (strcmp(expected_hmac, token_hmac) != 0) {
        return -1; // Signature mismatch (tampering detected)
    }

    strncpy(username_out, username, max_len - 1);
    username_out[max_len - 1] = '\0';
    return 0;
}
