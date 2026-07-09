#ifndef AUTH_H
#define AUTH_H

#include <stddef.h>

/**
 * Initializes authentication and IP whitelist configurations.
 * Reads /etc/soc/whitelist.conf and /etc/soc/users.conf.
 *
 * @return 0 on success, -1 on failure.
 */
int auth_init(void);

/**
 * Checks if a source IP is whitelisted.
 *
 * @param ip IP address string (e.g. "192.168.1.10").
 * @return 1 if whitelisted, 0 if blocked.
 */
int auth_check_ip(const char *ip);

/**
 * Verifies username and password using bcrypt (via glibc crypt()).
 *
 * @param username Input username.
 * @param password Input password.
 * @return 0 on success, -1 on invalid credentials.
 */
int auth_verify_login(const char *username, const char *password);

/**
 * Generates a signed session token.
 * Token format: username:expiry:signature_hex
 *
 * @param username The authenticated username.
 * @param token_out Destination buffer.
 * @param max_len Size of destination buffer.
 */
void auth_generate_session_token(const char *username, char *token_out, size_t max_len);

/**
 * Verifies a signed session token and extracts the username.
 *
 * @param token Input token string.
 * @param username_out Destination buffer for username.
 * @param max_len Size of destination buffer.
 * @return 0 on success, -1 on invalid or expired token.
 */
int auth_verify_session_token(const char *token, char *username_out, size_t max_len);

#endif // AUTH_H
