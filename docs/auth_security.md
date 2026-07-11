# Authentication and Security

## Overview

The system implements a layered security model:

1. IP whitelist for API access
2. bcrypt password authentication
3. HMAC-SHA256 session tokens with expiry
4. PGP encryption for agent-server communication
5. Internal API key for localhost-only endpoints

## SOC Receiver Authentication (auth.c / auth.h)

### IP Whitelist (auth_init)

Loaded from /etc/soc/whitelist.conf on startup:

```
# IP whitelist configuration
127.0.0.1/32
10.0.0.0/8
192.168.0.0/16
```

- Supports CIDR notation (up to 256 entries)
- If file is missing, defaults to 127.0.0.1/32 only
- Matching uses ntohl() + bitmask in host byte order

auth_check_ip() returns 1 if the connecting IP is whitelisted.

### Password Authentication (auth_verify_login)

Users file: /etc/soc/users.conf

```
admin:$2a$12$...bcrypt_hash...
```

- Format: username:hashed_password
- Hash algorithm: bcrypt via glibc crypt()
- Lines starting with # are ignored

### Session Token Management

Token format:
```
username:expiry_timestamp:HMAC_SHA256_hex
```

- HMAC secret: 32 random bytes generated at startup via
  RAND_bytes (OpenSSL)
- Session expiry: 8 hours
- Token verified by recomputing HMAC and comparing

#### auth_generate_session_token()
1. Encode current_time + 28800 seconds (8h) as decimal string
2. Build string: "username:expiry"
3. Compute HMAC-SHA256 with secret key
4. Return "username:expiry:hex_hmac"

#### auth_verify_session_token()
1. Split token by ':'
2. Check expiry against current time
3. Recompute HMAC on "username:expiry"
4. Verify HMAC matches
5. Return username on success, NULL on failure

## Spring Boot Authentication

### WebConfig.java (Interceptor)

All /api/v2/** endpoints (except /api/v2/auth) are intercepted.

Authentication:
1. Check for X-Session-Token header or token query parameter
2. Verify token exists in the activeTokens synchronized set
3. If invalid/missing: return 401 with JSON error message

Session tokens are UUIDs generated at login:

```java
@PostMapping("/auth")
public Map<String, Object> login(@RequestBody Map<String, String> credentials) {
    if (verifyUser(username, password)) {
        String token = UUID.randomUUID().toString();
        WebConfig.activeTokens.add(token);
        return Map.of("status", "success", "token", token);
    } else {
        return Map.of("status", "failed");
    }
}
```

### Verify User (DashboardController.java)

1. Read /etc/soc/users.conf file
2. Parse username:hash lines
3. Use BCrypt.checkpw() to verify password
4. Fallback: admin/password if file doesn't exist (local dev)

## Internal Security

### Internal Push Endpoint

POST /api/v2/internal/push-event
Requires X-Internal-Key header matching "soc-receiver-forward".
Used only by the C soc_receiver daemon on localhost.

### Control Port Security

The control command port (8444) accepts TCP connections from
localhost only. No authentication is needed because the socket
is bound to 127.0.0.1.

All agent-to-SOC TCP communication on port 1113 is AES-encrypted:

- Uses symmetric AES-256-CBC encryption via OpenSSL libcrypto
- A pre-shared 256-bit key is compiled into both the agent and server
- Encryption generates a random IV that is prepended to the ciphertext
- Decryption extracts the IV from the beginning of the payload
- Avoids GnuPG process forks and keyring management issues

## CORS

The Spring Boot DashboardController has @CrossOrigin(origins = "*")
enabled, allowing cross-origin requests from any domain. This is
acceptable for the dashboard but should be restricted in production.

## Security Considerations

1. The system stores no plaintext passwords; only bcrypt hashes
   in users.conf
2. Session tokens are UUIDv4 with 8-hour expiry, stored in an
   in-memory synchronized set
3. HMAC secrets are generated fresh on each soc_receiver restart
4. The C receiver REST API uses both IP whitelist AND session tokens
5. The internal push key is hardcoded (not ideal for production;
   should be configurable)
6. Database connections use parameterized queries (PQexecParams)
   to prevent SQL injection
