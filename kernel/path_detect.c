#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "path_detect.h"

// Helper to URL decode a string
static int url_decode(const char *src, int src_len, char *dst, int dst_len) {
    int i = 0, j = 0;
    while (i < src_len && j < dst_len - 1) {
        if (src[i] == '%' && i + 2 < src_len && isxdigit(src[i+1]) && isxdigit(src[i+2])) {
            char hex[3] = { src[i+1], src[i+2], '\0' };
            dst[j++] = (char)strtol(hex, NULL, 16);
            i += 3;
        } else if (src[i] == '+') {
            dst[j++] = ' ';
            i++;
        } else {
            dst[j++] = src[i++];
        }
    }
    dst[j] = '\0';
    return j;
}

// Case-insensitive substring match
static const char *strcase_contains(const char *haystack, const char *needle) {
    int needle_len = strlen(needle);
    if (needle_len == 0) return haystack;
    
    while (*haystack) {
        int match = 1;
        for (int i = 0; i < needle_len; i++) {
            if (!haystack[i] || tolower((unsigned char)haystack[i]) != tolower((unsigned char)needle[i])) {
                match = 0;
                break;
            }
        }
        if (match) return haystack;
        haystack++;
    }
    return NULL;
}

int detect_path_traversal(const char *payload, int payload_len, 
                          char *matched_pattern, int max_pattern_len, 
                          char *details, int max_details_len) {
    
    char decoded[4096];
    int dec_len = url_decode(payload, payload_len, decoded, sizeof(decoded));

    // Try double decoding if '%' is still found
    if (strchr(decoded, '%')) {
        char temp[4096];
        memcpy(temp, decoded, dec_len + 1);
        dec_len = url_decode(temp, dec_len, decoded, sizeof(decoded));
    }

    int score = 0;
    matched_pattern[0] = '\0';
    details[0] = '\0';

    // 1. Look for traversal sequences: ../ or ..\ or overlong UTF-8 variants like %c0%ae%c0%ae/
    int traversal_count = 0;
    const char *ptr = decoded;
    while ((ptr = strstr(ptr, "../")) != NULL) {
        traversal_count++;
        ptr += 3;
    }
    ptr = decoded;
    while ((ptr = strstr(ptr, "..\\")) != NULL) {
        traversal_count++;
        ptr += 3;
    }
    ptr = decoded;
    while ((ptr = strstr(ptr, "..;")) != NULL) { // bypass attempt
        traversal_count++;
        ptr += 3;
    }

    // 2. Check for LFI sensitive target paths/files
    const char *lfi_targets[] = {
        "/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/group", "/etc/issue",
        "/proc/self/", "/proc/version", "/proc/cmdline",
        "/var/log/apache", "/var/log/nginx", "/var/log/httpd", "/var/log/auth.log",
        "boot.ini", "win.ini", "system.ini", "web.config"
    };
    int num_lfi_targets = sizeof(lfi_targets) / sizeof(lfi_targets[0]);
    int lfi_match = 0;
    for (int i = 0; i < num_lfi_targets; i++) {
        if (strcase_contains(decoded, lfi_targets[i])) {
            lfi_match = 1;
            break;
        }
    }

    // 3. Check for PHP wrappers
    const char *php_wrappers[] = {
        "php://filter", "php://input", "php://output", "php://temp",
        "data://text", "data:text/html", "zip://", "phar://", "expect://"
    };
    int num_wrappers = sizeof(php_wrappers) / sizeof(php_wrappers[0]);
    int wrapper_match = 0;
    for (int i = 0; i < num_wrappers; i++) {
        if (strcase_contains(decoded, php_wrappers[i])) {
            wrapper_match = 1;
            break;
        }
    }

    // 4. Check for RFI (Remote File Inclusion)
    // E.g., looking for external resources inside parameter assignments: file=http://evil.com/shell.txt
    // We check if "http://" or "https://" or "ftp://" occurs.
    // If it starts with "/" or "http" occurs at the start of a value after "="
    int rfi_match = 0;
    const char *http_idx = strstr(decoded, "http://");
    if (!http_idx) http_idx = strstr(decoded, "https://");
    if (!http_idx) http_idx = strstr(decoded, "ftp://");

    if (http_idx) {
        // Confirm if it looks like an inclusion parameter (preceded by "=" or part of query parameters)
        // If it's a parameter value, it usually has a "=" or "/" before it in HTTP query parameters
        // Or if it's the start of the payload
        if (http_idx == decoded || (http_idx > decoded && *(http_idx - 1) == '=')) {
            rfi_match = 1;
        }
    }

    // Accumulate scores
    if (traversal_count > 0) {
        score += (traversal_count * 15); // 15 points per traversal depth
        strncat(matched_pattern, "TRAVERSAL; ", max_pattern_len - strlen(matched_pattern) - 1);
    }

    if (lfi_match) {
        score += 35;
        strncat(matched_pattern, "LFI_TARGET; ", max_pattern_len - strlen(matched_pattern) - 1);
    }

    if (wrapper_match) {
        score += 45;
        strncat(matched_pattern, "PHP_WRAPPER; ", max_pattern_len - strlen(matched_pattern) - 1);
    }

    if (rfi_match) {
        score += 45;
        strncat(matched_pattern, "RFI_HTTP; ", max_pattern_len - strlen(matched_pattern) - 1);
    }

    // Null byte injection attempt
    if (strstr(payload, "%00") || memchr(payload, 0, payload_len)) {
        score += 15;
        strncat(matched_pattern, "NULL_BYTE; ", max_pattern_len - strlen(matched_pattern) - 1);
    }

    snprintf(details, max_details_len, "Path/LFI/RFI Score: %d. Matches: %s. Decoded: %s", 
             score, matched_pattern, decoded);

    return score;
}
