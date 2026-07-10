#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "sqli_detect.h"

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

// Check case-insensitive equality
static int strcase_equals(const char *s1, const char *s2) {
    while (*s1 && *s2) {
        if (tolower((unsigned char)*s1) != tolower((unsigned char)*s2)) {
            return 0;
        }
        s1++;
        s2++;
    }
    return *s1 == '\0' && *s2 == '\0';
}

// Check if string contains substring case-insensitively
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

int detect_sqli(const char *payload, int payload_len, 
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

    // Simple Tokenizer
    #define MAX_TOKENS 128
    char tokens[MAX_TOKENS][64];
    int token_count = 0;

    int idx = 0;
    while (idx < dec_len && token_count < MAX_TOKENS) {
        // Skip whitespace
        while (idx < dec_len && isspace((unsigned char)decoded[idx])) {
            idx++;
        }
        if (idx >= dec_len) break;

        // Check if operator or comment
        if (decoded[idx] == '-' && idx + 1 < dec_len && decoded[idx+1] == '-') {
            strcpy(tokens[token_count++], "--");
            idx += 2;
            continue;
        }
        if (decoded[idx] == '/' && idx + 1 < dec_len && decoded[idx+1] == '*') {
            strcpy(tokens[token_count++], "/*");
            idx += 2;
            continue;
        }
        if (decoded[idx] == '*' && idx + 1 < dec_len && decoded[idx+1] == '/') {
            strcpy(tokens[token_count++], "*/");
            idx += 2;
            continue;
        }

        // Operators & Special chars
        if (strchr("=><!();#',\"", decoded[idx])) {
            tokens[token_count][0] = decoded[idx];
            tokens[token_count][1] = '\0';
            token_count++;
            idx++;
            continue;
        }

        // Word token
        int t_idx = 0;
        while (idx < dec_len && !isspace((unsigned char)decoded[idx]) && 
               !strchr("=><!();#',\"/*", decoded[idx]) && 
               !(decoded[idx] == '-' && idx + 1 < dec_len && decoded[idx+1] == '-') &&
               t_idx < 63) {
            tokens[token_count][t_idx++] = decoded[idx++];
        }
        tokens[token_count][t_idx] = '\0';
        token_count++;
    }

    // Pattern recognition on tokens
    int union_found = 0;
    int select_found = 0;
    int admin_bypass = 0;
    int tautology = 0;
    int comment_found = 0;
    int error_func = 0;
    int time_func = 0;
    int stacked_query = 0;
    int write_func = 0;

    for (int i = 0; i < token_count; i++) {
        // Check for UNION SELECT
        if (strcase_equals(tokens[i], "union")) {
            union_found = 1;
        }
        if (union_found && strcase_equals(tokens[i], "select")) {
            select_found = 1;
        }

        // Check for comment chars
        if (strcmp(tokens[i], "--") == 0 || strcmp(tokens[i], "#") == 0 || strcmp(tokens[i], "/*") == 0) {
            comment_found = 1;
        }

        // Check for Admin Bypass (e.g., admin' --, admin' #, admin' OR '1'='1)
        if (strcase_equals(tokens[i], "admin") && i + 2 < token_count) {
            if (strcmp(tokens[i+1], "'") == 0 && (strcmp(tokens[i+2], "--") == 0 || strcmp(tokens[i+2], "#") == 0 || strcmp(tokens[i+2], "/*") == 0)) {
                admin_bypass = 1;
            }
        }

        // Check for tautology OR/AND 1=1 or 'a'='a'
        if ((strcase_equals(tokens[i], "or") || strcase_equals(tokens[i], "and")) && i + 4 < token_count) {
            // OR 1 = 1
            if (strcmp(tokens[i+2], "=") == 0 && strcmp(tokens[i+1], tokens[i+3]) == 0) {
                tautology = 1;
            }
            // OR 'a' = 'a'
            else if (strcmp(tokens[i+1], "'") == 0 && strcmp(tokens[i+3], "'") == 0 && strcmp(tokens[i+5], "'") == 0 && strcmp(tokens[i+2], tokens[i+4]) == 0) {
                tautology = 1;
            }
        }

        // Check for error-based functions
        if (strcase_equals(tokens[i], "updatexml") || strcase_equals(tokens[i], "extractvalue") ||
            strcase_equals(tokens[i], "convert") || strcase_equals(tokens[i], "cast")) {
            error_func = 1;
        }

        // Check for time-based functions
        if (strcase_equals(tokens[i], "sleep") || strcase_equals(tokens[i], "benchmark") ||
            strcase_equals(tokens[i], "pg_sleep")) {
            time_func = 1;
        }

        // Stacked queries (; DROP, ; DELETE, etc.)
        if (strcmp(tokens[i], ";") == 0 && i + 1 < token_count) {
            if (strcase_equals(tokens[i+1], "drop") || strcase_equals(tokens[i+1], "delete") ||
                strcase_equals(tokens[i+1], "insert") || strcase_equals(tokens[i+1], "update") ||
                strcase_equals(tokens[i+1], "exec") || strcase_equals(tokens[i+1], "select")) {
                stacked_query = 1;
            }
        }

        // File system / write operations
        if (strcase_equals(tokens[i], "outfile") || strcase_equals(tokens[i], "load_file") ||
            strcase_equals(tokens[i], "dumpfile")) {
            write_func = 1;
        }
    }

    // Accumulate scores
    if (union_found && select_found) {
        score += 45;
        strncat(matched_pattern, "UNION SELECT; ", max_pattern_len - strlen(matched_pattern) - 1);
    }
    if (tautology) {
        score += 45;
        strncat(matched_pattern, "TAUTOLOGY (OR 1=1); ", max_pattern_len - strlen(matched_pattern) - 1);
    }
    if (admin_bypass) {
        score += 45;
        strncat(matched_pattern, "ADMIN BYPASS; ", max_pattern_len - strlen(matched_pattern) - 1);
    }
    if (stacked_query) {
        score += 40;
        strncat(matched_pattern, "STACKED QUERIES; ", max_pattern_len - strlen(matched_pattern) - 1);
    }
    if (error_func) {
        score += 25;
        strncat(matched_pattern, "ERROR SQLI FUNC; ", max_pattern_len - strlen(matched_pattern) - 1);
    }
    if (time_func) {
        score += 35;
        strncat(matched_pattern, "TIME SQLI FUNC; ", max_pattern_len - strlen(matched_pattern) - 1);
    }
    if (write_func) {
        score += 35;
        strncat(matched_pattern, "FILE WRITE; ", max_pattern_len - strlen(matched_pattern) - 1);
    }
    if (comment_found) {
        score += 10;
        strncat(matched_pattern, "SQL COMMENT; ", max_pattern_len - strlen(matched_pattern) - 1);
    }

    // If score matches or we find raw dangerous patterns like UNION SELECT in raw payload:
    if (score < 40) {
        if (strcase_contains(decoded, "union select") || strcase_contains(decoded, "union all select")) {
            score += 40;
            strncat(matched_pattern, "RAW UNION SELECT; ", max_pattern_len - strlen(matched_pattern) - 1);
        }
        if (strcase_contains(decoded, "or 1=1") || strcase_contains(decoded, "or '1'='1'")) {
            score += 40;
            strncat(matched_pattern, "RAW OR 1=1; ", max_pattern_len - strlen(matched_pattern) - 1);
        }
    }

    // Format details
    snprintf(details, max_details_len, "SQLi Score: %d. Matches: %s. Decoded Payload: %s", 
             score, matched_pattern, decoded);

    return score;
}
