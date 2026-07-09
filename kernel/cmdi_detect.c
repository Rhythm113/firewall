#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "cmdi_detect.h"

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

int detect_cmdi(const char *payload, int payload_len, 
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

    // 1. Check for shell metacharacters
    int has_semi = (strchr(decoded, ';') != NULL);
    int has_pipe = (strchr(decoded, '|') != NULL);
    int has_amp = (strstr(decoded, "&&") != NULL);
    int has_backtick = (strchr(decoded, '`') != NULL);
    int has_dollar_paren = (strstr(decoded, "$(") != NULL);
    int has_redirect = (strchr(decoded, '>') != NULL || strchr(decoded, '<') != NULL);

    int has_meta = (has_semi || has_pipe || has_amp || has_backtick || has_dollar_paren || has_redirect);

    // 2. Dangerous binaries/commands
    const char *commands[] = {
        "whoami", "uname", "id", "hostname", "netstat", "ifconfig", "ip addr",
        "wget", "curl", "nc ", "ncat", "netcat", "ping", "tftp", "ftp ",
        "bash", "sh ", "ash", "csh", "zsh", "python", "perl", "ruby", "php -r",
        "cat /", "grep ", "find ", "chmod ", "chown ", "rm -rf", "touch ", "mkdir "
    };
    int num_commands = sizeof(commands) / sizeof(commands[0]);
    int command_match_count = 0;
    char matched_cmds[256] = {0};

    for (int i = 0; i < num_commands; i++) {
        if (strcase_contains(decoded, commands[i])) {
            command_match_count++;
            if (strlen(matched_cmds) < sizeof(matched_cmds) - 32) {
                strcat(matched_cmds, commands[i]);
                strcat(matched_cmds, ", ");
            }
        }
    }

    // 3. Special file and directory checks
    int has_passwd = (strcase_contains(decoded, "/etc/passwd") != NULL);
    int has_shadow = (strcase_contains(decoded, "/etc/shadow") != NULL);
    int has_bin = (strcase_contains(decoded, "/bin/sh") != NULL || strcase_contains(decoded, "/bin/bash") != NULL);
    int has_dev_tcp = (strcase_contains(decoded, "/dev/tcp/") != NULL);

    // Accumulate scores
    if (has_meta) {
        score += 15;
        strncat(matched_pattern, "META_CHAR; ", max_pattern_len - strlen(matched_pattern) - 1);
    }

    if (command_match_count > 0) {
        score += (command_match_count * 20); // 20 per command match
        strncat(matched_pattern, "SHELL_CMD; ", max_pattern_len - strlen(matched_pattern) - 1);
    }

    if (has_passwd || has_shadow) {
        score += 35;
        strncat(matched_pattern, "ETC_FILES; ", max_pattern_len - strlen(matched_pattern) - 1);
    }

    if (has_bin) {
        score += 30;
        strncat(matched_pattern, "BIN_PATHS; ", max_pattern_len - strlen(matched_pattern) - 1);
    }

    if (has_dev_tcp) {
        score += 40;
        strncat(matched_pattern, "DEV_TCP; ", max_pattern_len - strlen(matched_pattern) - 1);
    }

    // High confidence triggers
    // e.g. metacharacter followed immediately/closely by command
    if (has_meta && command_match_count > 0) {
        score += 25; // boost
        strncat(matched_pattern, "META+CMD; ", max_pattern_len - strlen(matched_pattern) - 1);
    }

    // Reverse Shell specifics: bash -i, sh -i
    if (strcase_contains(decoded, "bash -i") || strcase_contains(decoded, "sh -i")) {
        score += 50;
        strncat(matched_pattern, "REV_SHELL; ", max_pattern_len - strlen(matched_pattern) - 1);
    }

    snprintf(details, max_details_len, "CMDi Score: %d. Matches: %s. Commands: %s. Decoded: %s", 
             score, matched_pattern, matched_cmds, decoded);

    return score;
}
