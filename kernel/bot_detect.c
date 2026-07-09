#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "bot_detect.h"

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

int detect_bot(const char *payload, int payload_len, 
               char *matched_pattern, int max_pattern_len, 
               char *details, int max_details_len) {
    
    int score = 0;
    matched_pattern[0] = '\0';
    details[0] = '\0';

    // Parse HTTP request method and path from the first line
    // e.g. GET /admin HTTP/1.1
    char method[16] = {0};
    char path[512] = {0};
    int path_found = 0;

    // Make a null-terminated copy of the first line/headers for parsing
    char headers_copy[1024];
    int copy_len = payload_len > 1023 ? 1023 : payload_len;
    memcpy(headers_copy, payload, copy_len);
    headers_copy[copy_len] = '\0';

    if (sscanf(headers_copy, "%15s %511s", method, path) == 2) {
        path_found = 1;
    }

    // Extract User-Agent header value
    char user_agent[256] = {0};
    const char *ua_hdr = strcase_contains(headers_copy, "User-Agent:");
    if (ua_hdr) {
        // Skip "User-Agent:"
        ua_hdr += 11;
        while (*ua_hdr && isspace((unsigned char)*ua_hdr)) {
            ua_hdr++;
        }
        int i = 0;
        while (*ua_hdr && *ua_hdr != '\r' && *ua_hdr != '\n' && i < 255) {
            user_agent[i++] = *ua_hdr++;
        }
        user_agent[i] = '\0';
    }

    // 1. Signature Bot scans on User-Agent
    const char *scanner_uas[] = {
        "sqlmap", "nikto", "dirbuster", "gobuster", "burpsuite", "arachni", "w3af",
        "hydra", "nmap", "masscan", "nessus", "acunetix", "netsparker", "owasp",
        "python-urllib", "python-requests", "curl/", "wget", "go-http-client",
        "libwww-perl", "lwp-trivial", "perl", "ruby", "httpx", "zjgr"
    };
    int num_scanners = sizeof(scanner_uas) / sizeof(scanner_uas[0]);
    int ua_match = 0;
    char matched_ua[64] = {0};

    if (strlen(user_agent) > 0) {
        for (int i = 0; i < num_scanners; i++) {
            if (strcase_contains(user_agent, scanner_uas[i])) {
                ua_match = 1;
                strncpy(matched_ua, scanner_uas[i], sizeof(matched_ua) - 1);
                break;
            }
        }
    } else {
        // Empty User-Agent is highly suspicious for standard browsers, but common in simple bots
        // E.g., scoring it partially
        score += 20;
        strncat(matched_pattern, "EMPTY_UA; ", max_pattern_len - strlen(matched_pattern) - 1);
    }

    // 2. Honeypot bait path check
    const char *honeypot_paths[] = {
        "/wp-login.php", "/wp-admin", "/xmlrpc.php",
        "/phpmyadmin", "/pma/", "/dbadmin/",
        "/.env", "/config.php", "/database.yml", "/credentials",
        "/.git/config", "/.git/HEAD",
        "/admin/login", "/admin/config", "/administrator/",
        "/shell.php", "/cmd.php", "/upload.php"
    };
    int num_honeypots = sizeof(honeypot_paths) / sizeof(honeypot_paths[0]);
    int honeypot_match = 0;
    char matched_honeypot[64] = {0};

    if (path_found) {
        for (int i = 0; i < num_honeypots; i++) {
            if (strcase_contains(path, honeypot_paths[i])) {
                honeypot_match = 1;
                strncpy(matched_honeypot, honeypot_paths[i], sizeof(matched_honeypot) - 1);
                break;
            }
        }
    }

    // Accumulate scores
    if (ua_match) {
        score += 45;
        strncat(matched_pattern, "SCANNER_UA; ", max_pattern_len - strlen(matched_pattern) - 1);
    }

    if (honeypot_match) {
        score += 45;
        strncat(matched_pattern, "HONEYPOT_PATH; ", max_pattern_len - strlen(matched_pattern) - 1);
    }

    // If both UA matches and honeypot path is accessed, boost it to critical
    if (ua_match && honeypot_match) {
        score += 10;
    }

    snprintf(details, max_details_len, "Bot Score: %d. Matches: %s. UA: %s, Path: %s", 
             score, matched_pattern, matched_ua[0] ? matched_ua : (user_agent[0] ? "Browser/Other" : "None"), 
             matched_honeypot[0] ? matched_honeypot : "None");

    return score;
}
