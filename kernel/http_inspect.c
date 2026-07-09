#ifdef BUILD_USERSPACE
#include "userspace_compat.h"
#else
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#endif
#include "fw_inspect.h"
#include "sqli_detect.h"
#include "cmdi_detect.h"
#include "path_detect.h"
#include "bot_detect.h"
#include "yara_engine.h"
#include "ip_reputation.h"

// External callback to send event to userspace
extern void send_fw_event(struct fw_event *event);

// Helper substring search function (non-allocating, simple and fast)
static const char *k_strstr(const char *haystack, int haystack_len, const char *needle, int needle_len) {
    int i, j;
    if (needle_len > haystack_len) return NULL;

    for (i = 0; i <= haystack_len - needle_len; i++) {
        for (j = 0; j < needle_len; j++) {
            if (haystack[i + j] != needle[j])
                break;
        }
        if (j == needle_len) {
            return &haystack[i];
        }
    }
    return NULL;
}

// Case-insensitive substring search helper
static const char *k_stristr(const char *haystack, int haystack_len, const char *needle, int needle_len) {
    int i, j;
    if (needle_len > haystack_len) return NULL;

    for (i = 0; i <= haystack_len - needle_len; i++) {
        for (j = 0; j < needle_len; j++) {
            char h_c = haystack[i + j];
            char n_c = needle[j];
            
            // Convert to lowercase for comparison
            if (h_c >= 'A' && h_c <= 'Z') h_c += 32;
            if (n_c >= 'A' && n_c <= 'Z') n_c += 32;

            if (h_c != n_c)
                break;
        }
        if (j == needle_len) {
            return &haystack[i];
        }
    }
    return NULL;
}

// Main HTTP payload inspector
int inspect_http_payload(struct sk_buff *skb, struct iphdr *iph, struct tcphdr *tcph) {
    unsigned char *payload;
    int ip_header_len = iph->ihl * 4;
    int tcp_header_len = tcph->doff * 4;
    int payload_offset = ip_header_len + tcp_header_len;
    int payload_len = ntohs(iph->tot_len) - payload_offset;
    
    // PHP shell signatures
    const char *php_signatures[] = {
        "eval(", "base64_decode(", "system(", "passthru(", "exec(", "shell_exec(", "popen(", "proc_open("
    };
    int php_sig_lens[] = { 5, 14, 7, 9, 5, 11, 6, 10 };
    int num_php_sigs = 8;

    // XSS signatures (case-insensitive)
    const char *xss_signatures[] = {
        "<script>", "javascript:", "onerror=", "onload=", "<img", "alert("
    };
    int xss_sig_lens[] = { 8, 11, 8, 7, 4, 6 };
    int num_xss_sigs = 6;

    int i;

    if (payload_len <= 0) {
        return 0; // No payload to inspect
    }

    // Pull or map skb data to make sure it's linear and accessible
    if (!pskb_may_pull(skb, payload_offset + (payload_len > 1024 ? 1024 : payload_len))) {
        return 0; // Can't pull skb data safely
    }

    // Re-evaluate iph and tcph after pull, as headers could have moved
    iph = ip_hdr(skb);
    tcph = tcp_hdr(skb);
    payload = skb->data + payload_offset;

    // We can limit scan depth for inline to prevent performance degradation
    int scan_len = payload_len > 2048 ? 2048 : payload_len;

    char pattern[128];
    char details[256];

    // 1. Scan for SQL Injection
    if (detect_sqli((const char *)payload, scan_len, pattern, sizeof(pattern), details, sizeof(details)) >= 40) {
        struct fw_event event = {
            .timestamp = ktime_get_real_seconds(),
            .src_ip = iph->saddr,
            .dest_ip = iph->daddr,
            .src_port = tcph->source,
            .dest_port = tcph->dest,
            .threat_type = THREAT_SQLI,
            .severity = SEVERITY_CRITICAL,
        };
        snprintf(event.payload_preview, sizeof(event.payload_preview), "%s", pattern);
        snprintf(event.details, sizeof(event.details), "%s", details);
        send_fw_event(&event);
        update_ip_reputation(iph->saddr, 20, THREAT_SQLI);
        return 1;
    }

    // 2. Scan for Command Injection
    if (detect_cmdi((const char *)payload, scan_len, pattern, sizeof(pattern), details, sizeof(details)) >= 40) {
        struct fw_event event = {
            .timestamp = ktime_get_real_seconds(),
            .src_ip = iph->saddr,
            .dest_ip = iph->daddr,
            .src_port = tcph->source,
            .dest_port = tcph->dest,
            .threat_type = THREAT_CMDI,
            .severity = SEVERITY_CRITICAL,
        };
        snprintf(event.payload_preview, sizeof(event.payload_preview), "%s", pattern);
        snprintf(event.details, sizeof(event.details), "%s", details);
        send_fw_event(&event);
        update_ip_reputation(iph->saddr, 20, THREAT_CMDI);
        return 1;
    }

    // 3. Scan for Path Traversal / LFI / RFI
    if (detect_path_traversal((const char *)payload, scan_len, pattern, sizeof(pattern), details, sizeof(details)) >= 40) {
        struct fw_event event = {
            .timestamp = ktime_get_real_seconds(),
            .src_ip = iph->saddr,
            .dest_ip = iph->daddr,
            .src_port = tcph->source,
            .dest_port = tcph->dest,
            .threat_type = THREAT_PATH_TRAV,
            .severity = SEVERITY_CRITICAL,
        };
        if (strstr(pattern, "RFI")) event.threat_type = THREAT_RFI;
        else if (strstr(pattern, "LFI")) event.threat_type = THREAT_LFI;

        snprintf(event.payload_preview, sizeof(event.payload_preview), "%s", pattern);
        snprintf(event.details, sizeof(event.details), "%s", details);
        send_fw_event(&event);
        update_ip_reputation(iph->saddr, 20, event.threat_type);
        return 1;
    }

    // 4. Scan for Bot / Scanner indicators
    if (detect_bot((const char *)payload, scan_len, pattern, sizeof(pattern), details, sizeof(details)) >= 40) {
        struct fw_event event = {
            .timestamp = ktime_get_real_seconds(),
            .src_ip = iph->saddr,
            .dest_ip = iph->daddr,
            .src_port = tcph->source,
            .dest_port = tcph->dest,
            .threat_type = THREAT_BOT,
            .severity = SEVERITY_WARNING,
        };
        snprintf(event.payload_preview, sizeof(event.payload_preview), "%s", pattern);
        snprintf(event.details, sizeof(event.details), "%s", details);
        send_fw_event(&event);
        update_ip_reputation(iph->saddr, 15, THREAT_BOT);
        return 1;
    }

    // 5. Scan for PHP Shell Signatures (existing checks)
    for (i = 0; i < num_php_sigs; i++) {
        if (k_strstr((const char *)payload, scan_len, php_signatures[i], php_sig_lens[i])) {
            struct fw_event event = {
                .timestamp = ktime_get_real_seconds(),
                .src_ip = iph->saddr,
                .dest_ip = iph->daddr,
                .src_port = tcph->source,
                .dest_port = tcph->dest,
                .threat_type = THREAT_PHP_SHELL,
                .severity = SEVERITY_CRITICAL,
            };
            snprintf(event.payload_preview, sizeof(event.payload_preview), "PHP Shell: %.100s", php_signatures[i]);
            memcpy(event.details, payload, scan_len > 255 ? 255 : scan_len);
            event.details[scan_len > 255 ? 255 : scan_len] = '\0';
            
            send_fw_event(&event);
            update_ip_reputation(iph->saddr, 25, THREAT_PHP_SHELL);
            return 1; // Drop packet
        }
    }

    // 6. Scan for XSS Signatures (existing checks)
    for (i = 0; i < num_xss_sigs; i++) {
        if (k_stristr((const char *)payload, scan_len, xss_signatures[i], xss_sig_lens[i])) {
            struct fw_event event = {
                .timestamp = ktime_get_real_seconds(),
                .src_ip = iph->saddr,
                .dest_ip = iph->daddr,
                .src_port = tcph->source,
                .dest_port = tcph->dest,
                .threat_type = THREAT_XSS,
                .severity = SEVERITY_WARNING,
            };
            snprintf(event.payload_preview, sizeof(event.payload_preview), "XSS Detected: %.100s", xss_signatures[i]);
            memcpy(event.details, payload, scan_len > 255 ? 255 : scan_len);
            event.details[scan_len > 255 ? 255 : scan_len] = '\0';
            
            send_fw_event(&event);
            update_ip_reputation(iph->saddr, 10, THREAT_XSS);
            return 1; // Drop packet
        }
    }

    // 7. YARA Inline matching (last, heavier)
    if (scan_mem_yara((const char *)payload, scan_len, pattern, sizeof(pattern)) > 0) {
        struct fw_event event = {
            .timestamp = ktime_get_real_seconds(),
            .src_ip = iph->saddr,
            .dest_ip = iph->daddr,
            .src_port = tcph->source,
            .dest_port = tcph->dest,
            .threat_type = THREAT_YARA,
            .severity = SEVERITY_CRITICAL,
        };
        snprintf(event.payload_preview, sizeof(event.payload_preview), "YARA matched: %.100s", pattern);
        snprintf(event.details, sizeof(event.details), "HTTP payload triggered inline YARA rule %.100s", pattern);
        send_fw_event(&event);
        update_ip_reputation(iph->saddr, 30, THREAT_YARA);
        return 1;
    }

    return 0; // Accept packet
}
