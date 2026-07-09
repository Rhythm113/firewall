#ifndef FW_INSPECT_H
#define FW_INSPECT_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

#define NETLINK_FW_INSPECT 31
#define MAX_PATTERN_LEN 64
#define MAX_BLOCKLIST_IPS 1024

// Event severity levels
#define SEVERITY_INFO     0
#define SEVERITY_WARNING  1
#define SEVERITY_CRITICAL 2

// Threat types
#define THREAT_PHP_SHELL   1
#define THREAT_XSS         2
#define THREAT_SYN_FLOOD   3
#define THREAT_SLOWLORIS   4
#define THREAT_BLOCKLIST   5
#define THREAT_SQLI        6
#define THREAT_CMDI        7
#define THREAT_PATH_TRAV   8
#define THREAT_LFI         9
#define THREAT_RFI         10
#define THREAT_BOT         11
#define THREAT_YARA        12
#define THREAT_REPUTATION  13


// Struct sent from kernel to userspace agent via Netlink
struct fw_event {
    uint64_t timestamp;
    uint32_t src_ip;
    uint32_t dest_ip;
    uint16_t src_port;
    uint16_t dest_port;
    uint8_t threat_type;
    uint8_t severity;
    char payload_preview[128];
    char details[256];
};

// Struct sent from userspace agent to kernel to load blocklist
struct blocklist_entry {
    uint32_t ip;
    uint8_t mask; // CIDR mask (e.g. 24, 32)
};

struct blocklist_payload {
    uint32_t count;
    struct blocklist_entry entries[MAX_BLOCKLIST_IPS];
};

#endif // FW_INSPECT_H
