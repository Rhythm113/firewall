#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "fw_inspect.h"

#define SOC_PORT 1113
#define MAGIC_HEADER 0x46573031 // "FW01" in hex

// Message types
#define MSG_TYPE_PING  0
#define MSG_TYPE_BATCH 1
#define MSG_TYPE_ALERT 2
#define MSG_TYPE_BLOCK_IP      3
#define MSG_TYPE_UNBLOCK_IP    4
#define MSG_TYPE_CONFIG_UPDATE 5
#define MSG_TYPE_YARA_UPDATE   6


// Wire Protocol Header
struct soc_msg_hdr {
    uint32_t magic;
    uint8_t agent_uuid[16];
    uint8_t msg_type;
    uint32_t payload_len; // Size of encrypted payload that follows
} __attribute__((packed));

struct agent_health_payload {
    double cpu_usage;
    double mem_usage;
    uint64_t uptime_sec;
} __attribute__((packed));

#endif // PROTOCOL_H
