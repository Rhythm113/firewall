#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "../kernel/fw_inspect.h"

#define SOC_PORT 1113
#define MAGIC_HEADER 0x46573031 // "FW01" in hex

// Message types
#define MSG_TYPE_PING  0
#define MSG_TYPE_BATCH 1
#define MSG_TYPE_ALERT 2

// Wire Protocol Header
struct soc_msg_hdr {
    uint32_t magic;
    uint8_t agent_uuid[16];
    uint8_t msg_type;
    uint32_t payload_len; // Size of encrypted payload that follows
} __attribute__((packed));

#endif // PROTOCOL_H
