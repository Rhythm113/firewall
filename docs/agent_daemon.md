# Agent Daemon

## Overview

The agent (fw_agent) runs on each web server node. It bridges the
local firewall daemon (fw_nfq) and the centralized SOC receiver.

Source: agent/fw_agent.c

## Startup Flow

```
main()
  +-> load_agent_uuid()
  |    Reads UUID from /etc/fw_keys/agent_uuid
  |    Generates from /dev/urandom if file missing
  +-> signal(SIGHUP) -> reload_blocklist
  +-> signal(SIGPIPE, SIG_IGN)
  +-> connect_to_firewall()
  |    Tries Netlink (NETLINK_FW_INSPECT=31) first
  |    Falls back to UNIX socket (/var/run/fw_inspect.sock)
  +-> connect_to_soc()
  |    Resolves "soc-server" hostname (or 127.0.0.1)
  |    Connects to TCP port 1113 with 5-second timeout
  |    Sets aggressive TCP keepalive
  +-> send_to_soc(MSG_TYPE_PING) -> register with SOC
  +-> load_and_push_blocklist()
  |    Parses /etc/fw_inspect/blocklist.txt
  |    Pushes entries to firewall daemon
  +-> Event loop: select(2s) on fw_fd + soc_fd
```

## Event Loop

The main loop uses select() with a 2-second timeout on two file
descriptors:

1. **fw_fd**: Reads firewall events from the local daemon
2. **soc_fd**: Reads downstream commands from the SOC receiver

### Event Processing

On data from fw_fd:
1. Read fw_event struct from UNIX socket
2. Check dedup (32-entry ring buffer, 10-second window per src_ip
   + threat_type)
3. For CRITICAL (severity=2) or WARNING (severity=1) events that
   are NOT duplicates: send immediate MSG_TYPE_ALERT to SOC
4. Buffer event into pending batch (up to 512 events)
5. Every 10 seconds: flush batch as MSG_TYPE_BATCH

### Downstream Command Processing

On data from soc_fd:
1. Read soc_msg_hdr (8 bytes: magic + uuid + type + len)
2. Verify magic header (0x46573031 = "FW01")
3. Read payload of payload_len bytes
4. Decrypt payload with PGP
5. Dispatch by msg_type:

| Type | Command | Action |
|------|---------|--------|
| 3 | MSG_TYPE_BLOCK_IP | Append IP to blocklist.txt, SIGHUP reload |
| 4 | MSG_TYPE_UNBLOCK_IP | Rewrite blocklist.txt without the IP, reload |
| 5 | MSG_TYPE_CONFIG_UPDATE | Update block_local_ips line in blocklist.txt |
| 6 | MSG_TYPE_YARA_UPDATE | Write new rules.yar, signal reload |

### Health Check

- Every 5 seconds checks SOC connection status
- If disconnected: closes old socket, attempts reconnect with
  5-second timeout

## Event Dedup

A 32-entry ring buffer prevents duplicate alerts:
```c
struct dedup_entry {
    uint32_t src_ip;
    int threat_type;
    time_t timestamp;  // creation time
};
```

Dedup window: 10 seconds. An event with the same (src_ip,
threat_type) within 10 seconds of a previously sent event is
silently dropped.

## AES Encryption (aes_wrapper.c)

Uses in-memory AES-256-CBC encryption using OpenSSL libcrypto:

### Encryption
- Generates a random 16-byte IV
- Encrypts using `EVP_aes_256_cbc()` and the pre-shared key `"nullsploit_secure_aes_key_2026!"`
- Prepends the 16-byte IV to the ciphertext

### Decryption
- Extracts the 16-byte IV from the beginning of the ciphertext payload
- Decrypts using `EVP_aes_256_cbc()` and the pre-shared key
- Allocates and returns the decrypted plaintext buffer

This approach avoids GnuPG process forks and keyring management issues.

## Wire Protocol

```c
struct soc_msg_hdr {
    uint32_t magic;         // 0x46573031 ("FW01")
    uint8_t agent_uuid[16]; // 16-byte binary UUID
    uint8_t msg_type;       // message type enum
    uint32_t payload_len;   // payload length (network byte order)
};
```

Total header size: 8 bytes (magic + msg_type + payload_len) plus
16 bytes (agent_uuid) = 25 bytes.

Payload after header is always AES-encrypted for agent<->SOC
communication.

## Blocklist File Format

File: /etc/fw_inspect/blocklist.txt

```
# Firewall IP Blocklist
block_local_ips=1
192.168.0.222/32
10.99.99.99/32
```

Lines starting with # are comments. The block_local_ips=N line
controls private IP blocking behavior. Each subsequent line is an
IP or CIDR range to block.

## Agent UUID

Stored in /etc/fw_keys/agent_uuid as a hex string (32 hex chars
representing 16 bytes). Generated once from /dev/urandom on first
startup. Used to identify the agent in all SOC communications.

## Build

```
cd agent/
make    # Compiles fw_agent from fw_agent.c + aes_wrapper.c
```

Produces a single binary: fw_agent.
For static production builds:
```
gcc -O2 -Wall -static fw_agent.c aes_wrapper.c -o fw_agent -pthread -lcrypto
strip fw_agent
```
