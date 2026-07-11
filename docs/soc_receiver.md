# SOC Receiver Daemon

## Overview

The SOC receiver (soc_receiver) is the central ingest and control
daemon. It receives events from agents, writes them to PostgreSQL,
broadcasts them for live dashboard updates, and sends downstream
commands back to agents.

Source: soc-server/soc_receiver.c

## Startup Flow

```
main()
  +-> db_init() with up to 15 retries (5-second interval)
  +-> auth_init() -- load IP whitelist and HMAC secret
  +-> sse_init() -- initialize SSE client array
  +-> init_threat_intel() -- start background feed fetcher
  +-> create_listen sockets for ports 1113, 8444, 8445
  +-> epoll_create
  +-> epoll loop (edge-triggered)
```

## Listening Ports

| Port | Purpose |
|------|---------|
| 1113 | Agent ingest (AES-encrypted TCP) |
| 8444 | Local control commands from Spring Boot |
| 8445 | REST API + SSE broadcast for dashboard |

## Epoll Event Loop

All three listening sockets are registered with epoll (edge-triggered).
The loop:

1. epoll_wait() with infinite timeout
2. For each ready fd:
   - If listening socket: accept() and add to epoll
   - Process data based on port

### Port 1113: Agent Message Processing

Message read flow:
1. Read soc_msg_hdr (sizeof = header struct)
2. Verify magic == 0x46573031 ("FW01")
3. Read payload_len bytes of AES-encrypted payload
4. Call aes_decrypt() to decrypt
5. Dispatch by msg_type:

| Type | Handler | Description |
|------|---------|-------------|
| MSG_TYPE_PING (1) | Register/update agent in DB | Agent heartbeat, updates last_seen |
| MSG_TYPE_ALERT (2) | db_insert_event() + broadcast | Critical/warning event |
| MSG_TYPE_BATCH (7) | Batch insert events | Non-critical events, bulk insert |
| Other | Heartbeat log | Empty payload = keepalive ping |

### Port 8444: Local Control Commands

Accepts raw TCP connections from Spring Boot. Protocol:
- 33 bytes: agent UUID (hex string)
- 1 byte: command type
- 4 bytes: payload (IP address or config value)

Command types:
- 3 (MSG_TYPE_BLOCK_IP): Block an IP on the agent
- 4 (MSG_TYPE_UNBLOCK_IP): Unblock an IP
- 5 (MSG_TYPE_CONFIG_UPDATE): Update agent config

After reading, the receiver finds the agent by UUID in the registry
and sends the encrypted downstream command via send_command_to_agent().

### Port 8445: REST API

Accepts HTTP requests. Supports:

| Method | Path | Description |
|--------|------|-------------|
| GET | /api/v2/auth | Verify session token |
| POST | /api/v2/auth | Login (username + password) |
| GET | /api/v2/stats | Dashboard statistics |
| GET | /api/v2/agents | List registered agents |
| GET | /api/v2/events | List events (paginated) |
| GET | /api/v2/blocklist | List blocklist entries |
| GET | /api/v2/reputation | Get IP reputation data |
| GET | /api/v2/yara/rules | List YARA rules |
| GET | /api/v2/config | Get configuration |
| POST | /api/v2/config | Update configuration |
| POST | /api/v2/threat-intel/fetch | Trigger feed fetch |
| GET | /api/v2/events/live | SSE endpoint for live events |

Responses are JSON strings hand-built using the json_buf helper.

## SSE Broadcast

The SSE system (sse.c, sse.h) maintains an array of up to 32 SSE
client connections. When an event is received from an agent, it is:

1. Written to PostgreSQL via db_insert_event()
2. Broadcast to all SSE clients via sse_broadcast()
3. Forwarded to Spring Boot via forward_to_spring_boot()

### forward_to_spring_boot()

Uses raw TCP sockets (no libcurl dependency):
1. Create socket, set non-blocking
2. connect() to 127.0.0.1:8443
3. select() with 3-second timeout
4. If connected: send POST /api/v2/internal/push-event
   with X-Internal-Key header and JSON body
5. Close socket immediately

The internal key is hardcoded as "soc-receiver-forward".

## Agent Registry

An in-memory array of up to 128 agents:

```c
struct agent_registry {
    uint8_t uuid[16];
    int fd;         // socket fd for this agent
    int port;       // source port of connection
    struct sockaddr_in addr;  // source address
    time_t last_seen;
};
```

Agents are looked up by UUID when sending downstream commands.

## REST API Authentication

The REST API on port 8445 authenticates requests via:
1. Session token in X-Session-Token header (HMAC-SHA256 based)
2. IP whitelist check (CIDR matching against whitelist.conf)

The auth system is in auth.c/auth.h.

## Port 8445 Connection Close

The daemon includes a periodic close of any lingering connections
on the REST API port (sock_close = 1), triggered every iteration
if an old connection is detected. This prevents stale connections
from accumulating.

## Build

```
cd soc-server/
make    # Compiles soc_receiver from soc_receiver.c + db.c +
        # auth.c + aes_wrapper.c + threat_intel.c
```

Links: -lpq -lcurl -lcrypto -lcrypt -pthread
