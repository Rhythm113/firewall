# Architecture Overview

## System Topology

Nullsploit is a Web Application Firewall (WAF) and Security Operations
Center (SOC) monitoring suite. It consists of four main tiers:

```
Client Browser --> Apache httpd --> NFQUEUE (iptables) --> fw_nfq (userspace firewall)
    |
    v
fw_agent (local agent) --AES/TCP 1113--> soc_receiver (SOC daemon)
    |                                          |
    v                                          v
PostgreSQL <-- JDBC --> Spring Boot Dashboard (port 8443)
```

## Tiers

### Tier 1: Kernel Firewall (fw_nfq)
A userspace daemon using libnetfilter_queue to intercept packets at
the Netfilter hook NF_INET_PRE_ROUTING. It performs:

- IP blocklist CIDR matching
- TCP connection state monitoring (SYN flood, Slowloris)
- HTTP payload inspection (SQLi, XSS, CMDi, path traversal, bot UA)
- YARA signature scanning (inline + file upload)
- IP reputation scoring
- eBPF/XDP blocklist offload (if available)

Verdicts: NF_ACCEPT (allow) or NF_DROP (block).

A kernel module variant (fw_inspect.ko) uses Netfilter hooks directly
and communicates with the agent via a custom Netlink protocol
(NETLINK_FW_INSPECT=31).

### Tier 2: Agent Daemon (fw_agent)
A lightweight daemon running alongside the firewall daemon on each
web server node. It:

- Connects to fw_nfq via a local UNIX domain socket
  (/var/run/fw_inspect.sock)
- Collects events, deduplicates them (32-entry ring, 10s window)
- Encrypts and forwards alerts to the SOC receiver via TCP port 1113
- Batches non-critical events every 10 seconds
- Receives block/unblock/config commands from the SOC receiver
- Loads and applies blocklists from /etc/fw_inspect/blocklist.txt

### Tier 3: SOC Receiver Daemon (soc_receiver)
A C daemon that acts as the central ingest point. It:

- Listens on port 1113 for AES-encrypted agent messages
- Listens on port 8445 for REST API calls (REST API)
- Listens on port 8444 for local control commands from Spring Boot
- Decrypts and processes agent events (alerts, batches, heartbeats)
- Writes all events to PostgreSQL
- Broadcasts events via SSE (port 8445) for live dashboard updates
- Forwards events to Spring Boot internal endpoint for instant SSE push
- Sends AES-encrypted downstream commands back to agents
- Manages threat intelligence feed fetching (Feodo, BinaryDefense, CIArmy)

### Tier 4: Spring Boot Dashboard
A Java Spring Boot application serving:

- REST API on port 8443
- Single-page HTML/JS dashboard with multiple tabs
- Server-Sent Events (SSE) for live updates
- AI analysis service (background thread, OpenCode-compatible API)
- Email notification service (SMTP)
- System health monitoring (CPU, memory, event throughput, spike detection)

### Data Storage: PostgreSQL
All event data, agent registrations, IP reputations, blocklists, YARA
rules, configurations, threat intelligence, and AI analysis results
are stored in a PostgreSQL 15 database.

## Network Ports

| Port | Direction | Protocol | Purpose |
|------|-----------|----------|---------|
| 80   | Inbound   | HTTP     | Apache web server (target) |
| 1113 | Inbound   | TCP      | AES-encrypted agent events |
| 8443 | Inbound   | HTTP     | Spring Boot dashboard API |
| 8444 | Localhost | TCP      | Control commands to soc_receiver |
| 8445 | Inbound   | HTTP     | soc_receiver REST API + SSE |
| 5432 | Internal  | TCP      | PostgreSQL database |

## Data Flow

1. HTTP request arrives at port 80/443
2. iptables NFQUEUE rule intercepts matching packets
3. fw_nfq evaluates the packet against all detection engines
4. If malicious: packet is dropped (NF_DROP), event is sent to fw_agent
   via UNIX socket, and IP reputation is updated
5. fw_agent encrypts the event with AES and sends to soc_receiver:1113
6. soc_receiver decrypts and writes to PostgreSQL
7. soc_receiver broadcasts the event over SSE (port 8445) and forwards
   to Spring Boot internal push endpoint
8. Spring Boot sends the event to all connected dashboard SSE clients
9. AI Service periodically analyzes unanalyzed events (every 10s)
10. Notification Service checks for new events (every 5s) and sends
    email alerts for WARNING/CRITICAL events if SMTP is configured

## Communication Security

- Agent-to-SOC: AES-256-CBC encryption (in-memory using OpenSSL libcrypto)
- Spring Boot-to-soc_receiver: Localhost-only TCP (port 8444)
- External API access: Session tokens (HMAC-SHA256) + IP whitelist
- Internal push: Shared secret key (X-Internal-Key header)

## Detection Flow Order

For each intercepted packet, the evaluation chain in fw_nfq_callback()
proceeds in this order:

1. IP Reputation check (score <= 20 -> DROP)
2. IP Blocklist match (exact or CIDR -> DROP)
3. TCP connection stats (SYN flood detection)
4. HTTP payload inspection (only on port 80):
   a. SQL injection detection
   b. Command injection detection
   c. Path traversal / LFI / RFI detection
   d. Bot / scanner detection (UA + path)
   e. PHP shell detection
   f. XSS detection
   g. YARA inline memory scan
5. Local IP bypass logic (if g_block_local_ips == 0)
