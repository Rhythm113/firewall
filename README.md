# Nullsploit: Advanced WAF & SOC Dashboard

Nullsploit is a distributed, high-performance Web Application Firewall (WAF) and Security Operations Center (SOC) dashboard. The system runs as a multi-container Docker Compose application on Linux systems.

## Features
- **Next.js 15 + shadcn/ui Dashboard**: Premium real-time analytics panel displaying events, active agents, blocklists, IP reputation tracking, YARA rules manager, and threat intelligence.
- **Bi-directional AES Agent Protocol**: Agents register dynamically and connect to the SOC server on port 1113. Alerts are AES-encrypted and sent to the server in real-time. Settings and IP block lists are pushed from the dashboard down to the agents.
- **Deep Packet Inspection (DPI) Engine**: C-based userspace WAF daemon (`fw_nfq`) powered by Netfilter Queues (`iptables NFQUEUE`).
- **SQL Injection Tokenizer**: Scans and parses payloads for SQLi indicators (Union Select, Boolean Tautology, Stacked queries).
- **Command Injection Scanner**: Detects shell metacharacters, reverse shells, and malicious Unix binaries.
- **Path Traversal / LFI / RFI**: Decodes nested URL/Hex encoding to block local/remote file inclusions.
- **Bot and Scanner blocklist**: User-Agent fingerprinting and honeypot trap routing.
- **YARA rules matching**: Runs inline memory checking and offloads heavy file uploads asynchronously to a single background worker thread.
- **eBPF/XDP hardware-level filters**: Drops blacklisted IPs at the network interface card driver level before hitting the kernel network stack (Linux 5.x+ fallback).
- **IP Reputation system**: Tracks cumulative malice score (0-100) per source IP.
- **Threat Intelligence feeds**: Automatically aggregates indicators of compromise from Feodo Tracker, Binary Defense, and CI Army.

---

## Architecture Overview

```
                          AES over TCP (1113)
  [ WAF Node: Apache ] ────────────────────────► [ SOC Server (C Backend) ]
  (fw_nfq + inotify)                                   │
          │                                            ▼
          ▼                                     [ PostgreSQL DB ]
   /var/www/uploads/                                   ▲
                                                       │
                                                [ Next.js 15 Web Console ]
                                                       (Port 8443)
```

---

## Setup & Execution

### 1. Build and Launch
Initialize PostgreSQL schemas, compile WAF and Agent C modules, build the web console, and launch the multi-container stack:
```bash
docker compose up -d --build
```

### 2. Access the Dashboard
Open your browser and navigate to:
```text
https://localhost:8443
```
Login using default credentials (configured in `users.conf`).

### 3. Simulating Attacks & Verification
You can test the WAF logic and YARA upload scanning by sending HTTP requests:

- **SQL Injection**:
  ```bash
  curl "http://localhost/?q=1+union+select+null,username,password+from+users"
  ```
- **Command Injection**:
  ```bash
  curl "http://localhost/?cmd=;whoami"
  ```
- **Path Traversal**:
  ```bash
  curl "http://localhost/?file=../../../../etc/passwd"
  ```
- **Webshell File Upload**:
  Access the vulnerable target portal at:
  ```text
  http://localhost/cgi-bin/upload.py
  ```
  Upload a shell (containing the string `eval(` or `system(`). The `inotify` queue watches `/var/www/uploads/` and scans the uploaded file in the background async YARA thread pool. Check the dashboard logs for results.
