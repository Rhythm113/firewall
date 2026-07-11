# Kernel Firewall Module

## Overview

The kernel firewall consists of two parallel implementations:

1. **fw_nfq** (primary): A userspace daemon using libnetfilter_queue.
   This is the running WAF in production.
2. **fw_inspect.ko** (optional): A Linux Kernel Module using Netfilter
   hooks directly. Communicates with fw_agent via Netlink.

Both share the same detection logic via shared source files.

## fw_nfq (Userspace NFQUEUE Daemon)

### Source: kernel/fw_nfq.c

The main daemon process flow:

```
main()
  +-> init_ip_reputation()
  +-> init_yara_engine()
  +-> init_ebpf_xdp()
  +-> init_conn_pool()
  +-> Setup UNIX socket for agent communication
  +-> agent_listener_thread()        (detached)
  +-> yara_inotify_thread()          (detached)
  +-> nfq_open()
  +-> nfq_bind_pf()
  +-> nfq_create_queue(0)
  +-> recv loop: fw_nfq_callback()
```

### Module Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| g_block_local_ips | 0 | If 1, block local IPs when malicious |
| g_yara_enabled | 1 | If 1, enable YARA scanning |

### Packet Callback: fw_nfq_callback()

Called for each intercepted packet. Evaluation order:

1. Extract IP and TCP headers from raw packet data
2. IP reputation check via get_ip_reputation()
   - score <= 20 -> NF_DROP + alert + reputation update
3. IP blocklist check via inspect_ip_blocklist()
   - Match -> NF_DROP + alert + reputation update
4. TCP stats monitoring via monitor_tcp_stats()
   - SYN flood detected -> NF_DROP
5. HTTP payload inspection (port 80 only) via inspect_http_payload()
   - Malicious -> NF_DROP + alert + reputation update
6. Local IP bypass: if src_ip is private and g_block_local_ips is 0,
   override DROP verdict to ACCEPT
7. Default: NF_ACCEPT

### UNIX Socket Agent Communication

The daemon creates a local UNIX domain socket at
/var/run/fw_inspect.sock. The agent connects to receive events.

`send_fw_event()` writes events to the agent's socket using
MSG_DONTWAIT (non-blocking). If the agent is backlogged (write fails
with EAGAIN/EWOULDBLOCK), the event is silently dropped and a counter
is incremented. This prevents the firewall from blocking on a slow or
disconnected agent.

### YARA Inotify Thread

A detached thread that monitors UPLOAD_DIR (/var/www/uploads by
default) using inotify. It watches for:

- IN_CLOSE_WRITE: file finished uploading
- IN_MOVED_TO: file moved into directory

When a file event triggers, it calls queue_file_upload_scan() which
adds the file path to the YARA worker's async scan queue.

### eBPF/XDP Init

On startup, the daemon attempts to load an eBPF XDP program. If
HAS_EBPF is not defined, all eBPF functions are no-ops. The XDP
program attaches to the network interface and drops blocked IPs at
the NIC level (before Netfilter).

## fw_inspect.ko (Kernel LKM Variant)

### Source: kernel/fw_inspect.c

A loadable kernel module that hooks into Netfilter at:

- Hook: NF_INET_PRE_ROUTING
- Priority: NF_IP_PRI_FIRST

It uses a custom Netlink protocol (NETLINK_FW_INSPECT=31) to
communicate with fw_agent. The module parameter max_connections
(default 4096) controls the connection tracking pool size.

The kernel module performs the same detection chain as fw_nfq but
within kernel context. Events are sent to userspace via nlmsg_unicast.

### Local IP Bypass

Both implementations check local IPs:

```c
static int is_local_ip(uint32_t ip) {
    // 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
}
```

When g_block_local_ips is 0 (default), malicious traffic from private
IPs is logged but ACCEPTed. When set to 1, private IPs are also
blocked.

## Shared Detection Sources

The following source files are compiled into both fw_nfq and the
test suite, and some into the kernel module:

| File | Purpose |
|------|---------|
| http_inspect.c | HTTP payload analysis entry point |
| sqli_detect.c | SQL injection detection |
| cmdi_detect.c | Command injection detection |
| path_detect.c | Path traversal / LFI / RFI |
| bot_detect.c | Bot / scanner detection |
| ip_reputation.c | IP score tracking |
| ip_blocklist.c | CIDR blocklist matching |
| tcp_monitor.c | Connection state tracking |
| yara_engine.c | YARA signature scanning |
| ebpf_xdp.c | eBPF/XDP offload |
| fw_inspect.h | Shared structs and enums |

## Build

```
cd kernel/
make fw_nfq           # Build userspace daemon
make modules           # Build kernel module (fw_inspect.ko)
```

See kernel/Makefile for full build rules.
