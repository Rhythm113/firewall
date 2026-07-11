# eBPF / XDP Filtering

## Overview

The eBPF/XDP component provides NIC-level packet dropping for
blocklisted IPs. It drops packets before they reach the kernel
Netfilter stack, providing a performance benefit for known-bad IPs.

Compiled with HAS_EBPF: the feature is active.
Without HAS_EBPF: all functions are no-ops (compat mode).

## Source Files

- kernel/ebpf_xdp.h: API declarations
- kernel/ebpf_xdp.c: Load/unload/update implementation (no-ops
  without HAS_EBPF)
- kernel/xdp_firewall.bpf.c: The eBPF program loaded into the kernel

## eBPF Program (xdp_firewall.bpf.c)

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);    // IP address (network byte order)
    __type(value, __u8);   // 1 = blocked
} blocked_ips SEC(".maps");

SEC("xdp")
int xdp_block_ip(struct xdp_md *ctx) {
    // Parse Ethernet header
    // Check ETH_P_IP
    // Parse IP header, extract src_ip
    // Lookup src_ip in blocked_ips map
    // If found: increment drop_counter, return XDP_DROP
    // If not found: return XDP_PASS
}
```

### Map
- Type: BPF_MAP_TYPE_HASH
- Key: __u32 (IP address in network byte order)
- Value: __u8 (non-zero = blocked)
- Max entries: 65536

### Action
- XDP_DROP on blocked IP match
- XDP_PASS on no match (continues to normal Netfilter processing)
- Atomic drop counter increment on each drop

## Userspace Interface (ebpf_xdp.c)

### API

| Function | Description |
|----------|-------------|
| init_ebpf_xdp(ifname) | Load xdp_firewall.bpf.o, attach to interface, find map fd. Without HAS_EBPF: return 0 (no-op) |
| ebpf_xdp_block_ip(ip) | Update BPF map with key=ip, value=1. No-op without HAS_EBPF |
| ebpf_xdp_unblock_ip(ip) | Delete key from BPF map. No-op without HAS_EBPF |
| cleanup_ebpf_xdp() | Detach XDP program from interface. No-op without HAS_EBPF |

### Initialization Flow
1. Load the compiled eBPF object file (xdp_firewall.bpf.o)
2. Find the SEC(".maps") section containing blocked_ips map
3. Attach the XDP program to the specified network interface
4. Store file descriptor for map update operations

### Block/Unblock Operations
Called from fw_nfq.c when IPs are added to or removed from the
blocklist. The kernel BPF map is updated in parallel with the
userspace blocklist.

## Compilation

The eBPF program requires:
- LLVM/clang (for compiling .bpf.c to BPF bytecode)
- libbpf development headers
- Linux kernel with BPF support enabled

Standard kernel compilation path: the .bpf.c file is compiled with
clang -target bpf to produce xdp_firewall.bpf.o, which is then
loaded by the userspace daemon.

## Integration

When the blocklist is updated (via SOC command or loading
blocklist.txt), fw_nfq calls both:
1. update_ip_blocklist() -- userspace blocklist hash table
2. ebpf_xdp_block_ip() -- kernel BPF map

This ensures both layers are synchronized. The XDP layer provides
early dropping while the userspace layer provides detailed event
logging.
