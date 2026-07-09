#ifndef EBPF_XDP_H
#define EBPF_XDP_H

#include <stdint.h>

/**
 * Loads the compiled eBPF/XDP object file and attaches it to the specified interface.
 * If eBPF/XDP is not supported (eBPF build flag not set or kernel incompatible),
 * this falls back to userspace-only logging.
 *
 * @param ifname The network interface name (e.g. eth0).
 * @return 0 on success, -1 on failure.
 */
int init_ebpf_xdp(const char *ifname);

/**
 * Detaches the XDP program and cleans up eBPF maps and resources.
 */
void cleanup_ebpf_xdp(void);

/**
 * Adds an IP to the eBPF/XDP blocked list map.
 *
 * @param ip IP address (in network byte order).
 * @return 0 on success, -1 on failure.
 */
int ebpf_xdp_block_ip(uint32_t ip);

/**
 * Removes an IP from the eBPF/XDP blocked list map.
 *
 * @param ip IP address (in network byte order).
 * @return 0 on success, -1 on failure.
 */
int ebpf_xdp_unblock_ip(uint32_t ip);

#endif // EBPF_XDP_H
