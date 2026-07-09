#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ebpf_xdp.h"

#ifdef HAS_EBPF
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <linux/if_link.h>

static int map_fd = -1;
static int ifindex = -1;
static struct bpf_object *obj = NULL;
#endif

int init_ebpf_xdp(const char *ifname) {
#ifdef HAS_EBPF
    struct bpf_program *prog;
    int prog_fd;

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "[ebpf_xdp] Invalid interface name: %s\n", ifname);
        return -1;
    }

    // Load compiled BPF skeleton / object
    obj = bpf_object__open_file("xdp_firewall.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "[ebpf_xdp] Failed to open BPF object file\n");
        return -1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "[ebpf_xdp] Failed to load BPF object\n");
        bpf_object__close(obj);
        obj = NULL;
        return -1;
    }

    // Find the XDP program and attach it
    prog = bpf_object__find_program_by_name(obj, "xdp_firewall_prog");
    if (!prog) {
        fprintf(stderr, "[ebpf_xdp] Failed to find BPF program\n");
        bpf_object__close(obj);
        obj = NULL;
        return -1;
    }

    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "[ebpf_xdp] Failed to get program FD\n");
        bpf_object__close(obj);
        obj = NULL;
        return -1;
    }

    // Attach to network interface
    int err = bpf_set_link_xdp_fd(ifindex, prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST);
    if (err < 0) {
        fprintf(stderr, "[ebpf_xdp] Failed to attach XDP to %s (error: %d)\n", ifname, err);
        bpf_object__close(obj);
        obj = NULL;
        return -1;
    }

    // Find map for blocked IPs
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "blocked_ips");
    if (map) {
        map_fd = bpf_map__fd(map);
    }

    printf("[ebpf_xdp] Attached XDP firewall program to interface %s successfully\n", ifname);
    return 0;
#else
    printf("[ebpf_xdp] eBPF/XDP compiled in compatibility mode (no BPF macro). Falls back to NFQUEUE filtering.\n");
    return 0;
#endif
}

void cleanup_ebpf_xdp(void) {
#ifdef HAS_EBPF
    if (ifindex > 0) {
        bpf_set_link_xdp_fd(ifindex, -1, 0);
        ifindex = -1;
    }
    if (obj) {
        bpf_object__close(obj);
        obj = NULL;
    }
    map_fd = -1;
    printf("[ebpf_xdp] Detached XDP program.\n");
#endif
}

int ebpf_xdp_block_ip(uint32_t ip) {
#ifdef HAS_EBPF
    if (map_fd < 0) return -1;
    uint32_t val = 0;
    int err = bpf_map_update_elem(map_fd, &ip, &val, BPF_ANY);
    if (err) {
        fprintf(stderr, "[ebpf_xdp] Failed to block IP in BPF map (error: %d)\n", err);
        return -1;
    }
    printf("[ebpf_xdp] Successfully blocked IP in XDP hardware/driver table.\n");
    return 0;
#else
    printf("[ebpf_xdp] Blocked IP (compat mode): %u\n", ip);
    return 0;
#endif
}

int ebpf_xdp_unblock_ip(uint32_t ip) {
#ifdef HAS_EBPF
    if (map_fd < 0) return -1;
    int err = bpf_map_delete_elem(map_fd, &ip);
    if (err) {
        fprintf(stderr, "[ebpf_xdp] Failed to unblock IP in BPF map (error: %d)\n", err);
        return -1;
    }
    printf("[ebpf_xdp] Successfully unblocked IP in XDP hardware/driver table.\n");
    return 0;
#else
    printf("[ebpf_xdp] Unblocked IP (compat mode): %u\n", ip);
    return 0;
#endif
}
