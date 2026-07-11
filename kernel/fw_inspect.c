#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/netlink.h>
#include <net/sock.h>
#include "fw_inspect.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Antigravity");
MODULE_DESCRIPTION("Custom Kernel Firewall with HTTP payload inspection and TCP monitors");
MODULE_VERSION("1.0");

// Module Parameters
static int max_connections = 4096;
module_param(max_connections, int, 0644);
MODULE_PARM_DESC(max_connections, "Maximum tracked concurrent connections");

// Netlink Socket
static struct sock *nl_sk = NULL;
static int agent_pid = 0;

// External Inspection Functions (to be implemented in helper files)
extern int inspect_ip_blocklist(uint32_t src_ip);
extern void update_ip_blocklist(struct blocklist_payload *payload);
extern int inspect_http_payload(struct sk_buff *skb, struct iphdr *iph, struct tcphdr *tcph);
extern int monitor_tcp_stats(struct iphdr *iph, struct tcphdr *tcph);
extern int init_conn_pool(void);
extern void cleanup_conn_pool(void);

// Send event to userspace agent via Netlink
void send_fw_event(struct fw_event *event) {
    struct nlmsghdr *nlh;
    struct sk_buff *skb_out;
    int msg_size = sizeof(struct fw_event);
    int res;

    if (agent_pid == 0) {
        // No agent registered yet
        return;
    }

    skb_out = nlmsg_new(msg_size, GFP_ATOMIC);
    if (!skb_out) {
        printk(KERN_ERR "fw_inspect: Failed to allocate netlink socket buffer\n");
        return;
    }

    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
    memcpy(nlmsg_data(nlh), event, msg_size);

    res = nlmsg_unicast(nl_sk, skb_out, agent_pid);
    if (res < 0) {
        printk(KERN_WARNING "fw_inspect: Error while sending netlink message to agent (pid %d): %d\n", agent_pid, res);
    }
}
EXPORT_SYMBOL(send_fw_event);

// Handle commands from userspace agent (e.g. register agent, load blocklist)
static void fw_nl_recv_msg(struct sk_buff *skb) {
    struct nlmsghdr *nlh;
    void *payload;

    nlh = (struct nlmsghdr *)skb->data;
    payload = nlmsg_data(nlh);

    if (nlh->nlmsg_type == NLMSG_DONE) {
        // Check if message is a register command (pid registration)
        int command = *(int *)payload;
        if (command == 1) { // 1 = REGISTER_AGENT
            agent_pid = nlh->nlmsg_pid;
            printk(KERN_INFO "fw_inspect: Agent registered with PID %d\n", agent_pid);
        }
    } else if (nlh->nlmsg_type == 2) { // 2 = LOAD_BLOCKLIST
        struct blocklist_payload *bl_payload = (struct blocklist_payload *)payload;
        update_ip_blocklist(bl_payload);
        printk(KERN_INFO "fw_inspect: Loaded %d IP blocklist entries\n", bl_payload->count);
    }
}

extern int g_block_local_ips;

static int is_local_ip(uint32_t ip) {
    uint32_t host_ip = ntohl(ip);
    uint8_t o1 = (host_ip >> 24) & 0xFF;
    uint8_t o2 = (host_ip >> 16) & 0xFF;
    
    if (o1 == 127) return 1;
    if (o1 == 10) return 1;
    if (o1 == 172 && o2 >= 16 && o2 <= 31) return 1;
    if (o1 == 192 && o2 == 168) return 1;
    return 0;
}

// Netfilter Hook Function
static unsigned int fw_hook_fn(void *priv,
                             struct sk_buff *skb,
                             const struct nf_hook_state *state) {
    struct iphdr *iph;
    struct tcphdr *tcph;
    int verdict = NF_ACCEPT;

    if (!skb) return NF_ACCEPT;

    // Only inspect IPv4
    iph = ip_hdr(skb);
    if (!iph) return NF_ACCEPT;

    // 1. IP Blocklist Inspection
    if (inspect_ip_blocklist(iph->saddr)) {
        struct fw_event event = {
            .timestamp = ktime_get_real_seconds(),
            .src_ip = iph->saddr,
            .dest_ip = iph->daddr,
            .threat_type = THREAT_BLOCKLIST,
            .severity = SEVERITY_WARNING,
        };
        snprintf(event.payload_preview, sizeof(event.payload_preview), "IP Blocklisted");
        snprintf(event.details, sizeof(event.details), "Inbound connection blocked from blocklisted IP address");
        send_fw_event(&event);
        verdict = NF_DROP;
    }

    // Inspect TCP traffic
    if (verdict != NF_DROP && iph->protocol == IPPROTO_TCP) {
        // Ensure transport header is pulled
        tcph = tcp_hdr(skb);
        if (tcph) {
            // 2. TCP Stats Monitoring (SYN flood, Slowloris)
            if (monitor_tcp_stats(iph, tcph)) {
                verdict = NF_DROP;
            }
            // 3. HTTP Payload Inspection
            else if (ntohs(tcph->dest) == 80) {
                if (inspect_http_payload(skb, iph, tcph)) {
                    verdict = NF_DROP;
                }
            }
        }
    }

    // Apply local IP bypass logic
    if (verdict == NF_DROP && is_local_ip(iph->saddr)) {
        if (!g_block_local_ips) {
            verdict = NF_ACCEPT;
        }
    }

    return verdict;
}

// Hook registration struct
static struct nf_hook_ops fw_hook_ops = {
    .hook = fw_hook_fn,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};

// Module Init
static int __init fw_inspect_init(void) {
    struct netlink_kernel_cfg cfg = {
        .input = fw_nl_recv_msg,
    };
    int ret;

    printk(KERN_INFO "fw_inspect: Initializing firewall module\n");

    // Initialize connection pool
    ret = init_conn_pool();
    if (ret) {
        printk(KERN_ERR "fw_inspect: Failed to initialize connection pool\n");
        return ret;
    }

    // Create Netlink Socket
    nl_sk = netlink_kernel_create(&init_net, NETLINK_FW_INSPECT, &cfg);
    if (!nl_sk) {
        printk(KERN_ERR "fw_inspect: Failed to create netlink socket\n");
        cleanup_conn_pool();
        return -ENOMEM;
    }

    // Register Netfilter Hook
    if (nf_register_net_hook(&init_net, &fw_hook_ops) < 0) {
        printk(KERN_ERR "fw_inspect: Failed to register netfilter hook\n");
        netlink_kernel_release(nl_sk);
        cleanup_conn_pool();
        return -EFAULT;
    }

    printk(KERN_INFO "fw_inspect: Firewall module loaded successfully (max_connections=%d)\n", max_connections);
    return 0;
}

// Module Exit
static void __exit fw_inspect_exit(void) {
    printk(KERN_INFO "fw_inspect: Unloading firewall module\n");
    nf_unregister_net_hook(&init_net, &fw_hook_ops);
    if (nl_sk) {
        netlink_kernel_release(nl_sk);
    }
    cleanup_conn_pool();
    printk(KERN_INFO "fw_inspect: Firewall module unloaded successfully\n");
}

module_init(fw_inspect_init);
module_exit(fw_inspect_exit);
