#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/inotify.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>

#ifndef BUILD_USERSPACE
#define BUILD_USERSPACE
#endif
#include "userspace_compat.h"
#include "fw_inspect.h"
#include "ip_reputation.h"
#include "yara_engine.h"
#include "ebpf_xdp.h"

#define UNIX_SOCK_PATH "/var/run/fw_inspect.sock"
#define EVENT_SIZE  ( sizeof (struct inotify_event) )
#define BUF_LEN     ( 1024 * ( EVENT_SIZE + 16 ) )

// Active agent socket fd
static int agent_fd = -1;
static pthread_mutex_t agent_lock = PTHREAD_MUTEX_INITIALIZER;
// Drop counter — incremented when send_fw_event discards events because the
// agent UNIX socket buffer is full. Exposed so SOC or health endpoint can
// warn about agent throughput bottleneck.
static volatile unsigned long dropped_event_count = 0;

// Connection pool functions
extern int init_conn_pool(void);
extern void cleanup_conn_pool(void);

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

static int is_bypassed_ip(uint32_t ip) {
    uint32_t host_ip = ntohl(ip);
    uint8_t o1 = (host_ip >> 24) & 0xFF;
    uint8_t o2 = (host_ip >> 16) & 0xFF;
    uint8_t o3 = (host_ip >> 8) & 0xFF;
    
    // 1. Loopback is always bypassed
    if (o1 == 127) return 1;
    
    // 2. Docker Desktop host gateway network (192.168.65.0/24)
    // Only bypass if we are running inside Docker to avoid affecting bare metal systems
    static int in_docker = -1;
    if (in_docker == -1) {
        in_docker = (access("/.dockerenv", F_OK) == 0);
    }
    if (in_docker && o1 == 192 && o2 == 168 && o3 == 65) return 1;
    
    // 3. Container's default gateway (dynamically read from /proc/net/route)
    static uint32_t default_gw = 0;
    static int gw_initialized = 0;
    if (!gw_initialized) {
        FILE *f = fopen("/proc/net/route", "r");
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                char iface[32];
                uint32_t dest, gateway;
                if (sscanf(line, "%31s %x %x", iface, &dest, &gateway) == 3) {
                    if (dest == 0) { // Default route
                        default_gw = gateway;
                        break;
                    }
                }
            }
            fclose(f);
        }
        gw_initialized = 1;
    }
    
    if (default_gw != 0 && ip == default_gw) return 1;
    
    return 0;
}

// Inspection functions
extern int inspect_ip_blocklist(uint32_t src_ip);
extern void update_ip_blocklist(struct blocklist_payload *payload);
extern int inspect_http_payload(struct sk_buff *skb, struct iphdr *iph, struct tcphdr *tcph);
extern int monitor_tcp_stats(struct iphdr *iph, struct tcphdr *tcph);

// Implementation of send_fw_event for userspace (writes to UNIX socket)
// Uses non-blocking writes so the NFQUEUE callback never stalls when the
// agent is overwhelmed. Events that can't be delivered are counted and dropped.
void send_fw_event(struct fw_event *event) {
    pthread_mutex_lock(&agent_lock);
    if (agent_fd != -1) {
        int bytes_sent = send(agent_fd, event, sizeof(struct fw_event), MSG_DONTWAIT);
        if (bytes_sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Socket buffer full — agent is backlogged. Drop event
                // gracefully instead of blocking the entire NFQUEUE pipeline.
                dropped_event_count++;
            } else {
                printf("[fw_nfq] Agent disconnected. Closing socket.\n");
                close(agent_fd);
                agent_fd = -1;
            }
        } else {
            printf("[fw_nfq] Alert sent to agent. Threat type: %d, Severity: %d\n", event->threat_type, event->severity);
        }
    } else {
        printf("[fw_nfq] Alert dropped (no agent connected). Threat type: %d\n", event->threat_type);
    }
    pthread_mutex_unlock(&agent_lock);
}

// Inotify directory watcher thread to scan uploads asynchronously with YARA
void *yara_inotify_thread(void *arg) {
    int length, i = 0;
    int fd;
    int wd;
    char buffer[BUF_LEN];

    const char *upload_dir = getenv("UPLOAD_DIR") ? getenv("UPLOAD_DIR") : "/var/www/uploads";
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "mkdir -p %s", upload_dir);
    if (system(cmd) < 0) {
        perror("[fw_nfq] failed to create upload directory");
    }

    fd = inotify_init();
    if (fd < 0) {
        perror("[fw_nfq] inotify_init failed");
        return NULL;
    }

    wd = inotify_add_watch(fd, upload_dir, IN_CLOSE_WRITE | IN_MOVED_TO);
    if (wd < 0) {
        perror("[fw_nfq] inotify_add_watch failed");
        close(fd);
        return NULL;
    }

    printf("[fw_nfq] YARA inotify watcher active on %s\n", upload_dir);

    while (1) {
        i = 0;
        length = read(fd, buffer, BUF_LEN);
        if (length < 0) {
            break;
        }

        while (i < length) {
            struct inotify_event *event = (struct inotify_event *) &buffer[i];
            if (event->len) {
                if (event->mask & (IN_CLOSE_WRITE | IN_MOVED_TO)) {
                    char filepath[512];
                    snprintf(filepath, sizeof(filepath), "%s/%s", upload_dir, event->name);
                    queue_file_upload_scan(filepath);
                }
            }
            i += EVENT_SIZE + event->len;
        }
    }

    inotify_rm_watch(fd, wd);
    close(fd);
    return NULL;
}

// Thread to handle incoming commands from the agent (e.g. loading blocklist)
void *agent_listener_thread(void *arg) {
    int server_fd = *(int *)arg;
    free(arg);

    while (1) {
        printf("[fw_nfq] Waiting for agent to connect at %s...\n", UNIX_SOCK_PATH);
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            perror("[fw_nfq] accept failed");
            sleep(1);
            continue;
        }

        pthread_mutex_lock(&agent_lock);
        if (agent_fd != -1) {
            close(agent_fd);
        }
        agent_fd = client_fd;
        pthread_mutex_unlock(&agent_lock);
        printf("[fw_nfq] Agent connected successfully!\n");

        struct blocklist_payload bl_payload;
        while (1) {
            int total_read = 0;
            char *ptr = (char *)&bl_payload;
            while (total_read < sizeof(struct blocklist_payload)) {
                int r = read(client_fd, ptr + total_read, sizeof(struct blocklist_payload) - total_read);
                if (r <= 0) break;
                total_read += r;
            }
            
            if (total_read == 0) {
                break; // EOF
            }
            
            if (total_read == sizeof(struct blocklist_payload)) {
                update_ip_blocklist(&bl_payload);
                printf("[fw_nfq] Loaded %d IP blocklist entries from agent\n", bl_payload.count);
                for (uint32_t i = 0; i < bl_payload.count; i++) {
                    ebpf_xdp_block_ip(bl_payload.entries[i].ip);
                }
            } else {
                break; // Short read or error
            }
        }

        pthread_mutex_lock(&agent_lock);
        if (agent_fd == client_fd) {
            close(agent_fd);
            agent_fd = -1;
        }
        pthread_mutex_unlock(&agent_lock);
        printf("[fw_nfq] Agent disconnected.\n");
    }
    return NULL;
}

// Callback for NFQUEUE packet evaluation
static int fw_nfq_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                      struct nfq_data *nfa, void *data) {
    uint32_t id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    unsigned char *payload;
    int payload_len;
    int verdict = NF_ACCEPT;

    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
    }

    payload_len = nfq_get_payload(nfa, &payload);
    if (payload_len >= (int)sizeof(struct iphdr)) {
        struct sk_buff skb;
        skb.data = payload;
        skb.len = payload_len;

        struct iphdr *iph = (struct iphdr *)payload;

        // 0. Bypassed IP check (loopback/gateway) - always accept
        if (is_bypassed_ip(iph->saddr)) {
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
        }

        // 1. IP Reputation Check — block IPs with poor reputation
        int rep_score = get_ip_reputation(iph->saddr);
        if (rep_score <= 20) {
            struct fw_event event = {
                .timestamp = ktime_get_real_seconds(),
                .src_ip = iph->saddr,
                .dest_ip = iph->daddr,
                .threat_type = THREAT_REPUTATION,
                .severity = SEVERITY_CRITICAL,
            };
            snprintf(event.payload_preview, sizeof(event.payload_preview), "IP Reputation: %d", rep_score);
            snprintf(event.details, sizeof(event.details), "Low reputation score — blocking IP (score <= 20)");
            send_fw_event(&event);
            verdict = NF_DROP;
        }
        // 2. IP Blocklist check
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
        // Check TCP traffic independently
        if (iph->protocol == IPPROTO_TCP && payload_len >= (int)(iph->ihl * 4 + sizeof(struct tcphdr))) {
            struct tcphdr *tcph = (struct tcphdr *)(payload + (iph->ihl * 4));

            // 3. TCP Stats check (SYN flood, Slowloris)
            if (monitor_tcp_stats(iph, tcph)) {
                verdict = NF_DROP;
            }
            // 4. HTTP payload check
            else if (ntohs(tcph->dest) == 80) {
                if (inspect_http_payload(&skb, iph, tcph)) {
                    verdict = NF_DROP;
                }
            }
        }

        // Apply local IP bypass logic: allow local IP threats (e.g. LAN) unless g_block_local_ips is enabled
        if (verdict == NF_DROP && is_local_ip(iph->saddr)) {
            if (!g_block_local_ips) {
                printf("[fw_nfq] Local IP threat bypassed: ALLOWED.\n");
                verdict = NF_ACCEPT;
            }
        }
    }

    return nfq_set_verdict(qh, id, verdict, 0, NULL);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("[fw_nfq] Starting Userspace NFQUEUE Firewall Daemon...\n");

    // Initialize detection engines & structures
    init_ip_reputation();
    init_yara_engine("/etc/fw_inspect/yara");
    
    // eBPF/XDP load attempt on eth0 (defaults to mock/compat mode if not supported)
    init_ebpf_xdp("eth0");

    // Initialize connection pool
    if (init_conn_pool() != 0) {
        fprintf(stderr, "[fw_nfq] Failed to initialize connection pool\n");
        return 1;
    }

    // Set up UNIX Domain Socket Server for agent communication
    unlink(UNIX_SOCK_PATH);
    int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("[fw_nfq] UNIX socket creation failed");
        cleanup_conn_pool();
        return 1;
    }

    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, UNIX_SOCK_PATH, sizeof(sa.sun_path) - 1);

    if (bind(server_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("[fw_nfq] bind failed");
        close(server_fd);
        cleanup_conn_pool();
        return 1;
    }

    if (listen(server_fd, 5) < 0) {
        perror("[fw_nfq] listen failed");
        close(server_fd);
        cleanup_conn_pool();
        return 1;
    }

    // Allow any container user to read/write socket if needed
    chmod(UNIX_SOCK_PATH, 0666);

    // Launch agent listener thread
    pthread_t thread_id;
    int *arg_fd = malloc(sizeof(*arg_fd));
    *arg_fd = server_fd;
    if (pthread_create(&thread_id, NULL, agent_listener_thread, arg_fd) != 0) {
        perror("[fw_nfq] Failed to create listener thread");
        close(server_fd);
        cleanup_conn_pool();
        return 1;
    }
    pthread_detach(thread_id);

    // Launch YARA inotify watcher thread
    pthread_t inotify_tid;
    if (pthread_create(&inotify_tid, NULL, yara_inotify_thread, NULL) != 0) {
        perror("[fw_nfq] Failed to create YARA inotify watcher thread");
    }
    pthread_detach(inotify_tid);

    // Initialize Netfilter Queue
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "[fw_nfq] error during nfq_open()\n");
        close(server_fd);
        cleanup_conn_pool();
        return 1;
    }

    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "[fw_nfq] error during nfq_unbind_pf()\n");
        nfq_close(h);
        close(server_fd);
        cleanup_conn_pool();
        return 1;
    }

    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "[fw_nfq] error during nfq_bind_pf()\n");
        nfq_close(h);
        close(server_fd);
        cleanup_conn_pool();
        return 1;
    }

    // Create queue 0
    qh = nfq_create_queue(h, 0, &fw_nfq_callback, NULL);
    if (!qh) {
        fprintf(stderr, "[fw_nfq] error during nfq_create_queue()\n");
        nfq_close(h);
        close(server_fd);
        cleanup_conn_pool();
        return 1;
    }

    // Set queue copy mode
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "[fw_nfq] can't set packet copy mode\n");
        nfq_destroy_queue(qh);
        nfq_close(h);
        close(server_fd);
        cleanup_conn_pool();
        return 1;
    }

    fd = nfq_fd(h);
    printf("[fw_nfq] NFQUEUE setup complete. Intercepting packets on queue 0...\n");

    while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
        nfq_handle_packet(h, buf, rv);
    }

    printf("[fw_nfq] Stopping daemon...\n");
    nfq_destroy_queue(qh);
    nfq_close(h);
    close(server_fd);
    unlink(UNIX_SOCK_PATH);
    cleanup_conn_pool();

    // Clean up detection modules
    cleanup_ebpf_xdp();
    cleanup_yara_engine();
    cleanup_ip_reputation();

    return 0;
}
