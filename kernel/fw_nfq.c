#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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

#define BUILD_USERSPACE
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

// Connection pool functions
extern int init_conn_pool(void);
extern void cleanup_conn_pool(void);

// Inspection functions
extern int inspect_ip_blocklist(uint32_t src_ip);
extern void update_ip_blocklist(struct blocklist_payload *payload);
extern int inspect_http_payload(struct sk_buff *skb, struct iphdr *iph, struct tcphdr *tcph);
extern int monitor_tcp_stats(struct iphdr *iph, struct tcphdr *tcph);

// Implementation of send_fw_event for userspace (writes to UNIX socket)
void send_fw_event(struct fw_event *event) {
    pthread_mutex_lock(&agent_lock);
    if (agent_fd != -1) {
        int bytes_sent = write(agent_fd, event, sizeof(struct fw_event));
        if (bytes_sent < 0) {
            printf("[fw_nfq] Agent disconnected. Closing socket.\n");
            close(agent_fd);
            agent_fd = -1;
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
            int bytes_read = read(client_fd, &bl_payload, sizeof(struct blocklist_payload));
            if (bytes_read <= 0) {
                break; 
            }
            if (bytes_read == sizeof(struct blocklist_payload)) {
                update_ip_blocklist(&bl_payload);
                printf("[fw_nfq] Loaded %d IP blocklist entries from agent\n", bl_payload.count);
                
                for (uint32_t i = 0; i < bl_payload.count; i++) {
                    ebpf_xdp_block_ip(bl_payload.entries[i].ip);
                }
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

        // 1. IP Reputation Check (Score >= 80 blocks immediately)
        int rep_score = get_ip_reputation(iph->saddr);
        if (rep_score >= 80) {
            struct fw_event event = {
                .timestamp = ktime_get_real_seconds(),
                .src_ip = iph->saddr,
                .dest_ip = iph->daddr,
                .threat_type = THREAT_REPUTATION,
                .severity = SEVERITY_CRITICAL,
            };
            snprintf(event.payload_preview, sizeof(event.payload_preview), "IP Reputation: %d", rep_score);
            snprintf(event.details, sizeof(event.details), "Connection dropped: source IP reputation is malicious (score >= 80)");
            send_fw_event(&event);
            verdict = NF_DROP;
        }
        // 2. IP Blocklist check
        else if (inspect_ip_blocklist(iph->saddr)) {
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
        // Check TCP traffic
        else if (iph->protocol == IPPROTO_TCP && payload_len >= (int)(iph->ihl * 4 + sizeof(struct tcphdr))) {
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
    }

    return nfq_set_verdict(qh, id, verdict, 0, NULL);
}

int main(int argc, char **argv) {
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
