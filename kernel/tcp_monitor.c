#ifdef BUILD_USERSPACE
#include "userspace_compat.h"
#else
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/jiffies.h>
#include <linux/slab.h>
#endif
#include "fw_inspect.h"

#define MAX_TRACKED_CONNS 4096
#define SYN_FLOOD_THRESHOLD 100 // 100 SYN packets per second
#define SLOWLORIS_TIMEOUT 30     // 30 seconds timeout for incomplete HTTP headers

// Structure to track connection state
struct conn_state {
    uint32_t src_ip;
    uint16_t src_port;
    uint16_t dest_port;
    unsigned long last_seen;
    unsigned long syn_window_start;
    uint32_t syn_count;
    unsigned long http_start_time;
    uint8_t http_header_count;
    uint8_t is_http_complete;
    uint8_t is_blocked;
};

// Fixed pool of connection state structs (zero dynamic allocation after init)
static struct conn_state *conn_pool = NULL;
static DEFINE_SPINLOCK(pool_lock);

// Initialize connection pool
int init_conn_pool(void) {
    conn_pool = kzalloc(sizeof(struct conn_state) * MAX_TRACKED_CONNS, GFP_KERNEL);
    if (!conn_pool) return -ENOMEM;
    return 0;
}

// Cleanup connection pool
void cleanup_conn_pool(void) {
    kfree(conn_pool);
}

#ifdef BUILD_USERSPACE
static uint32_t conn_hash(uint32_t ip, uint16_t port);
struct conn_state *test_get_conn_state(uint32_t ip, uint16_t port) {
    if (!conn_pool) return NULL;
    uint32_t index = conn_hash(ip, port);
    return &conn_pool[index];
}
#endif

// Simple hash function for IP/Port to index the pool
static uint32_t conn_hash(uint32_t ip, uint16_t port) {
    // Jenkins One-at-a-time hash
    uint32_t hash = ip;
    hash += (hash << 10);
    hash ^= (hash >> 6);
    hash += port;
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return hash % MAX_TRACKED_CONNS;
}

// External callback to send event to userspace agent
extern void send_fw_event(struct fw_event *event);

// Core TCP stats monitoring (SYN flood & Slowloris)
int monitor_tcp_stats(struct iphdr *iph, struct tcphdr *tcph) {
    uint32_t src_ip = iph->saddr;
    uint16_t src_port = tcph->source;
    uint16_t dest_port = tcph->dest;
    uint32_t index = conn_hash(src_ip, src_port);
    struct conn_state *conn;
    unsigned long now = jiffies;
    int drop_packet = 0;

    if (!conn_pool) return 0;

    spin_lock(&pool_lock);
    conn = &conn_pool[index];

    // If entry is empty or occupied by another connection, reclaim it
    if (conn->src_ip != src_ip || conn->src_port != src_port) {
        // Evict if inactive or timeout has passed
        if (conn->src_ip == 0 || time_after(now, conn->last_seen + (HZ * 60))) {
            memset(conn, 0, sizeof(struct conn_state));
            conn->src_ip = src_ip;
            conn->src_port = src_port;
            conn->dest_port = dest_port;
            conn->syn_window_start = now;
            conn->last_seen = now;
        } else {
            // Hash collision on active connection. For safety in basic implementation:
            // update and override if older than 5s
            if (time_after(now, conn->last_seen + (HZ * 5))) {
                memset(conn, 0, sizeof(struct conn_state));
                conn->src_ip = src_ip;
                conn->src_port = src_port;
                conn->dest_port = dest_port;
                conn->syn_window_start = now;
                conn->last_seen = now;
            } else {
                // Let it pass (false negative prevention under collision)
                spin_unlock(&pool_lock);
                return 0;
            }
        }
    }

    conn->last_seen = now;

    // 1. SYN Flood Detection
    if (tcph->syn && !tcph->ack) {
        // Check sliding window (1 second = HZ)
        if (time_after(now, conn->syn_window_start + HZ)) {
            conn->syn_count = 1;
            conn->syn_window_start = now;
        } else {
            conn->syn_count++;
            if (conn->syn_count > SYN_FLOOD_THRESHOLD) {
                conn->is_blocked = 1;
                drop_packet = 1;
                
                // Raise Alert (throttled by only sending once per window)
                if (conn->syn_count == SYN_FLOOD_THRESHOLD + 1) {
                    struct fw_event event = {
                        .timestamp = ktime_get_real_seconds(),
                        .src_ip = src_ip,
                        .dest_ip = iph->daddr,
                        .src_port = src_port,
                        .dest_port = dest_port,
                        .threat_type = THREAT_SYN_FLOOD,
                        .severity = SEVERITY_CRITICAL,
                    };
                    snprintf(event.payload_preview, sizeof(event.payload_preview), "SYN Flood Detected");
                    snprintf(event.details, sizeof(event.details), "SYN Rate: %u/sec (Threshold: %d)", conn->syn_count, SYN_FLOOD_THRESHOLD);
                    send_fw_event(&event);
                }
            }
        }
    }

    if (conn->is_blocked) {
        spin_unlock(&pool_lock);
        return 1; // Drop if flagged blocked
    }

    // 2. Slowloris Detection (port 80 HTTP)
    if (ntohs(dest_port) == 80 && !conn->is_http_complete) {
        if (conn->http_start_time == 0) {
            conn->http_start_time = now;
        }

        // Check if connection has timed out before completing headers
        if (time_after(now, conn->http_start_time + (HZ * SLOWLORIS_TIMEOUT))) {
            drop_packet = 1;
            conn->is_blocked = 1; // Block future segments of this connection

            struct fw_event event = {
                .timestamp = ktime_get_real_seconds(),
                .src_ip = src_ip,
                .dest_ip = iph->daddr,
                .src_port = src_port,
                .dest_port = dest_port,
                .threat_type = THREAT_SLOWLORIS,
                .severity = SEVERITY_WARNING,
            };
            snprintf(event.payload_preview, sizeof(event.payload_preview), "Slowloris Timeout");
            snprintf(event.details, sizeof(event.details), "HTTP request headers took longer than %d seconds to complete", SLOWLORIS_TIMEOUT);
            send_fw_event(&event);
        }
    }

    spin_unlock(&pool_lock);
    return drop_packet;
}
