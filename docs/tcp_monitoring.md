# TCP Monitoring

## Overview

The TCP monitor tracks connection states for SYN flood and Slowloris
detection. It maintains a fixed-size pool of connection entries,
indexed by a Jenkins one-at-a-time hash of (src_ip, src_port).

Source: kernel/tcp_monitor.c

## Connection Pool

- Size: 4096 entries (fixed, defined by POOL_SIZE)
- Indexing: Jenkins one-at-a-time hash over (src_ip, src_port)
- Locking: Spinlock (pool_lock) for all mutations
- Memory: Allocated via kzalloc in init_conn_pool()

### Entry Structure

```c
struct conn_state {
    uint32_t src_ip;
    uint32_t dest_ip;
    uint16_t src_port;
    uint16_t dest_port;
    unsigned long last_seen;           // jiffies timestamp
    unsigned long syn_window_start;    // syn window start (jiffies)
    uint32_t syn_count;                // syn count in current window
    unsigned long http_start_time;     // first http data seen
    uint8_t http_header_count;         // partial http headers count
    uint8_t is_http_complete;          // \r\n\r\n received
    uint8_t is_blocked;               // flagged for blocking
};
```

### Entry Lifecycle

1. **Allocation**: Created on first TCP packet for a unique
   (src_ip, src_port) pair.
2. **Reclamation on FIN/RST**: Immediately freed on FIN or RST
   packets.
3. **Inactivity timeout**: Entries not seen for 60 seconds are
   available for reuse.
4. **Collision override**: If a hash collision occurs and the
   existing entry has been inactive for 5 seconds, it is overwritten.
5. **Cleanup on shutdown**: cleanup_conn_pool() walks the entire
   pool and frees all entries.

## SYN Flood Detection

### Mechanism
- Monitor TCP packets where syn=1 and ack=0
- Sliding window: 1 second (jiffies-based)
- Threshold: 100 SYN packets per second per source IP

### Flow
1. Packet arrives with SYN=1, ACK=0
2. Look up or create connection state for (src_ip, src_port)
3. If current time > syn_window_start + HZ (1 second), reset counter
4. Increment syn_count
5. If syn_count > 100:
   - Set is_blocked = 1
   - Call send_fw_event() with THREAT_SYN_FLOOD (3)
   - Return 1 (DROP)
6. Otherwise return 0 (ACCEPT)

Once blocked, subsequent SYN packets from the same entry are
immediately dropped.

## Slowloris Detection

### Mechanism
Detects HTTP connections that send headers slowly (partial HTTP
headers without completing within the timeout window).

### Thresholds
- **Concurrent incomplete connections**: > 20 per source IP triggers
  immediate block. Counted as entries with the same src_ip where
  is_http_complete == 0.
- **Timeout**: 30 seconds (SLOWLORIS_TIMEOUT, defined as 30 * HZ).
  If a connection has partial headers (http_header_count > 0) but
  hasn't completed after 30 seconds, it is dropped.
- **Zero-byte filter**: Connections with 0 HTTP header bytes sent are
  silently ignored (avoids false positives from healthcheck probes).
- **Health check bypass**: Connections closed before any HTTP data
  is received are not logged.

### Flow
1. Packet arrives with data (not a pure SYN)
2. http_header_count is incremented by register_http_header_sent()
   (called from http_inspect.c when partial headers are seen)
3. is_http_complete is set by register_http_complete() (called when
   \r\n\r\n is received)
4. On each TCP packet, if is_http_complete == 0 and
   http_header_count > 0 and
   (jiffies - http_start_time) > SLOWLORIS_TIMEOUT:
   - Set is_blocked = 1
   - Call send_fw_event() with THREAT_SLOWLORIS (4)
   - Return 1 (DROP)
5. Also checks: if http_header_count > MAX_INCOMPLETE_HTTP (20)
   and is_http_complete == 0, return 1 (DROP) for that src_ip

## Integration with HTTP Inspector

http_inspect.c calls two functions to update TCP monitor state:

- register_http_header_sent(skb): Called on each HTTP data chunk
  before full inspection, increments http_header_count.
- register_http_complete(skb): Called when \r\n\r\n is detected
  in the HTTP payload, sets is_http_complete = 1.

These functions update the connection state entry looked up by the
same (src_ip, src_port) hash.
