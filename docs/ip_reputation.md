# IP Reputation System

## Overview

The IP reputation system tracks a numeric score for each source IP.
A HIGH score (100) indicates GOOD reputation (trusted IP). A LOW
score (<= 20) indicates a MALICIOUS IP that should be blocked.

The system has been corrected so that the semantics are intuitive:
high = trusted, low = malicious. Originally this was inverted.

## Kernel-Level Reputation (ip_reputation.c)

### Storage
A linked-list hash table with HASH_SIZE=1024 buckets.

```c
struct ip_reputation_entry {
    uint32_t ip;
    int score;
    unsigned long last_seen;       // jiffies
    uint32_t attack_types_mask;    // bitmask by threat_type
    struct ip_reputation_entry *next;
};
```

Hashing uses a Jenkins one-at-a-time variant.

### Locking
A single mutex (rep_mutex) protects all hash table operations.

### API

| Function | Description |
|----------|-------------|
| init_ip_reputation() | Initialize mutex and hash table |
| cleanup_ip_reputation() | Free all entries, destroy mutex |
| get_ip_reputation(ip) | Return score (0-100). Returns 100 for unknown IPs |
| update_ip_reputation(ip, damage, threat_type) | Subtract damage from score. Creates new entry at (100 - damage) if not found |
| decay_reputation_scores(recovery_amount) | Add recovery_amount to all scores. Remove entries where score >= 100 |

### Entry Lifecycle

1. **Creation**: On first malicious event, entry created with
   score = 100 - damage.
2. **Updates**: Each subsequent event subtracts more damage.
   Score is clamped to minimum 0.
3. **Decay**: Periodically, scores are increased by a recovery
   amount (simulating time-based healing).
4. **Removal**: When score reaches 100 or above via decay, entry
   is removed from the table.
5. **Unknown IPs**: get_ip_reputation() returns 100 (perfect trust)
   for IPs not in the table.

### Attack Types Mask
A bitmask tracking which attack types this IP has engaged in.
Bit position corresponds to threat_type.

## Database Reputation (PostgreSQL)

The database stores a more detailed reputation with three separate
score columns:

### Schema (ip_reputation table)

| Column | Type | Description |
|--------|------|-------------|
| ip | INET PK | IP address |
| score | INTEGER | Combined score (min of local and external) |
| local_score | INTEGER | Score from local firewall events |
| external_score | INTEGER | Score from external threat intel feeds |
| total_blocks | INTEGER | Total block count |
| attack_types | TEXT[] | Array of attack type strings |
| first_seen | TIMESTAMPTZ | First time this IP was seen |
| last_seen | TIMESTAMPTZ | Most recent event timestamp |
| manual_override | INTEGER | Admin-set score override (-1 = disabled) |
| updated_at | TIMESTAMPTZ | Last update timestamp |

### Score Arithmetic

**Combined Score** (the effective score used for blocking):
```
score = LEAST(local_score, external_score)
```
The combined score is the more suspicious (lower) of the two sources.

**Local Score** is calculated in NotificationService.java every 30
seconds by aggregating events by src_ip:
```
local_score = GREATEST(0, 100 - SUM(severity_weight))
```

Severity weight mapping:
- CRITICAL (severity=2): 25 points
- WARNING (severity=1): 15 points
- INFO (severity=0): 5 points

**External Score** is set by threat intelligence feeds (Feodo,
BinaryDefense, CI Army) and is always <= 25 for known malicious IPs.

### Auto-Blocking

NotificationService.java runs every 30 seconds:
```sql
INSERT INTO blocklist (ip_cidr, list_type, reason, source)
SELECT ip, 'block', 'Auto-blocked: Low reputation (Score: ' || score || ')', 'system'
FROM ip_reputation r
WHERE score <= 20
  AND NOT EXISTS (
      SELECT 1 FROM blocklist b WHERE b.ip_cidr = r.ip
  )
```

This automatically adds IPs with score <= 20 to the blocklist.

### Manual Override

Admin can set a manual score override via the dashboard. When set to
-1 (default), the automatic scoring takes effect.

## Threat Intel Feed Scores

When threat intelligence feeds import IPs, they set external scores:

| Feed | External Score | Description |
|------|---------------|-------------|
| Feodo Tracker | 15 | Known botnet C2 servers |
| Binary Defense | 20 | Known malicious IPs |
| CI Army | 25 | Known scanners |

## Firewall Block Threshold

In fw_nfq.c, the packet callback checks:
```c
if (rep_score <= 20) {
    // DROP packet, log event, update reputation
}
```

Scores above 20 pass through to further inspection.
