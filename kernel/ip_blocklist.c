#ifdef BUILD_USERSPACE
#include "userspace_compat.h"
#else
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/rcupdate.h>
#endif
#include "fw_inspect.h"

// Define a hash table for IP blocklist
// Use 8 bits for hash table size (256 buckets)
#define HASH_BITS 8

struct blocklist_node {
    uint32_t ip;
    uint8_t mask;
    struct hlist_node node;
    struct rcu_head rcu;
};

int g_block_local_ips = 0;

// Declaring the hash table
static DEFINE_HASHTABLE(blocklist_hash, HASH_BITS);
static DEFINE_SPINLOCK(blocklist_lock);

// Check if IP is in the blocklist
int inspect_ip_blocklist(uint32_t src_ip) {
    struct blocklist_node *curr;
    int bucket;
    int match = 0;

    rcu_read_lock();
    // We hash the IP. For simple prefix matching, we could look up exact IP or check subnet masks.
    // For high performance, we hash the IP and look for exact matches or iterate over matches.
    // Let's do a fast lookup for exact IP matching or subnet match
    hash_for_each_rcu(blocklist_hash, bucket, curr, node) {
        // Calculate subnet mask
        uint32_t mask_val = curr->mask == 0 ? 0 : (~0U << (32 - curr->mask));
        // On IPv4, network byte order is big endian. Let's compare correctly.
        if (curr->mask == 32) {
            if (curr->ip == src_ip) {
                match = 1;
                break;
            }
        } else {
            // Apply subnet mask in host byte order
            uint32_t masked_src = ntohl(src_ip) & mask_val;
            uint32_t masked_bl = ntohl(curr->ip) & mask_val;
            if (masked_src == masked_bl) {
                match = 1;
                break;
            }
        }
    }
    rcu_read_unlock();

    return match;
}

// Update the IP blocklist (atomic swap using RCU/spinlocks)
void update_ip_blocklist(struct blocklist_payload *payload) {
    struct blocklist_node *curr;
    struct hlist_node *tmp;
    int bucket;
    int i;
    
    spin_lock(&blocklist_lock);
    g_block_local_ips = payload->block_local_ips;

    // 1. Clear old blocklist and free nodes
    for (bucket = 0; bucket < (1 << HASH_BITS); bucket++) {
        struct hlist_node *n = blocklist_hash[bucket];
        while (n) {
            struct blocklist_node *node_to_free = container_of(n, struct blocklist_node, node);
            n = n->next;
            free(node_to_free);
        }
        blocklist_hash[bucket] = NULL;
    }

    // 2. Load new blocklist
    for (i = 0; i < payload->count && i < MAX_BLOCKLIST_IPS; i++) {
        struct blocklist_node *new_node = kmalloc(sizeof(struct blocklist_node), GFP_ATOMIC);
        if (new_node) {
            new_node->ip = payload->entries[i].ip;
            new_node->mask = payload->entries[i].mask;
            hash_add_rcu(blocklist_hash, &new_node->node, new_node->ip);
        }
    }

    spin_unlock(&blocklist_lock);
}
