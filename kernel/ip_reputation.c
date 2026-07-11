#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "ip_reputation.h"

#define HASH_SIZE 1024

struct reputation_entry {
    uint32_t ip;
    int score;
    time_t last_seen;
    uint32_t attack_types_mask;
    struct reputation_entry *next;
};

static struct reputation_entry *reputation_table[HASH_SIZE];
static pthread_mutex_t rep_lock = PTHREAD_MUTEX_INITIALIZER;

static uint32_t hash_ip(uint32_t ip) {
    // Jenkins one-at-a-time hash for 32-bit IP
    uint32_t hash = ip;
    hash = (hash + 0x7ed55d16) + (hash << 12);
    hash = (hash ^ 0xc761c23c) ^ (hash >> 19);
    hash = (hash + 0x165667b1) + (hash << 5);
    hash = (hash + 0xd3a2646c) ^ (hash << 9);
    hash = (hash + 0xfd7046c5) + (hash << 3);
    hash = (hash ^ 0xb55a4f09) ^ (hash >> 16);
    return hash % HASH_SIZE;
}

int init_ip_reputation(void) {
    pthread_mutex_lock(&rep_lock);
    memset(reputation_table, 0, sizeof(reputation_table));
    pthread_mutex_unlock(&rep_lock);
    return 0;
}

void cleanup_ip_reputation(void) {
    pthread_mutex_lock(&rep_lock);
    for (int i = 0; i < HASH_SIZE; i++) {
        struct reputation_entry *entry = reputation_table[i];
        while (entry) {
            struct reputation_entry *tmp = entry;
            entry = entry->next;
            free(tmp);
        }
        reputation_table[i] = NULL;
    }
    pthread_mutex_unlock(&rep_lock);
}

int get_ip_reputation(uint32_t ip) {
    uint32_t bucket = hash_ip(ip);
    pthread_mutex_lock(&rep_lock);

    struct reputation_entry *entry = reputation_table[bucket];
    while (entry) {
        if (entry->ip == ip) {
            int score = entry->score;
            pthread_mutex_unlock(&rep_lock);
            return score;
        }
        entry = entry->next;
    }

    pthread_mutex_unlock(&rep_lock);
    return 100; // Unknown IPs default to perfect reputation
}

int update_ip_reputation(uint32_t ip, int damage, int threat_type) {
    uint32_t bucket = hash_ip(ip);
    pthread_mutex_lock(&rep_lock);

    struct reputation_entry *entry = reputation_table[bucket];
    while (entry) {
        if (entry->ip == ip) {
            entry->score -= damage;
            if (entry->score > 100) entry->score = 100;
            if (entry->score < 0) entry->score = 0;
            entry->last_seen = time(NULL);
            entry->attack_types_mask |= (1 << threat_type);
            int score = entry->score;
            pthread_mutex_unlock(&rep_lock);
            return score;
        }
        entry = entry->next;
    }

    // Create new entry — start at 100 (perfect) and apply damage
    struct reputation_entry *new_entry = malloc(sizeof(struct reputation_entry));
    new_entry->ip = ip;
    new_entry->score = 100 - damage;
    if (new_entry->score > 100) new_entry->score = 100;
    if (new_entry->score < 0) new_entry->score = 0;
    new_entry->last_seen = time(NULL);
    new_entry->attack_types_mask = (1 << threat_type);
    new_entry->next = reputation_table[bucket];
    reputation_table[bucket] = new_entry;

    int score = new_entry->score;
    pthread_mutex_unlock(&rep_lock);
    return score;
}

void decay_reputation_scores(int recovery_amount) {
    pthread_mutex_lock(&rep_lock);

    for (int i = 0; i < HASH_SIZE; i++) {
        struct reputation_entry *entry = reputation_table[i];
        struct reputation_entry *prev = NULL;

        while (entry) {
            entry->score += recovery_amount;
            if (entry->score >= 100) {
                // Remove entry if reputation has fully recovered
                struct reputation_entry *tmp = entry;
                if (prev) {
                    prev->next = entry->next;
                } else {
                    reputation_table[i] = entry->next;
                }
                entry = entry->next;
                free(tmp);
            } else {
                prev = entry;
                entry = entry->next;
            }
        }
    }

    pthread_mutex_unlock(&rep_lock);
}

#include "fw_inspect.h"

void sync_reputation_with_blocklist(void *payload_ptr) {
    if (!payload_ptr) return;
    struct blocklist_payload *payload = (struct blocklist_payload *)payload_ptr;
    
    pthread_mutex_lock(&rep_lock);
    for (int i = 0; i < HASH_SIZE; i++) {
        struct reputation_entry *entry = reputation_table[i];
        while (entry) {
            if (entry->score <= 20) {
                int found = 0;
                for (uint32_t j = 0; j < payload->count; j++) {
                    if (payload->entries[j].ip == entry->ip) {
                        found = 1;
                        break;
                    }
                }
                if (!found) {
                    unsigned char *octets = (unsigned char *)&(entry->ip);
                    printf("[reputation] Resetting score of IP %u.%u.%u.%u to 100 (unblocked)\n",
                           octets[0], octets[1], octets[2], octets[3]);
                    entry->score = 100;
                }
            }
            entry = entry->next;
        }
    }
    pthread_mutex_unlock(&rep_lock);
}
