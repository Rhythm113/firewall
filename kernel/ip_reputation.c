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
    return 0;
}

int update_ip_reputation(uint32_t ip, int increment, int threat_type) {
    uint32_t bucket = hash_ip(ip);
    pthread_mutex_lock(&rep_lock);
    
    struct reputation_entry *entry = reputation_table[bucket];
    while (entry) {
        if (entry->ip == ip) {
            entry->score += increment;
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
    
    // Create new entry
    struct reputation_entry *new_entry = malloc(sizeof(struct reputation_entry));
    new_entry->ip = ip;
    new_entry->score = increment;
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

void decay_reputation_scores(int decay_amount) {
    pthread_mutex_lock(&rep_lock);
    
    for (int i = 0; i < HASH_SIZE; i++) {
        struct reputation_entry *entry = reputation_table[i];
        struct reputation_entry *prev = NULL;
        
        while (entry) {
            entry->score -= decay_amount;
            if (entry->score <= 0) {
                // Remove entry if score decays to 0
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
