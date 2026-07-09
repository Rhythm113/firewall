#ifndef USERSPACE_COMPAT_H
#define USERSPACE_COMPAT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <errno.h>

// Mock kernel printk
#define printk(fmt, ...) printf(fmt, ##__VA_ARGS__)
#define KERN_INFO "INFO: "
#define KERN_ERR "ERR: "
#define KERN_WARNING "WARN: "

// Mock kernel time / jiffies
#define HZ 100
static inline unsigned long get_millis(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
}
#define jiffies (get_millis() / 10) // 10ms per jiffy, matches HZ=100
#define time_after(a, b) ((long)(b) - (long)(a) < 0)

static inline uint64_t ktime_get_real_seconds(void) {
    return (uint64_t)time(NULL);
}

// Mock kernel spinlock
typedef struct { int lock; } spinlock_t;
#define DEFINE_SPINLOCK(x) spinlock_t x = {0}
#define spin_lock(x) (void)(x)
#define spin_unlock(x) (void)(x)

// Mock RCU
#define rcu_read_lock()
#define rcu_read_unlock()
struct rcu_head { int dummy; };
#define kfree_rcu(ptr, member) free(ptr)

// Mock Hash Table and container_of
#define offsetof(type, member) ((size_t) &((type *)0)->member)
#define container_of(ptr, type, member) \
    (ptr ? ((type *)((char *)(ptr) - offsetof(type, member))) : NULL)

struct hlist_node {
    struct hlist_node *next, **pprev;
};

#define DEFINE_HASHTABLE(name, bits) \
    struct hlist_node *name[1 << (bits)] = { NULL }

#define hash_for_each_rcu(name, bucket, obj, member) \
    for (bucket = 0; bucket < (1 << HASH_BITS); bucket++) \
        for (obj = container_of(name[bucket], typeof(*obj), member); \
             obj; \
             obj = container_of(obj->member.next, typeof(*obj), member))

#define hash_for_each_safe(name, bucket, tmp, obj, member) \
    for (bucket = 0; bucket < (1 << HASH_BITS); bucket++) \
        for (obj = container_of(name[bucket], typeof(*obj), member), \
             tmp = obj ? obj->member.next : NULL; \
             obj; \
             obj = container_of(tmp, typeof(*obj), member), \
             tmp = obj ? obj->member.next : NULL)

#define hash_add_rcu(name, obj_node, key) \
    do { \
        int _b = (key) % (1 << HASH_BITS); \
        (obj_node)->next = name[_b]; \
        name[_b] = (obj_node); \
    } while (0)

#define hash_del_rcu(obj_node)

// Mock kernel memory allocation
#define GFP_ATOMIC 0
#define GFP_KERNEL 0
#define kmalloc(sz, flags) malloc(sz)
#define kzalloc(sz, flags) calloc(1, sz)
#define kfree(ptr) free(ptr)

// Mock headers / network types
struct sk_buff {
    unsigned char *data;
    int len;
};

#define ip_hdr(skb) ((struct iphdr *)((skb)->data))
#define tcp_hdr(skb) ((struct tcphdr *)((skb)->data + (((struct iphdr *)((skb)->data))->ihl * 4)))
#define pskb_may_pull(skb, len) (1)

// Mock EXPORT_SYMBOL
#define EXPORT_SYMBOL(x)

#endif // USERSPACE_COMPAT_H
