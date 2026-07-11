#ifndef IP_REPUTATION_H
#define IP_REPUTATION_H

#include <stdint.h>

/**
 * Initializes the IP reputation memory structures.
 *
 * @return 0 on success, -1 on failure.
 */
int init_ip_reputation(void);

/**
 * Cleanup IP reputation structures.
 */
void cleanup_ip_reputation(void);

/**
 * Gets the current reputation score (0-100) of an IP address.
 * A HIGH score indicates GOOD reputation (trusted IP).
 * A LOW score (≤ 20) indicates a MALICIOUS IP that should be blocked.
 * New IPs start at score 100 (perfect reputation).
 *
 * @param ip IP address (in network byte order).
 * @return The score (0 to 100, higher = more trusted).
 */
int get_ip_reputation(uint32_t ip);

/**
 * Updates/Deducts the reputation score of an IP after a threat event.
 * Also tracks attack types seen from this IP.
 *
 * @param ip IP address (in network byte order).
 * @param damage Amount to subtract from the reputation score
 *               (higher damage = more severe threat).
 * @param threat_type The threat type integer triggered.
 * @return The updated score.
 */
int update_ip_reputation(uint32_t ip, int damage, int threat_type);

/**
 * Decays (recovers) the reputation scores of all active IPs over time.
 * Should be called periodically (e.g. once per minute/hour).
 * The reputation score increases toward 100 as time passes without threats.
 *
 * @param recovery_amount Amount to add to all active scores
 *                        (reputation recovers over time).
 */
void decay_reputation_scores(int recovery_amount);

void sync_reputation_with_blocklist(void *payload);

#endif // IP_REPUTATION_H
