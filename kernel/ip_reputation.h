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
 * High scores indicate higher malice (80+ represents block).
 *
 * @param ip IP address (in network byte order).
 * @return The score (0 to 100).
 */
int get_ip_reputation(uint32_t ip);

/**
 * Updates/Increments the reputation score of an IP.
 * Also tracks attack types seen from this IP.
 *
 * @param ip IP address (in network byte order).
 * @param increment Value to add to the score.
 * @param threat_type The threat type integer triggered.
 * @return The updated score.
 */
int update_ip_reputation(uint32_t ip, int increment, int threat_type);

/**
 * Decays the reputation scores of all active IPs.
 * Should be called periodically (e.g. once per minute/hour).
 *
 * @param decay_amount Amount to subtract from all active scores.
 */
void decay_reputation_scores(int decay_amount);

#endif // IP_REPUTATION_H
