#ifndef THREAT_INTEL_H
#define THREAT_INTEL_H

/**
 * Initializes and starts the background threat intelligence feed aggregator thread.
 *
 * @return 0 on success, -1 on failure.
 */
int init_threat_intel(void);

/**
 * Cleans up and stops the threat intelligence feed aggregator.
 */
void cleanup_threat_intel(void);

/**
 * Triggers a manual fetch of all configured threat intel feeds.
 */
void trigger_feed_fetch(void);

#endif // THREAT_INTEL_H
