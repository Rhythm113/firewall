#ifndef DB_H
#define DB_H

#include <stdint.h>
#include "fw_inspect.h"

/**
 * Initializes the SQLite database.
 * Sets up the schema (agents, events tables) and enables WAL mode.
 *
 * @param db_path Path to the SQLite database file.
 * @return 0 on success, -1 on failure.
 */
int db_init(const char *db_path);

/**
 * Closes the SQLite database connection.
 */
void db_close(void);

/**
 * Registers/Updates an agent's last seen status and source IP.
 *
 * @param agent_uuid 16-byte agent UUID.
 * @param ip IP address string of the agent.
 * @return 0 on success, -1 on failure.
 */
int db_update_agent_last_seen(const uint8_t *agent_uuid, const char *ip);

/**
 * Inserts a firewall event into the database.
 *
 * @param agent_uuid 16-byte agent UUID that reported the event.
 * @param event The event structure.
 * @return 0 on success, -1 on failure.
 */
int db_insert_event(const uint8_t *agent_uuid, const struct fw_event *event);

/**
 * Queries events and returns them formatted as a JSON string.
 * Caller must free the returned pointer using free().
 *
 * @param limit Max events to return.
 * @param offset Pagination offset.
 * @param agent_filter Optional agent UUID string to filter by (can be NULL).
 * @return JSON string or NULL on error.
 */
char *db_get_events_json(int limit, int offset, const char *agent_filter);

/**
 * Queries all registered agents and returns them formatted as a JSON string.
 * Caller must free the returned pointer using free().
 *
 * @return JSON string or NULL on error.
 */
char *db_get_agents_json(void);

/**
 * Queries aggregated stats (e.g. threat type distribution, timeline) and
 * returns them formatted as a JSON string.
 * Caller must free the returned pointer using free().
 *
 * @return JSON string or NULL on error.
 */
char *db_get_stats_json(void);

#endif // DB_H
