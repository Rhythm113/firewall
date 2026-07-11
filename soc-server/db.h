#ifndef DB_H
#define DB_H

#include <stdint.h>
#include "fw_inspect.h"

/**
 * Initializes the PostgreSQL database connection.
 * Reads environment variables (PGHOST, PGPORT, PGDATABASE, PGUSER, PGPASSWORD) for configuration.
 *
 * @param conninfo Optional connection string. If NULL, environment variables are used.
 * @return 0 on success, -1 on failure.
 */
int db_init(const char *conninfo);

/**
 * Closes the PostgreSQL database connection.
 */
void db_close(void);

/**
 * Registers or updates an agent's status.
 */
int db_update_agent_last_seen(const uint8_t *agent_uuid, const char *ip);

/**
 * Inserts a security event into the database.
 */
int db_insert_event(const uint8_t *agent_uuid, const struct fw_event *event);

/**
 * Inserts a log entry from an agent connection.
 */
int db_insert_agent_log(const uint8_t *agent_uuid, const char *log_type, const char *message, const char *src_ip);

/**
 * Queries agent logs and returns them formatted as a JSON string.
 */
char *db_get_agent_logs_json(int limit, int offset, const char *search);

/**
 * Queries events and returns them formatted as a JSON string.
 */
char *db_get_events_json(int limit, int offset, const char *agent_filter);

/**
 * Queries all registered agents and returns them formatted as a JSON string.
 */
char *db_get_agents_json(void);

/**
 * Queries aggregated stats and returns them formatted as a JSON string.
 */
char *db_get_stats_json(void);

// --- Multi-Agent, YARA, Threat Intel, Configuration, Blocklist ---

int db_register_agent(const uint8_t *agent_uuid, const char *hostname, const char *ip);
int db_remove_agent(const uint8_t *agent_uuid);

int db_add_to_blocklist(const char *ip_cidr, const char *list_type, const char *reason);
int db_remove_from_blocklist(const char *ip_cidr, const char *list_type);
char *db_get_blocklist_json(const char *list_type);

int db_update_ip_reputation(const char *ip, int score, int local_score, int external_score, const char *attack_types);
char *db_get_reputation_json(const char *ip);

int db_add_yara_rule(const char *name, const char *content);
int db_delete_yara_rule(const char *name);
char *db_get_yara_rules_json(void);

int db_set_config(const char *key, const char *value, const char *category, const char *description);
char *db_get_config_json(void);

int db_save_threat_intel(const char *feed_name, const char *ind_type, const char *ind_val, const char *threat_type, int confidence, const char *source_url);
char *db_get_threat_intel_json(void);

#endif // DB_H
