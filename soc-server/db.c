#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <arpa/inet.h>
#include "db.h"

static sqlite3 *db = NULL;

// Helper to convert UUID to hex string
static void uuid_to_str(const uint8_t *uuid, char *out, size_t out_len) {
    if (out_len < 33) return;
    for (int i = 0; i < 16; i++) {
        snprintf(out + (i * 2), 3, "%02x", uuid[i]);
    }
    out[32] = '\0';
}

// Helper to convert IP integer to string
static void ip_to_str(uint32_t ip, char *out) {
    struct in_addr addr;
    addr.s_addr = ip;
    inet_ntop(AF_INET, &addr, out, 32);
}

int db_init(const char *db_path) {
    int rc = sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[db] Cannot open database: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    // Enable WAL mode for high concurrency
    char *err_msg = NULL;
    rc = sqlite3_exec(db, "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;", NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[db] Failed to set WAL mode: %s\n", err_msg);
        sqlite3_free(err_msg);
    }

    // Create Agents table
    const char *sql_agents = 
        "CREATE TABLE IF NOT EXISTS agents ("
        "  uuid TEXT PRIMARY KEY,"
        "  last_seen INTEGER,"
        "  ip TEXT"
        ");";
    rc = sqlite3_exec(db, sql_agents, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[db] Failed to create agents table: %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    // Create Events table
    const char *sql_events = 
        "CREATE TABLE IF NOT EXISTS events ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  agent_uuid TEXT,"
        "  timestamp INTEGER,"
        "  src_ip TEXT,"
        "  dest_ip TEXT,"
        "  src_port INTEGER,"
        "  dest_port INTEGER,"
        "  threat_type INTEGER,"
        "  severity INTEGER,"
        "  payload_preview TEXT,"
        "  details TEXT"
        ");";
    rc = sqlite3_exec(db, sql_events, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[db] Failed to create events table: %s\n", err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    // Add indexes for quick querying
    sqlite3_exec(db, "CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp);", NULL, NULL, NULL);
    sqlite3_exec(db, "CREATE INDEX IF NOT EXISTS idx_events_agent ON events(agent_uuid);", NULL, NULL, NULL);

    printf("[db] SQLite database initialized successfully at %s\n", db_path);
    return 0;
}

void db_close(void) {
    if (db) {
        sqlite3_close(db);
        db = NULL;
    }
}

int db_update_agent_last_seen(const uint8_t *agent_uuid, const char *ip) {
    char uuid_str[33];
    uuid_to_str(agent_uuid, uuid_str, sizeof(uuid_str));

    const char *sql = "INSERT OR REPLACE INTO agents (uuid, last_seen, ip) VALUES (?, ?, ?);";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;

    sqlite3_bind_text(stmt, 1, uuid_str, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)time(NULL));
    sqlite3_bind_text(stmt, 3, ip, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

int db_insert_event(const uint8_t *agent_uuid, const struct fw_event *event) {
    char uuid_str[33];
    uuid_to_str(agent_uuid, uuid_str, sizeof(uuid_str));

    char src_ip_str[32], dest_ip_str[32];
    ip_to_str(event->src_ip, src_ip_str);
    ip_to_str(event->dest_ip, dest_ip_str);

    const char *sql = 
        "INSERT INTO events (agent_uuid, timestamp, src_ip, dest_ip, src_port, dest_port, "
        "threat_type, severity, payload_preview, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";
    
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[db] Prepare insert event failed: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, uuid_str, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)event->timestamp);
    sqlite3_bind_text(stmt, 3, src_ip_str, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, dest_ip_str, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 5, ntohs(event->src_port));
    sqlite3_bind_int(stmt, 6, ntohs(event->dest_port));
    sqlite3_bind_int(stmt, 7, event->threat_type);
    sqlite3_bind_int(stmt, 8, event->severity);
    sqlite3_bind_text(stmt, 9, event->payload_preview, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 10, event->details, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

// Simple dynamic string builder
struct json_buf {
    char *buf;
    size_t len;
    size_t capacity;
};

static void json_buf_init(struct json_buf *jb) {
    jb->capacity = 4096;
    jb->buf = malloc(jb->capacity);
    jb->buf[0] = '\0';
    jb->len = 0;
}

static void json_buf_append(struct json_buf *jb, const char *fmt, ...) {
    va_list args1, args2;
    va_start(args1, fmt);
    va_copy(args2, args1);

    int size = vsnprintf(NULL, 0, fmt, args1);
    va_end(args1);

    if (size < 0) {
        va_end(args2);
        return;
    }

    if (jb->len + size >= jb->capacity) {
        jb->capacity = jb->capacity * 2 + size + 1;
        jb->buf = realloc(jb->buf, jb->capacity);
    }

    vsnprintf(jb->buf + jb->len, size + 1, fmt, args2);
    va_end(args2);
    jb->len += size;
}

// Escape JSON strings
static void escape_json_str(const char *src, char *dest, size_t dest_len) {
    size_t j = 0;
    for (size_t i = 0; src[i] != '\0' && j < dest_len - 4; i++) {
        if (src[i] == '"' || src[i] == '\\' || src[i] == '/') {
            dest[j++] = '\\';
            dest[j++] = src[i];
        } else if (src[i] == '\n') {
            dest[j++] = '\\';
            dest[j++] = 'n';
        } else if (src[i] == '\r') {
            dest[j++] = '\\';
            dest[j++] = 'r';
        } else if (src[i] == '\t') {
            dest[j++] = '\\';
            dest[j++] = 't';
        } else if ((unsigned char)src[i] < 32) {
            // skip control chars
        } else {
            dest[j++] = src[i];
        }
    }
    dest[j] = '\0';
}

char *db_get_events_json(int limit, int offset, const char *agent_filter) {
    const char *sql;
    sqlite3_stmt *stmt;
    int rc;

    if (agent_filter && strlen(agent_filter) == 32) {
        sql = "SELECT id, agent_uuid, timestamp, src_ip, dest_ip, src_port, dest_port, "
              "threat_type, severity, payload_preview, details FROM events "
              "WHERE agent_uuid = ? ORDER BY id DESC LIMIT ? OFFSET ?;";
        rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
        if (rc != SQLITE_OK) return NULL;
        sqlite3_bind_text(stmt, 1, agent_filter, -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 2, limit);
        sqlite3_bind_int(stmt, 3, offset);
    } else {
        sql = "SELECT id, agent_uuid, timestamp, src_ip, dest_ip, src_port, dest_port, "
              "threat_type, severity, payload_preview, details FROM events "
              "ORDER BY id DESC LIMIT ? OFFSET ?;";
        rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
        if (rc != SQLITE_OK) return NULL;
        sqlite3_bind_int(stmt, 1, limit);
        sqlite3_bind_int(stmt, 2, offset);
    }

    struct json_buf jb;
    json_buf_init(&jb);
    json_buf_append(&jb, "[");

    int first = 1;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (!first) json_buf_append(&jb, ",");
        first = 0;

        int id = sqlite3_column_int(stmt, 0);
        const unsigned char *agent_uuid_val = sqlite3_column_text(stmt, 1);
        sqlite3_int64 timestamp = sqlite3_column_int64(stmt, 2);
        const unsigned char *src_ip_val = sqlite3_column_text(stmt, 3);
        const unsigned char *dest_ip_val = sqlite3_column_text(stmt, 4);
        int src_port = sqlite3_column_int(stmt, 5);
        int dest_port = sqlite3_column_int(stmt, 6);
        int threat_type = sqlite3_column_int(stmt, 7);
        int severity = sqlite3_column_int(stmt, 8);
        const unsigned char *preview = sqlite3_column_text(stmt, 9);
        const unsigned char *details = sqlite3_column_text(stmt, 10);

        char esc_preview[512] = {0};
        char esc_details[1024] = {0};
        if (preview) escape_json_str((const char *)preview, esc_preview, sizeof(esc_preview));
        if (details) escape_json_str((const char *)details, esc_details, sizeof(esc_details));

        json_buf_append(&jb, 
            "{\"id\":%d,\"agent_uuid\":\"%s\",\"timestamp\":%lld,\"src_ip\":\"%s\",\"dest_ip\":\"%s\","
            "\"src_port\":%d,\"dest_port\":%d,\"threat_type\":%d,\"severity\":%d,"
            "\"payload_preview\":\"%s\",\"details\":\"%s\"}",
            id, agent_uuid_val, (long long)timestamp, src_ip_val, dest_ip_val,
            src_port, dest_port, threat_type, severity, esc_preview, esc_details);
    }
    json_buf_append(&jb, "]");
    sqlite3_finalize(stmt);

    return jb.buf;
}

char *db_get_agents_json(void) {
    const char *sql = "SELECT uuid, last_seen, ip FROM agents ORDER BY last_seen DESC;";
    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return NULL;

    struct json_buf jb;
    json_buf_init(&jb);
    json_buf_append(&jb, "[");

    int first = 1;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (!first) json_buf_append(&jb, ",");
        first = 0;

        const unsigned char *uuid = sqlite3_column_text(stmt, 0);
        sqlite3_int64 last_seen = sqlite3_column_int64(stmt, 1);
        const unsigned char *ip = sqlite3_column_text(stmt, 2);

        json_buf_append(&jb, "{\"uuid\":\"%s\",\"last_seen\":%lld,\"ip\":\"%s\"}",
                        uuid, (long long)last_seen, ip ? (const char *)ip : "");
    }
    json_buf_append(&jb, "]");
    sqlite3_finalize(stmt);

    return jb.buf;
}

char *db_get_stats_json(void) {
    struct json_buf jb;
    json_buf_init(&jb);
    json_buf_append(&jb, "{");

    // 1. Total events count
    sqlite3_stmt *stmt;
    int total_events = 0;
    if (sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM events;", -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            total_events = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }
    json_buf_append(&jb, "\"total_events\":%d,", total_events);

    // 2. Counts by threat type
    json_buf_append(&jb, "\"by_threat\":{");
    const char *threat_sql = "SELECT threat_type, COUNT(*) FROM events GROUP BY threat_type;";
    if (sqlite3_prepare_v2(db, threat_sql, -1, &stmt, NULL) == SQLITE_OK) {
        int first = 1;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            if (!first) json_buf_append(&jb, ",");
            first = 0;
            json_buf_append(&jb, "\"%d\":%d", sqlite3_column_int(stmt, 0), sqlite3_column_int(stmt, 1));
        }
        sqlite3_finalize(stmt);
    }
    json_buf_append(&jb, "},");

    // 3. Counts by severity
    json_buf_append(&jb, "\"by_severity\":{");
    const char *sev_sql = "SELECT severity, COUNT(*) FROM events GROUP BY severity;";
    if (sqlite3_prepare_v2(db, sev_sql, -1, &stmt, NULL) == SQLITE_OK) {
        int first = 1;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            if (!first) json_buf_append(&jb, ",");
            first = 0;
            json_buf_append(&jb, "\"%d\":%d", sqlite3_column_int(stmt, 0), sqlite3_column_int(stmt, 1));
        }
        sqlite3_finalize(stmt);
    }
    json_buf_append(&jb, "},");

    // 4. Last 24 hours timeline (grouped by hour)
    json_buf_append(&jb, "\"timeline\":[");
    time_t now = time(NULL);
    time_t day_ago = now - (24 * 3600);
    const char *time_sql = 
        "SELECT (timestamp / 3600) * 3600 AS hr, COUNT(*) FROM events "
        "WHERE timestamp >= ? GROUP BY hr ORDER BY hr ASC;";
    
    if (sqlite3_prepare_v2(db, time_sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, (sqlite3_int64)day_ago);
        int first = 1;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            if (!first) json_buf_append(&jb, ",");
            first = 0;
            json_buf_append(&jb, "{\"time\":%lld,\"count\":%d}", 
                            (long long)sqlite3_column_int64(stmt, 0), sqlite3_column_int(stmt, 1));
        }
        sqlite3_finalize(stmt);
    }
    json_buf_append(&jb, "]");

    json_buf_append(&jb, "}");
    return jb.buf;
}
