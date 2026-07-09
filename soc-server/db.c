#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <postgresql/libpq-fe.h>
#include <arpa/inet.h>
#include "db.h"

static PGconn *conn = NULL;

// Helper to convert UUID to hex string
static void uuid_to_str(const uint8_t *uuid, char *out, size_t out_len) {
    if (out_len < 37) return;
    // Format as standard UUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    snprintf(out, out_len, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             uuid[0], uuid[1], uuid[2], uuid[3],
             uuid[4], uuid[5],
             uuid[6], uuid[7],
             uuid[8], uuid[9],
             uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);
}

// Helper to convert IP integer to string
static void ip_to_str(uint32_t ip, char *out) {
    struct in_addr addr;
    addr.s_addr = ip;
    inet_ntop(AF_INET, &addr, out, 32);
}

// Dynamic string builder structure
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

int db_init(const char *conninfo) {
    char conn_str[1024];

    if (conninfo) {
        strncpy(conn_str, conninfo, sizeof(conn_str) - 1);
        conn_str[sizeof(conn_str) - 1] = '\0';
    } else {
        const char *host = getenv("PGHOST") ? getenv("PGHOST") : "localhost";
        const char *port = getenv("PGPORT") ? getenv("PGPORT") : "5432";
        const char *dbname = getenv("PGDATABASE") ? getenv("PGDATABASE") : "nullsploit";
        const char *user = getenv("PGUSER") ? getenv("PGUSER") : "nullsploit";
        const char *password = getenv("PGPASSWORD") ? getenv("PGPASSWORD") : "nullsploit_secure";

        snprintf(conn_str, sizeof(conn_str), "host=%s port=%s dbname=%s user=%s password=%s connect_timeout=10",
                 host, port, dbname, user, password);
    }

    printf("[db] Connecting to PostgreSQL database...\n");
    conn = PQconnectdb(conn_str);

    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "[db] Connection to database failed: %s\n", PQerrorMessage(conn));
        PQfinish(conn);
        conn = NULL;
        return -1;
    }

    PGresult *res;

    // Create agents table
    res = PQexec(conn, 
        "CREATE TABLE IF NOT EXISTS agents ("
        "  uuid UUID PRIMARY KEY,"
        "  hostname TEXT,"
        "  ip INET NOT NULL,"
        "  last_seen TIMESTAMPTZ,"
        "  status TEXT DEFAULT 'unknown',"
        "  config JSONB DEFAULT '{}',"
        "  registered_at TIMESTAMPTZ DEFAULT NOW()"
        ");");
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[db] Failed to create agents table: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }
    PQclear(res);

    // Create events table
    res = PQexec(conn,
        "CREATE TABLE IF NOT EXISTS events ("
        "  id BIGSERIAL PRIMARY KEY,"
        "  agent_uuid UUID REFERENCES agents(uuid) ON DELETE SET NULL,"
        "  timestamp TIMESTAMPTZ NOT NULL,"
        "  src_ip INET,"
        "  dest_ip INET,"
        "  src_port INTEGER,"
        "  dest_port INTEGER,"
        "  threat_type INTEGER NOT NULL,"
        "  severity INTEGER NOT NULL,"
        "  payload_preview TEXT,"
        "  details TEXT,"
        "  detection_module TEXT,"
        "  confidence INTEGER DEFAULT 100,"
        "  created_at TIMESTAMPTZ DEFAULT NOW()"
        ");");
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[db] Failed to create events table: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }
    PQclear(res);

    // Create ip_reputation table
    res = PQexec(conn,
        "CREATE TABLE IF NOT EXISTS ip_reputation ("
        "  ip INET PRIMARY KEY,"
        "  score INTEGER DEFAULT 0,"
        "  local_score INTEGER DEFAULT 0,"
        "  external_score INTEGER DEFAULT 0,"
        "  total_blocks INTEGER DEFAULT 0,"
        "  attack_types TEXT[] DEFAULT '{}',"
        "  first_seen TIMESTAMPTZ DEFAULT NOW(),"
        "  last_seen TIMESTAMPTZ DEFAULT NOW(),"
        "  manual_override INTEGER DEFAULT -1,"
        "  updated_at TIMESTAMPTZ DEFAULT NOW()"
        ");");
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[db] Failed to create ip_reputation table: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }
    PQclear(res);

    // Create threat_intel table
    res = PQexec(conn,
        "CREATE TABLE IF NOT EXISTS threat_intel ("
        "  id BIGSERIAL PRIMARY KEY,"
        "  feed_name TEXT NOT NULL,"
        "  indicator_type TEXT NOT NULL,"
        "  indicator_value TEXT NOT NULL,"
        "  threat_type TEXT,"
        "  confidence INTEGER,"
        "  source_url TEXT,"
        "  raw_data JSONB DEFAULT '{}',"
        "  fetched_at TIMESTAMPTZ DEFAULT NOW(),"
        "  expires_at TIMESTAMPTZ"
        ");");
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[db] Failed to create threat_intel table: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }
    PQclear(res);

    // Create yara_rules table
    res = PQexec(conn,
        "CREATE TABLE IF NOT EXISTS yara_rules ("
        "  id SERIAL PRIMARY KEY,"
        "  name TEXT UNIQUE NOT NULL,"
        "  content TEXT NOT NULL,"
        "  enabled BOOLEAN DEFAULT TRUE,"
        "  match_count INTEGER DEFAULT 0,"
        "  last_match TIMESTAMPTZ,"
        "  created_at TIMESTAMPTZ DEFAULT NOW(),"
        "  updated_at TIMESTAMPTZ DEFAULT NOW()"
        ");");
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[db] Failed to create yara_rules table: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }
    PQclear(res);

    // Create config table
    res = PQexec(conn,
        "CREATE TABLE IF NOT EXISTS config ("
        "  key TEXT PRIMARY KEY,"
        "  value JSONB NOT NULL,"
        "  category TEXT NOT NULL,"
        "  description TEXT,"
        "  updated_at TIMESTAMPTZ DEFAULT NOW()"
        ");");
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[db] Failed to create config table: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }
    PQclear(res);

    // Create blocklist table
    res = PQexec(conn,
        "CREATE TABLE IF NOT EXISTS blocklist ("
        "  id SERIAL PRIMARY KEY,"
        "  ip_cidr CIDR NOT NULL,"
        "  list_type TEXT NOT NULL DEFAULT 'block',"
        "  source TEXT DEFAULT 'manual',"
        "  reason TEXT,"
        "  added_by TEXT,"
        "  created_at TIMESTAMPTZ DEFAULT NOW()"
        ");");
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[db] Failed to create blocklist table: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }
    PQclear(res);

    // Create indexes
    PQexec(conn, "CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp DESC);");
    PQexec(conn, "CREATE INDEX IF NOT EXISTS idx_events_agent ON events(agent_uuid);");
    PQexec(conn, "CREATE INDEX IF NOT EXISTS idx_blocklist_type ON blocklist(list_type);");

    printf("[db] PostgreSQL database tables initialized successfully\n");
    return 0;
}

void db_close(void) {
    if (conn) {
        PQfinish(conn);
        conn = NULL;
    }
}

int db_register_agent(const uint8_t *agent_uuid, const char *hostname, const char *ip) {
    char uuid_str[37];
    uuid_to_str(agent_uuid, uuid_str, sizeof(uuid_str));

    const char *sql = 
        "INSERT INTO agents (uuid, hostname, ip, last_seen, status) "
        "VALUES ($1, $2, $3, NOW(), 'active') "
        "ON CONFLICT (uuid) DO UPDATE "
        "SET hostname = EXCLUDED.hostname, ip = EXCLUDED.ip, last_seen = NOW(), status = 'active';";

    const char *paramValues[3] = { uuid_str, hostname, ip };
    PGresult *res = PQexecParams(conn, sql, 3, NULL, paramValues, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[db] Register agent failed: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }

    PQclear(res);
    return 0;
}

int db_update_agent_last_seen(const uint8_t *agent_uuid, const char *ip) {
    return db_register_agent(agent_uuid, "Nullsploit-Agent", ip);
}

int db_remove_agent(const uint8_t *agent_uuid) {
    char uuid_str[37];
    uuid_to_str(agent_uuid, uuid_str, sizeof(uuid_str));

    const char *sql = "DELETE FROM agents WHERE uuid = $1;";
    const char *paramValues[1] = { uuid_str };
    PGresult *res = PQexecParams(conn, sql, 1, NULL, paramValues, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[db] Remove agent failed: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }

    PQclear(res);
    return 0;
}

int db_insert_event(const uint8_t *agent_uuid, const struct fw_event *event) {
    char uuid_str[37];
    uuid_to_str(agent_uuid, uuid_str, sizeof(uuid_str));

    char src_ip_str[32], dest_ip_str[32];
    ip_to_str(event->src_ip, src_ip_str);
    ip_to_str(event->dest_ip, dest_ip_str);

    char src_port_str[16], dest_port_str[16];
    snprintf(src_port_str, sizeof(src_port_str), "%d", ntohs(event->src_port));
    snprintf(dest_port_str, sizeof(dest_port_str), "%d", ntohs(event->dest_port));

    char threat_str[16], severity_str[16];
    snprintf(threat_str, sizeof(threat_str), "%d", event->threat_type);
    snprintf(severity_str, sizeof(severity_str), "%d", event->severity);

    char timestamp_str[64];
    time_t ts = (time_t)event->timestamp;
    struct tm *tm_info = gmtime(&ts);
    strftime(timestamp_str, sizeof(timestamp_str), "%Y-%m-%d %H:%M:%S+00", tm_info);

    const char *sql = 
        "INSERT INTO events (agent_uuid, timestamp, src_ip, dest_ip, src_port, dest_port, "
        "threat_type, severity, payload_preview, details) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);";

    const char *paramValues[10] = {
        uuid_str, timestamp_str, src_ip_str, dest_ip_str,
        src_port_str, dest_port_str, threat_str, severity_str,
        event->payload_preview, event->details
    };

    PGresult *res = PQexecParams(conn, sql, 10, NULL, paramValues, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[db] Insert event failed: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }

    PQclear(res);
    return 0;
}

char *db_get_events_json(int limit, int offset, const char *agent_filter) {
    char limit_str[16], offset_str[16];
    snprintf(limit_str, sizeof(limit_str), "%d", limit);
    snprintf(offset_str, sizeof(offset_str), "%d", offset);

    PGresult *res;
    if (agent_filter && strlen(agent_filter) == 36) {
        const char *sql = 
            "SELECT id, agent_uuid, EXTRACT(EPOCH FROM timestamp)::bigint, src_ip, dest_ip, src_port, dest_port, "
            "threat_type, severity, payload_preview, details FROM events "
            "WHERE agent_uuid = $1 ORDER BY id DESC LIMIT $2 OFFSET $3;";
        const char *paramValues[3] = { agent_filter, limit_str, offset_str };
        res = PQexecParams(conn, sql, 3, NULL, paramValues, NULL, NULL, 0);
    } else {
        const char *sql = 
            "SELECT id, agent_uuid, EXTRACT(EPOCH FROM timestamp)::bigint, src_ip, dest_ip, src_port, dest_port, "
            "threat_type, severity, payload_preview, details FROM events "
            "ORDER BY id DESC LIMIT $1 OFFSET $2;";
        const char *paramValues[2] = { limit_str, offset_str };
        res = PQexecParams(conn, sql, 2, NULL, paramValues, NULL, NULL, 0);
    }

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "[db] Get events failed: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return strdup("[]");
    }

    int rows = PQntuples(res);
    struct json_buf jb;
    json_buf_init(&jb);
    json_buf_append(&jb, "[");

    for (int i = 0; i < rows; i++) {
        if (i > 0) json_buf_append(&jb, ",");

        const char *id = PQgetvalue(res, i, 0);
        const char *agent_uuid = PQgetvalue(res, i, 1);
        const char *timestamp = PQgetvalue(res, i, 2);
        const char *src_ip = PQgetvalue(res, i, 3);
        const char *dest_ip = PQgetvalue(res, i, 4);
        const char *src_port = PQgetvalue(res, i, 5);
        const char *dest_port = PQgetvalue(res, i, 6);
        const char *threat_type = PQgetvalue(res, i, 7);
        const char *severity = PQgetvalue(res, i, 8);
        const char *preview = PQgetvalue(res, i, 9);
        const char *details = PQgetvalue(res, i, 10);

        char esc_preview[512] = {0};
        char esc_details[1024] = {0};
        if (preview) escape_json_str(preview, esc_preview, sizeof(esc_preview));
        if (details) escape_json_str(details, esc_details, sizeof(esc_details));

        json_buf_append(&jb, 
            "{\"id\":%s,\"agent_uuid\":\"%s\",\"timestamp\":%s,\"src_ip\":\"%s\",\"dest_ip\":\"%s\","
            "\"src_port\":%s,\"dest_port\":%s,\"threat_type\":%s,\"severity\":%s,"
            "\"payload_preview\":\"%s\",\"details\":\"%s\"}",
            id, agent_uuid, timestamp, src_ip, dest_ip,
            src_port, dest_port, threat_type, severity, esc_preview, esc_details);
    }
    json_buf_append(&jb, "]");
    PQclear(res);

    return jb.buf;
}

char *db_get_agents_json(void) {
    const char *sql = 
        "SELECT uuid, hostname, ip, EXTRACT(EPOCH FROM last_seen)::bigint, status, config::text "
        "FROM agents ORDER BY last_seen DESC;";
    PGresult *res = PQexec(conn, sql);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "[db] Get agents failed: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return strdup("[]");
    }

    int rows = PQntuples(res);
    struct json_buf jb;
    json_buf_init(&jb);
    json_buf_append(&jb, "[");

    for (int i = 0; i < rows; i++) {
        if (i > 0) json_buf_append(&jb, ",");

        const char *uuid = PQgetvalue(res, i, 0);
        const char *hostname = PQgetvalue(res, i, 1);
        const char *ip = PQgetvalue(res, i, 2);
        const char *last_seen = PQgetvalue(res, i, 3);
        const char *status = PQgetvalue(res, i, 4);
        const char *config = PQgetvalue(res, i, 5);

        json_buf_append(&jb, 
            "{\"uuid\":\"%s\",\"hostname\":\"%s\",\"ip\":\"%s\",\"last_seen\":%s,\"status\":\"%s\",\"config\":%s}",
            uuid, hostname, ip, last_seen, status, config && strlen(config) > 0 ? config : "{}");
    }
    json_buf_append(&jb, "]");
    PQclear(res);

    return jb.buf;
}

char *db_get_stats_json(void) {
    struct json_buf jb;
    json_buf_init(&jb);
    json_buf_append(&jb, "{");

    PGresult *res;

    // 1. Total events count
    int total_events = 0;
    res = PQexec(conn, "SELECT COUNT(*) FROM events;");
    if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0) {
        total_events = atoi(PQgetvalue(res, 0, 0));
    }
    PQclear(res);
    json_buf_append(&jb, "\"total_events\":%d,", total_events);

    // 2. Counts by threat type
    json_buf_append(&jb, "\"by_threat\":{");
    res = PQexec(conn, "SELECT threat_type, COUNT(*) FROM events GROUP BY threat_type;");
    if (PQresultStatus(res) == PGRES_TUPLES_OK) {
        int rows = PQntuples(res);
        for (int i = 0; i < rows; i++) {
            if (i > 0) json_buf_append(&jb, ",");
            json_buf_append(&jb, "\"%s\":%s", PQgetvalue(res, i, 0), PQgetvalue(res, i, 1));
        }
    }
    PQclear(res);
    json_buf_append(&jb, "},");

    // 3. Counts by severity
    json_buf_append(&jb, "\"by_severity\":{");
    res = PQexec(conn, "SELECT severity, COUNT(*) FROM events GROUP BY severity;");
    if (PQresultStatus(res) == PGRES_TUPLES_OK) {
        int rows = PQntuples(res);
        for (int i = 0; i < rows; i++) {
            if (i > 0) json_buf_append(&jb, ",");
            json_buf_append(&jb, "\"%s\":%s", PQgetvalue(res, i, 0), PQgetvalue(res, i, 1));
        }
    }
    PQclear(res);
    json_buf_append(&jb, "},");

    // 4. Last 24 hours timeline (grouped by hour)
    json_buf_append(&jb, "\"timeline\":[");
    res = PQexec(conn, 
        "SELECT EXTRACT(EPOCH FROM DATE_TRUNC('hour', timestamp))::bigint AS hr, COUNT(*) "
        "FROM events "
        "WHERE timestamp >= NOW() - INTERVAL '24 hours' "
        "GROUP BY hr ORDER BY hr ASC;");
    if (PQresultStatus(res) == PGRES_TUPLES_OK) {
        int rows = PQntuples(res);
        for (int i = 0; i < rows; i++) {
            if (i > 0) json_buf_append(&jb, ",");
            json_buf_append(&jb, "{\"time\":%s,\"count\":%s}", PQgetvalue(res, i, 0), PQgetvalue(res, i, 1));
        }
    }
    PQclear(res);
    json_buf_append(&jb, "]");

    json_buf_append(&jb, "}");
    return jb.buf;
}

// --- Blocklist, YARA, reputation, configs, threat intel ---

int db_add_to_blocklist(const char *ip_cidr, const char *list_type, const char *reason) {
    const char *sql = 
        "INSERT INTO blocklist (ip_cidr, list_type, reason) VALUES ($1, $2, $3) "
        "ON CONFLICT DO NOTHING;";
    const char *paramValues[3] = { ip_cidr, list_type, reason };
    PGresult *res = PQexecParams(conn, sql, 3, NULL, paramValues, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[db] Add blocklist failed: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }
    PQclear(res);
    return 0;
}

int db_remove_from_blocklist(const char *ip_cidr, const char *list_type) {
    const char *sql = "DELETE FROM blocklist WHERE ip_cidr = $1 AND list_type = $2;";
    const char *paramValues[2] = { ip_cidr, list_type };
    PGresult *res = PQexecParams(conn, sql, 2, NULL, paramValues, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[db] Remove blocklist failed: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }
    PQclear(res);
    return 0;
}

char *db_get_blocklist_json(const char *list_type) {
    const char *sql = "SELECT id, ip_cidr::text, reason, created_at FROM blocklist WHERE list_type = $1 ORDER BY id DESC;";
    const char *paramValues[1] = { list_type };
    PGresult *res = PQexecParams(conn, sql, 1, NULL, paramValues, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        return strdup("[]");
    }

    int rows = PQntuples(res);
    struct json_buf jb;
    json_buf_init(&jb);
    json_buf_append(&jb, "[");

    for (int i = 0; i < rows; i++) {
        if (i > 0) json_buf_append(&jb, ",");
        json_buf_append(&jb, "{\"id\":%s,\"ip_cidr\":\"%s\",\"reason\":\"%s\",\"created_at\":\"%s\"}",
                        PQgetvalue(res, i, 0), PQgetvalue(res, i, 1), PQgetvalue(res, i, 2), PQgetvalue(res, i, 3));
    }
    json_buf_append(&jb, "]");
    PQclear(res);
    return jb.buf;
}

int db_update_ip_reputation(const char *ip, int score, int local_score, int external_score, const char *attack_types) {
    const char *sql = 
        "INSERT INTO ip_reputation (ip, score, local_score, external_score, attack_types, last_seen) "
        "VALUES ($1, $2, $3, $4, string_to_array($5, ','), NOW()) "
        "ON CONFLICT (ip) DO UPDATE SET "
        "score = EXCLUDED.score, local_score = EXCLUDED.local_score, external_score = EXCLUDED.external_score, "
        "attack_types = array_cat(ip_reputation.attack_types, EXCLUDED.attack_types), last_seen = NOW(), updated_at = NOW();";

    char score_str[16], local_str[16], ext_str[16];
    snprintf(score_str, sizeof(score_str), "%d", score);
    snprintf(local_str, sizeof(local_str), "%d", local_score);
    snprintf(ext_str, sizeof(ext_str), "%d", external_score);

    const char *paramValues[5] = { ip, score_str, local_str, ext_str, attack_types };
    PGresult *res = PQexecParams(conn, sql, 5, NULL, paramValues, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[db] Update reputation failed: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }
    PQclear(res);
    return 0;
}

char *db_get_reputation_json(const char *ip) {
    PGresult *res;
    if (ip) {
        const char *sql = "SELECT ip::text, score, local_score, external_score, array_to_string(attack_types, ','), updated_at FROM ip_reputation WHERE ip = $1;";
        const char *paramValues[1] = { ip };
        res = PQexecParams(conn, sql, 1, NULL, paramValues, NULL, NULL, 0);
    } else {
        const char *sql = "SELECT ip::text, score, local_score, external_score, array_to_string(attack_types, ','), updated_at FROM ip_reputation ORDER BY score DESC LIMIT 100;";
        res = PQexec(conn, sql);
    }

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        return strdup("[]");
    }

    int rows = PQntuples(res);
    struct json_buf jb;
    json_buf_init(&jb);
    json_buf_append(&jb, "[");

    for (int i = 0; i < rows; i++) {
        if (i > 0) json_buf_append(&jb, ",");
        json_buf_append(&jb, "{\"ip\":\"%s\",\"score\":%s,\"local_score\":%s,\"external_score\":%s,\"attack_types\":\"%s\",\"updated_at\":\"%s\"}",
                        PQgetvalue(res, i, 0), PQgetvalue(res, i, 1), PQgetvalue(res, i, 2), PQgetvalue(res, i, 3), PQgetvalue(res, i, 4), PQgetvalue(res, i, 5));
    }
    json_buf_append(&jb, "]");
    PQclear(res);
    return jb.buf;
}

int db_add_yara_rule(const char *name, const char *content) {
    const char *sql = 
        "INSERT INTO yara_rules (name, content, updated_at) VALUES ($1, $2, NOW()) "
        "ON CONFLICT (name) DO UPDATE SET content = EXCLUDED.content, updated_at = NOW();";
    const char *paramValues[2] = { name, content };
    PGresult *res = PQexecParams(conn, sql, 2, NULL, paramValues, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[db] Add YARA rule failed: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }
    PQclear(res);
    return 0;
}

int db_delete_yara_rule(const char *name) {
    const char *sql = "DELETE FROM yara_rules WHERE name = $1;";
    const char *paramValues[1] = { name };
    PGresult *res = PQexecParams(conn, sql, 1, NULL, paramValues, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[db] Delete YARA rule failed: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }
    PQclear(res);
    return 0;
}

char *db_get_yara_rules_json(void) {
    const char *sql = "SELECT id, name, content, enabled, match_count, updated_at FROM yara_rules ORDER BY name ASC;";
    PGresult *res = PQexec(conn, sql);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        return strdup("[]");
    }

    int rows = PQntuples(res);
    struct json_buf jb;
    json_buf_init(&jb);
    json_buf_append(&jb, "[");

    for (int i = 0; i < rows; i++) {
        if (i > 0) json_buf_append(&jb, ",");
        char esc_content[4096] = {0};
        escape_json_str(PQgetvalue(res, i, 2), esc_content, sizeof(esc_content));

        json_buf_append(&jb, "{\"id\":%s,\"name\":\"%s\",\"content\":\"%s\",\"enabled\":%s,\"match_count\":%s,\"updated_at\":\"%s\"}",
                        PQgetvalue(res, i, 0), PQgetvalue(res, i, 1), esc_content, 
                        strcmp(PQgetvalue(res, i, 3), "t") == 0 ? "true" : "false",
                        PQgetvalue(res, i, 4), PQgetvalue(res, i, 5));
    }
    json_buf_append(&jb, "]");
    PQclear(res);
    return jb.buf;
}

int db_set_config(const char *key, const char *value, const char *category, const char *description) {
    const char *sql = 
        "INSERT INTO config (key, value, category, description, updated_at) VALUES ($1, $2::jsonb, $3, $4, NOW()) "
        "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW();";
    const char *paramValues[4] = { key, value, category, description };
    PGresult *res = PQexecParams(conn, sql, 4, NULL, paramValues, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[db] Set config failed: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }
    PQclear(res);
    return 0;
}

char *db_get_config_json(void) {
    const char *sql = "SELECT key, value::text, category, description FROM config;";
    PGresult *res = PQexec(conn, sql);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        return strdup("{}");
    }

    int rows = PQntuples(res);
    struct json_buf jb;
    json_buf_init(&jb);
    json_buf_append(&jb, "{");

    for (int i = 0; i < rows; i++) {
        if (i > 0) json_buf_append(&jb, ",");
        json_buf_append(&jb, "\"%s\":{\"value\":%s,\"category\":\"%s\",\"description\":\"%s\"}",
                        PQgetvalue(res, i, 0), PQgetvalue(res, i, 1), PQgetvalue(res, i, 2), PQgetvalue(res, i, 3) ? PQgetvalue(res, i, 3) : "");
    }
    json_buf_append(&jb, "}");
    PQclear(res);
    return jb.buf;
}

int db_save_threat_intel(const char *feed_name, const char *ind_type, const char *ind_val, const char *threat_type, int confidence, const char *source_url) {
    const char *sql = 
        "INSERT INTO threat_intel (feed_name, indicator_type, indicator_value, threat_type, confidence, source_url) "
        "VALUES ($1, $2, $3, $4, $5, $6);";

    char conf_str[16];
    snprintf(conf_str, sizeof(conf_str), "%d", confidence);

    const char *paramValues[6] = { feed_name, ind_type, ind_val, threat_type, conf_str, source_url };
    PGresult *res = PQexecParams(conn, sql, 6, NULL, paramValues, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[db] Save threat intel failed: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return -1;
    }
    PQclear(res);
    return 0;
}

char *db_get_threat_intel_json(void) {
    const char *sql = "SELECT id, feed_name, indicator_type, indicator_value, threat_type, confidence, source_url, fetched_at FROM threat_intel ORDER BY id DESC LIMIT 100;";
    PGresult *res = PQexec(conn, sql);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        PQclear(res);
        return strdup("[]");
    }

    int rows = PQntuples(res);
    struct json_buf jb;
    json_buf_init(&jb);
    json_buf_append(&jb, "[");

    for (int i = 0; i < rows; i++) {
        if (i > 0) json_buf_append(&jb, ",");
        json_buf_append(&jb, "{\"id\":%s,\"feed_name\":\"%s\",\"indicator_type\":\"%s\",\"indicator_value\":\"%s\",\"threat_type\":\"%s\",\"confidence\":%s,\"source_url\":\"%s\",\"fetched_at\":\"%s\"}",
                        PQgetvalue(res, i, 0), PQgetvalue(res, i, 1), PQgetvalue(res, i, 2), PQgetvalue(res, i, 3), PQgetvalue(res, i, 4), PQgetvalue(res, i, 5), PQgetvalue(res, i, 6), PQgetvalue(res, i, 7));
    }
    json_buf_append(&jb, "]");
    PQclear(res);
    return jb.buf;
}
