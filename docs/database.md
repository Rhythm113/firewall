# Database Schema and Operations

## Overview

PostgreSQL 15-alpine database named "nullsploit". All tables are
created automatically by db_init() on startup. The Spring Boot
application also uses the same database via JDBC/JPA.

## Key Tables

### agents

Tracks registered firewall agent nodes.

```sql
CREATE TABLE agents (
  uuid UUID PRIMARY KEY,
  hostname TEXT,
  ip INET NOT NULL,
  last_seen TIMESTAMPTZ,
  status TEXT DEFAULT 'unknown',
  config JSONB DEFAULT '{}',
  registered_at TIMESTAMPTZ DEFAULT NOW()
);
```

Used by: soc_receiver on agent connect/ping, DashboardController
for agent listing.

### events

Stores all security events from agents.

```sql
CREATE TABLE events (
  id BIGSERIAL PRIMARY KEY,
  agent_uuid UUID REFERENCES agents(uuid) ON DELETE SET NULL,
  timestamp TIMESTAMPTZ NOT NULL,
  src_ip INET,
  dest_ip INET,
  src_port INTEGER,
  dest_port INTEGER,
  threat_type INTEGER NOT NULL,
  severity INTEGER NOT NULL,
  payload_preview TEXT,
  details TEXT,
  detection_module TEXT,
  confidence INTEGER DEFAULT 100,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
```

Indexes: timestamp DESC, agent_uuid.

### ip_reputation

Tracks per-IP reputation scores (both local and external).

```sql
CREATE TABLE ip_reputation (
  ip INET PRIMARY KEY,
  score INTEGER DEFAULT 100,
  local_score INTEGER DEFAULT 100,
  external_score INTEGER DEFAULT 100,
  total_blocks INTEGER DEFAULT 0,
  attack_types TEXT[] DEFAULT '{}',
  first_seen TIMESTAMPTZ DEFAULT NOW(),
  last_seen TIMESTAMPTZ DEFAULT NOW(),
  manual_override INTEGER DEFAULT -1,
  updated_at TIMESTAMPTZ DEFAULT NOW()
);
```

Score arithmetic: score = LEAST(local_score, external_score).

### blocklist

Stores IPs/CIDRs that should be blocked.

```sql
CREATE TABLE blocklist (
  id SERIAL PRIMARY KEY,
  ip_cidr CIDR NOT NULL,
  list_type TEXT NOT NULL DEFAULT 'block',
  source TEXT DEFAULT 'manual',
  reason TEXT,
  added_by TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
```

Index: list_type.

### threat_intel

Stores indicators from external threat intelligence feeds.

```sql
CREATE TABLE threat_intel (
  id BIGSERIAL PRIMARY KEY,
  feed_name TEXT NOT NULL,
  indicator_type TEXT NOT NULL,
  indicator_value TEXT NOT NULL,
  threat_type TEXT,
  confidence INTEGER,
  source_url TEXT,
  raw_data JSONB DEFAULT '{}',
  fetched_at TIMESTAMPTZ DEFAULT NOW(),
  expires_at TIMESTAMPTZ
);
```

### yara_rules

Stores YARA signature rules.

```sql
CREATE TABLE yara_rules (
  id SERIAL PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  content TEXT NOT NULL,
  enabled BOOLEAN DEFAULT TRUE,
  match_count INTEGER DEFAULT 0,
  last_match TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);
```

### config

Key-value store for system configuration.

```sql
CREATE TABLE config (
  key TEXT PRIMARY KEY,
  value JSONB NOT NULL,
  category TEXT NOT NULL,
  description TEXT,
  updated_at TIMESTAMPTZ DEFAULT NOW()
);
```

Categories include: ai, notifications, system, web.

### ai_analysis_dataset

Stores AI analysis results for security events.

```sql
CREATE TABLE ai_analysis_dataset (
  id SERIAL PRIMARY KEY,
  event_id BIGINT UNIQUE REFERENCES events(id) ON DELETE CASCADE,
  threat_detected BOOLEAN NOT NULL,
  confidence INTEGER NOT NULL,
  explanation TEXT,
  model_used TEXT,
  analyzed_at TIMESTAMPTZ DEFAULT NOW()
);
```

Index: event_id.

### agent_logs

Records agent-server interaction logs.

```sql
CREATE TABLE agent_logs (
  id BIGSERIAL PRIMARY KEY,
  agent_uuid UUID,
  log_type TEXT NOT NULL DEFAULT 'info',
  message TEXT,
  src_ip INET,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
```

Indexes: agent_uuid, created_at DESC.

## Database API (db.c)

All database operations are in soc-server/db.c. Key functions:

### Connection Management

- db_init(conninfo) -- Connect and create all tables
  Uses environment variables for connection params:
  PGHOST, PGPORT, PGDATABASE, PGUSER, PGPASSWORD
  Retries up to 15 times with 5-second intervals
- db_close() -- Disconnect

### Agent Operations

- db_register_agent() -- INSERT or UPDATE (ON CONFLICT) agent record
- db_update_agent_last_seen() -- Alias for register with hostname
- db_remove_agent() -- DELETE agent by UUID

### Event Operations

- db_insert_event() -- Insert a single event from fw_event struct
- db_get_events_json() -- Query events with pagination and agent
  filter. Returns JSON string.
- db_get_agents_json() -- List all agents as JSON
- db_get_stats_json() -- Statistics: total count, by_threat,
  by_severity, last-24-hour timeline

### Agent Logs

- db_insert_agent_log() -- Insert a log entry
- db_get_agent_logs_json() -- Query logs with ILIKE search,
  pagination, returns JSON

### Reputation

- db_update_ip_reputation() -- UPSERT with score calculation
- db_get_reputation_json() -- Query by IP or list all (score ASC)

### Blocklist

- db_add_to_blocklist() / db_remove_from_blocklist()
- db_get_blocklist_json() -- Filter by list_type

### YARA

- db_add_yara_rule() / db_delete_yara_rule()
- db_get_yara_rules_json() -- All rules with escaped content

### Config

- db_set_config() -- UPSERT key/value as JSONB
- db_get_config_json() -- All config keyed by name

### Threat Intel

- db_save_threat_intel() -- Insert indicator
- db_get_threat_intel_json() -- Last 100 entries

## JSON Builder

db.c includes a custom JSON builder (json_buf) for constructing
API responses without external JSON libraries:

- json_buf_init() -- Allocate initial 4096-byte buffer
- json_buf_append() -- printf-style formatted append with auto-grow
- escape_json_str() -- Escape quotes, backslashes, and control chars

## Query Patterns

- All queries use parameterized statements (PQexecParams) to prevent
  SQL injection
- UUIDs are stored as PostgreSQL UUID type, passed as hex strings
- IPs are stored as INET type, formatted with host() function
- JSON escaping is done manually for C-side JSON responses
