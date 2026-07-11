# Spring Boot Dashboard Backend

## Overview

The Spring Boot application serves the SOC dashboard REST API and
handles background services (AI analysis, notifications, monitoring).

Base package: com.nullsploit
Port: 8443
Java: 17 (OpenJDK)
Build: Maven (pom.xml)

## Main Application

### DashboardApplication.java

```java
@SpringBootApplication
@EnableScheduling
public class DashboardApplication {
    public static void main(String[] args) {
        SpringApplication.run(DashboardApplication.class, args);
    }
}
```

Enables Spring Scheduling for @Scheduled background tasks.

## Configuration

### application.properties

```properties
spring.datasource.url=jdbc:postgresql://${PGHOST:postgres}:${PGPORT:5432}/${PGDATABASE:nullsploit}
spring.datasource.username=${PGUSER:nullsploit}
spring.datasource.password=${PGPASSWORD:nullsploit_secure}
server.port=8443
spring.jpa.hibernate.ddl-auto=none
```

Database connection uses environment variables with defaults for
Docker Compose networking.

### WebConfig.java

Intercepts all /api/v2/** endpoints (except /auth) for session token
verification. Maintains a static synchronized Set<String> of active
tokens. Returns 401 for invalid/missing tokens.

## REST Controller (DashboardController.java)

### Endpoints

#### Dashboard Stats
- GET /api/v2/dashboard/stats
  Params: timeframe (1h/24h/7d), agent (UUID or "all")
  Returns: total_events, by_threat, by_severity, timeline
  Timeline SQL uses GROUP BY 1 ORDER BY MIN(timestamp) ASC to
  support PostgreSQL versions < 16.

#### Events
- GET /api/v2/events
  Params: limit, offset, search, severity, threat_type
  Returns: Paginated event list with filtering

#### Agents
- GET /api/v2/agents
  Returns: Agent list with active/offline status (30-second window)
- DELETE /api/v2/agents/{uuid}
  Removes agent from database

#### Authentication
- POST /api/v2/auth
  Body: { username, password }
  Returns: Session token or failure

#### Blocklist
- GET /api/v2/blocklist
- POST /api/v2/blocklist (body: { ip_cidr, reason })
- DELETE /api/v2/blocklist (param: ipCidr)
  Block/unblock operations push updates to agents via port 8444

#### Reputation
- GET /api/v2/reputation (params: type, limit, offset)
- GET /api/v2/reputation/count (params: type)
- DELETE /api/v2/reputation (params: ip)

#### Agent Logs
- GET /api/v2/agent-logs (params: limit, offset, search)
  Supports ILIKE search on message, log_type, and src_ip

#### YARA Rules
- GET /api/v2/yara/rules
- POST /api/v2/yara/rules (body: { name, content })
- DELETE /api/v2/yara/rules/{name}

#### Configuration
- GET /api/v2/config
- POST /api/v2/config (body: { key, value, category })
  Special handling for block_local_ips: pushes to agents via 8444
- POST /api/v2/config/test-email (tests SMTP config)

#### Threat Intel
- GET /api/v2/threat-intel
- POST /api/v2/threat-intel/fetch (proxies to C receiver:8445)

#### AI Analysis
- GET /api/v2/ai/status
  Returns: total_events, analyzed_events, pending_events,
  progress_percent, status, last_run, pending_count, analyzed_count
- GET /api/v2/dataset (last 50 analyzed events with event details)
- GET /api/v2/dataset/download (CSV export)

#### Health Monitoring
- GET /api/v2/monitor/health
  Returns: CPU, memory, threads, event throughput, spike alerts

#### Internal
- POST /api/v2/internal/push-event
  Requires X-Internal-Key: soc-receiver-forward
  Broadcasts event to all SSE clients immediately

#### SSE
- GET /api/v2/events/live (params: token)
  Returns: SseEmitter (1-hour timeout)
  Sends formatted time with EXTRACT(epoch) as timestamp

## Event Lifecycle

1. C receiver forwards event to POST /internal/push-event
2. Controller.handleNewEvent() broadcasts to all SSE emitters via
   NewEventDetectedEvent (Spring ApplicationEvent)
3. AIService.runAIAnalysis() picks up unanalyzed events every 10s
4. NotificationService.checkNewEventsAndNotify() runs every 5s

## SSE (Server-Sent Events)

### emitter Management
- CopyOnWriteArrayList of SseEmitter objects
- handleNewEvent() @EventListens for NewEventDetectedEvent
- checkEmitterHealth() @Scheduled every 30s removes dead emitters

### Flow
1. Client connects to GET /events/live with valid token
2. SseEmitter created with 1-hour timeout
3. Events pushed as JSON when received
4. Keepalive comments sent every 30 seconds

## AIService.java

Runs @Scheduled(fixedDelay=10000) for AI analysis.

### Flow
1. Check if API key is configured (opencode_api_key)
2. Fetch model name and API URL from config table
3. Enforce HTTPS for API URL
4. Query unanalyzed events (LEFT JOIN ai_analysis_dataset)
5. Process up to 5 individual events per cycle
6. Batch-process Slowloris events (up to 100 at once)
7. Write results to ai_analysis_dataset table
8. Update status config keys (ai_status, ai_pending_count, etc.)

### API Details
- Endpoint: configurable (default: https://opencode.ai/zen/v1/chat/completions)
- Model: configurable (default: opencode/deepseek-v4-flash-free)
- Auth: Bearer token or X-API-Key header
- Request: OpenAI-compatible chat completions format
- Response format: { threat_detected: bool, confidence: int, explanation: string }
- System prompt: "You are a WAF Security Expert..."

### Slowloris Batch Processing
Collects up to 100 unanalyzed Slowloris events and sends a single
aggregated prompt. The same analysis result is applied to all events
in the batch. This avoids wasting API credits on near-identical events.

### Status Tracking
Writes to config table:
- ai_status: "idle", "running (N pending)", "error: ..."
- ai_pending_count: Number of unanalyzed events
- ai_analyzed_count: Total analyzed
- ai_last_run: Timestamp of last run

## NotificationService.java

Runs @Scheduled(fixedDelay=5000) for event processing and
notifications.

### Reputation Sync (every 30 seconds)
1. Aggregate events by src_ip with severity-weighted scoring
2. Update ip_reputation table with calculated local_score
3. Auto-block IPs with combined score <= 20
4. Circuit breaker: only runs every 30 seconds

### Email Notifications
1. Check for new events (id > lastProcessedId)
2. If SMTP enabled: send email for WARNING and CRITICAL events
3. Uses JavaMailSenderImpl with configurable SMTP settings
4. Connection timeout: 3 seconds
5. HTML email template with dark theme styling

### Config Keys
- smtp_host, smtp_port, smtp_username, smtp_password
- smtp_auth, smtp_tls, smtp_from, smtp_to
- smtp_enabled, last_notified_event_id

## MonitorService.java

System health monitoring with:

### CPU
- Process CPU load (via com.sun.management.OperatingSystemMXBean)
- System load average
- Available processors

### Memory
- JVM heap: max, used, free, used_percent

### Threads
- Current thread count, daemon count, peak count

### Event Throughput
- Events in last 60s, 5min, 1h
- Rate per second
- Per-minute breakdown for last 10 minutes (sparkline)

### Spike Detection
- Rolling window of 10 samples (each sample = events last 60s)
- Spike if current > 2x average AND current > 10 events/min
- CRITICAL if current > 3x average, WARNING otherwise
