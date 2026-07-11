package com.nullsploit.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import org.springframework.http.*;

import java.io.OutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.BufferedReader;
import java.net.Socket;
import java.util.*;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;
import org.springframework.context.event.EventListener;
import com.nullsploit.event.NewEventDetectedEvent;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.springframework.scheduling.annotation.Scheduled;
import com.fasterxml.jackson.databind.ObjectMapper;

@RestController
@CrossOrigin(origins = "*")
@RequestMapping("/api/v2")
public class DashboardController {

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private com.nullsploit.service.NotificationService notificationService;

    @Autowired
    private com.nullsploit.service.MonitorService monitorService;

    private final ObjectMapper mapper = new ObjectMapper();

    private static final List<SseEmitter> emitters = new java.util.concurrent.CopyOnWriteArrayList<>();

    @EventListener
    public void handleNewEvent(NewEventDetectedEvent springEvent) {
        Map<String, Object> eventData = springEvent.getEventData();
        if (emitters.isEmpty()) return;

        List<SseEmitter> deadEmitters = new ArrayList<>();
        CountDownLatch latch = new CountDownLatch(emitters.size());

        for (SseEmitter emitter : emitters) {
            CompletableFuture.runAsync(() -> {
                try {
                    emitter.send(SseEmitter.event().data(eventData));
                } catch (Exception e) {
                    deadEmitters.add(emitter);
                } finally {
                    latch.countDown();
                }
            });
        }

        // Wait at most 5 seconds for all emitters to complete
        try {
            latch.await(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        emitters.removeAll(deadEmitters);
    }

    @Scheduled(fixedRate = 30000)
    public void checkEmitterHealth() {
        List<SseEmitter> dead = new ArrayList<>();
        for (SseEmitter em : emitters) {
            try {
                em.send(SseEmitter.event().comment("keepalive"));
            } catch (Exception e) {
                dead.add(em);
            }
        }
        emitters.removeAll(dead);
    }

    @GetMapping(value = "/events/live", produces = org.springframework.http.MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter liveEvents(@RequestParam(required = false) String token) {
        if (token == null || !com.nullsploit.config.WebConfig.activeTokens.contains(token)) {
            throw new org.springframework.web.server.ResponseStatusException(org.springframework.http.HttpStatus.UNAUTHORIZED, "Unauthorized");
        }
        SseEmitter emitter = new SseEmitter(3600000L); // 1 hour
        emitters.add(emitter);
        emitter.onCompletion(() -> emitters.remove(emitter));
        emitter.onTimeout(() -> emitters.remove(emitter));
        emitter.onError((e) -> emitters.remove(emitter));
        return emitter;
    }

    /**
     * Internal endpoint for the C soc_receiver to push events instantly, bypassing
     * the 5-second NotificationService poll. Authenticated via X-Internal-Key header.
     */
    @PostMapping("/internal/push-event")
    public ResponseEntity<?> pushEvent(@RequestBody Map<String, Object> eventData,
                                       @RequestHeader("X-Internal-Key") String key) {
        if (!"soc-receiver-forward".equals(key)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", "invalid key"));
        }
        // Broadcast to all connected SSE clients immediately
        if (emitters.isEmpty()) return ResponseEntity.ok(Map.of("status", "ok"));
        List<SseEmitter> deadEmitters = new ArrayList<>();
        CountDownLatch latch = new CountDownLatch(emitters.size());
        for (SseEmitter emitter : emitters) {
            CompletableFuture.runAsync(() -> {
                try {
                    emitter.send(SseEmitter.event().data(eventData));
                } catch (Exception e) {
                    deadEmitters.add(emitter);
                } finally {
                    latch.countDown();
                }
            });
        }
        try { latch.await(2, TimeUnit.SECONDS); } catch (InterruptedException ignored) {}
        emitters.removeAll(deadEmitters);
        return ResponseEntity.ok(Map.of("status", "ok"));
    }

    // 1. Dashboard Stats
    @GetMapping("/dashboard/stats")
    public Map<String, Object> getStats(
            @RequestParam(required = false) String timeframe,
            @RequestParam(required = false) String agent) {
        
        StringBuilder whereClause = new StringBuilder(" WHERE 1=1");
        List<Object> params = new ArrayList<>();
        
        if (agent != null && !agent.trim().isEmpty() && !agent.equals("all")) {
            whereClause.append(" AND agent_uuid = ?::uuid");
            params.add(agent);
        }
        
        if (timeframe != null) {
            if (timeframe.equals("1h")) {
                whereClause.append(" AND timestamp >= CURRENT_TIMESTAMP - INTERVAL '1 hour'");
            } else if (timeframe.equals("24h")) {
                whereClause.append(" AND timestamp >= CURRENT_TIMESTAMP - INTERVAL '24 hours'");
            } else if (timeframe.equals("7d")) {
                whereClause.append(" AND timestamp >= CURRENT_TIMESTAMP - INTERVAL '7 days'");
            }
        }
        
        Map<String, Object> res = new HashMap<>();
        
        String countSql = "SELECT COUNT(*) FROM events" + whereClause.toString();
        Integer totalEvents = jdbc.queryForObject(countSql, Integer.class, params.toArray());
        res.put("total_events", totalEvents != null ? totalEvents : 0);

        String indicatorSql = "SELECT COUNT(*) FROM events" + whereClause.toString() + " AND threat_type NOT IN (5, 13)";
        Integer totalIndicators = jdbc.queryForObject(indicatorSql, Integer.class, params.toArray());
        res.put("total_indicators", totalIndicators != null ? totalIndicators : 0);

        String threatSql = "SELECT threat_type, COUNT(*) as count FROM events" + whereClause.toString() + " GROUP BY threat_type";
        List<Map<String, Object>> byThreat = jdbc.queryForList(threatSql, params.toArray());
        Map<String, Object> threatMap = new HashMap<>();
        for (Map<String, Object> row : byThreat) {
            threatMap.put(row.get("threat_type").toString(), row.get("count"));
        }
        res.put("by_threat", threatMap);

        String severitySql = "SELECT severity, COUNT(*) as count FROM events" + whereClause.toString() + " GROUP BY severity";
        List<Map<String, Object>> bySeverity = jdbc.queryForList(severitySql, params.toArray());
        Map<String, Object> severityMap = new HashMap<>();
        for (Map<String, Object> row : bySeverity) {
            severityMap.put(row.get("severity").toString(), row.get("count"));
        }
        res.put("by_severity", severityMap);

        String timelineSql = "";
        List<Map<String, Object>> timeline = new ArrayList<>();
        if (timeframe != null && timeframe.equals("1h")) {
            timelineSql = "SELECT to_char(timestamp, 'HH24:MI') as time, COUNT(*) as count " +
                          "FROM events" + whereClause.toString() +
                          " GROUP BY 1 ORDER BY MIN(timestamp) ASC LIMIT 12";
        } else if (timeframe != null && timeframe.equals("7d")) {
            timelineSql = "SELECT to_char(timestamp, 'YYYY-MM-DD') as time, COUNT(*) as count " +
                          "FROM events" + whereClause.toString() +
                          " GROUP BY 1 ORDER BY 1 ASC LIMIT 7";
        } else {
            timelineSql = "SELECT to_char(timestamp, 'HH24') || ':00' as time, COUNT(*) as count " +
                          "FROM events" + whereClause.toString() +
                          " GROUP BY 1 ORDER BY 1 ASC LIMIT 24";
        }

        try {
            timeline = jdbc.queryForList(timelineSql, params.toArray());
            // If no data returned, seed with empty points so the chart doesn't vanish
            if (timeline.isEmpty()) {
                for (int i = 0; i < 10; i++) {
                    Map<String, Object> pt = new HashMap<>();
                    pt.put("time", (i * 2) + ":00");
                    pt.put("count", 0);
                    timeline.add(pt);
                }
            }
        } catch (Exception e) {
            for (int i = 0; i < 10; i++) {
                Map<String, Object> pt = new HashMap<>();
                pt.put("time", (i * 2) + ":00");
                pt.put("count", 0);
                timeline.add(pt);
            }
        }
        res.put("timeline", timeline);

        return res;
    }

    // 2. Events List
    @GetMapping("/events")
    public List<Map<String, Object>> getEvents(
            @RequestParam(defaultValue = "50") int limit,
            @RequestParam(defaultValue = "0") int offset,
            @RequestParam(required = false) String search,
            @RequestParam(required = false) Integer severity,
            @RequestParam(required = false) Integer threat_type) {
        
        StringBuilder sql = new StringBuilder(
            "SELECT id, agent_uuid::text as agent_uuid, EXTRACT(epoch FROM timestamp)::bigint as timestamp, " +
            "host(src_ip) as src_ip, host(dest_ip) as dest_ip, src_port, dest_port, threat_type, severity, " +
            "payload_preview, details FROM events WHERE 1=1"
        );
        List<Object> params = new ArrayList<>();
        
        if (severity != null) {
            sql.append(" AND severity = ?");
            params.add(severity);
        }
        
        if (threat_type != null) {
            sql.append(" AND threat_type = ?");
            params.add(threat_type);
        }
        
        if (search != null && !search.trim().isEmpty()) {
            String term = search.trim();
            sql.append(" AND (host(src_ip) = ? OR host(dest_ip) = ? OR payload_preview LIKE ? OR details LIKE ?)");
            params.add(term);
            params.add(term);
            params.add("%" + term + "%");
            params.add("%" + term + "%");
        }
        
        sql.append(" ORDER BY timestamp DESC LIMIT ? OFFSET ?");
        params.add(limit);
        params.add(offset);
        
        return jdbc.queryForList(sql.toString(), params.toArray());
    }

    // 3. Agents List (Dynamically calculates online/offline status based on 30-sec heartbeat window)
    @GetMapping("/agents")
    public List<Map<String, Object>> getAgents() {
        List<Map<String, Object>> list = jdbc.queryForList(
            "SELECT uuid::text as uuid, hostname, ip, " +
            "CASE WHEN last_seen >= CURRENT_TIMESTAMP - INTERVAL '30 seconds' THEN 'active' ELSE 'offline' END as status, " +
            "last_seen FROM agents"
        );
        return sanitizeIps(list, "ip");
    }

    // 3b. Dashboard Authentication
    @PostMapping("/auth")
    public Map<String, Object> login(@RequestBody Map<String, String> credentials) {
        String username = credentials.get("username");
        String password = credentials.get("password");
        Map<String, Object> res = new HashMap<>();

        if (verifyUser(username, password)) {
            String token = UUID.randomUUID().toString();
            com.nullsploit.config.WebConfig.activeTokens.add(token);
            res.put("status", "success");
            res.put("token", token);
        } else {
            res.put("status", "failed");
        }
        return res;
    }

    private boolean verifyUser(String username, String password) {
        try {
            File file = new File("/etc/soc/users.conf");
            if (!file.exists()) {
                // Local debug credentials fallback
                return "admin".equals(username) && "password".equals(password);
            }
            try (BufferedReader br = new BufferedReader(new FileReader(file))) {
                String line;
                while ((line = br.readLine()) != null) {
                    line = line.trim();
                    if (line.startsWith("#") || line.isEmpty()) continue;
                    String[] parts = line.split(":", 2);
                    if (parts.length == 2 && parts[0].equals(username)) {
                        return BCrypt.checkpw(password, parts[1]);
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    // 4. Delete Agent
    @DeleteMapping("/agents/{uuid}")
    public Map<String, String> deleteAgent(@PathVariable String uuid) {
        jdbc.update("DELETE FROM agents WHERE uuid = ?::uuid", uuid);
        Map<String, String> res = new HashMap<>();
        res.put("status", "removed");
        return res;
    }

    // 5. Block IP downstream (Sends command to C receiver on local port 8444)
    @PostMapping("/agents/{uuid}/block-ip")
    public Map<String, String> blockAgentIp(@PathVariable String uuid, @RequestBody Map<String, String> body) {
        String ip = body.get("ip");
        Map<String, String> res = new HashMap<>();

        try {
            // Parse IP string to network byte order integer
            String[] parts = ip.split("\\.");
            long ipVal = 0;
            for (int i = 0; i < 4; i++) {
                ipVal |= (Long.parseLong(parts[i]) << (i * 8));
            }

            // Communicate with C receiver over TCP port 8444
            try (Socket socket = new Socket("127.0.0.1", 8444);
                 OutputStream out = socket.getOutputStream()) {
                
                // Construct control payload matching C local_cmd struct
                byte[] uuidBytes = new byte[33];
                byte[] rawUuid = uuid.replace("-", "").getBytes();
                System.arraycopy(rawUuid, 0, uuidBytes, 0, Math.min(rawUuid.length, 32));
                
                out.write(uuidBytes); // 33 bytes agent_uuid_hex
                out.write(3);         // 1 byte MSG_TYPE_BLOCK_IP (3)
                
                byte[] ipBytes = new byte[4];
                ipBytes[0] = (byte) (ipVal & 0xFF);
                ipBytes[1] = (byte) ((ipVal >> 8) & 0xFF);
                ipBytes[2] = (byte) ((ipVal >> 16) & 0xFF);
                ipBytes[3] = (byte) ((ipVal >> 24) & 0xFF);
                out.write(ipBytes);   // 4 bytes IP address
                
                out.flush();
            }

            res.put("status", "blocked");
        } catch (Exception e) {
            res.put("error", "agent_offline");
        }

        return res;
    }

    // 6. Get Blocklist
    @GetMapping("/blocklist")
    public List<Map<String, Object>> getBlocklist() {
        List<Map<String, Object>> list = jdbc.queryForList(
            "SELECT id, host(ip_cidr) as ip_cidr, list_type, reason, created_at FROM blocklist"
        );
        return sanitizeIps(list, "ip_cidr");
    }

    // 7. Add to Blocklist
    @PostMapping("/blocklist")
    public Map<String, String> addBlocklist(@RequestBody Map<String, String> body) {
        String ipCidr = body.get("ip_cidr");
        String reason = body.get("reason");
        jdbc.update(
            "INSERT INTO blocklist (ip_cidr, list_type, reason) VALUES (?::cidr, 'block', ?)",
            ipCidr, reason
        );
        notificationService.pushBlocklistUpdateToAgents(ipCidr, 3); // 3 = MSG_TYPE_BLOCK_IP
        Map<String, String> res = new HashMap<>();
        res.put("status", "added");
        return res;
    }

    // 8. Delete from Blocklist
    @DeleteMapping("/blocklist")
    public Map<String, String> removeBlocklist(@RequestParam String ipCidr) {
        jdbc.update("DELETE FROM blocklist WHERE ip_cidr = ?::cidr", ipCidr);
        notificationService.pushBlocklistUpdateToAgents(ipCidr, 4); // 4 = MSG_TYPE_UNBLOCK_IP
        Map<String, String> res = new HashMap<>();
        res.put("status", "removed");
        return res;
    }

    // 9. Get IP Reputation
    @GetMapping("/reputation")
    public List<Map<String, Object>> getReputation(@RequestParam(required = false) String type,
                                                      @RequestParam(defaultValue = "0") int limit,
                                                      @RequestParam(defaultValue = "0") int offset) {
        List<Map<String, Object>> list;
        if ("local".equalsIgnoreCase(type)) {
            String sql = "SELECT host(ip) as ip, score, local_score, external_score, array_to_string(attack_types, ',') as attack_types, updated_at FROM ip_reputation WHERE local_score < 100 ORDER BY local_score ASC";
            if (limit > 0) {
                sql += " LIMIT " + limit + " OFFSET " + offset;
            }
            list = jdbc.queryForList(sql);
        } else if ("external".equalsIgnoreCase(type)) {
            String sql = "SELECT host(ip) as ip, score, local_score, external_score, array_to_string(attack_types, ',') as attack_types, updated_at FROM ip_reputation WHERE external_score < 100 ORDER BY external_score ASC";
            if (limit > 0) {
                sql += " LIMIT " + limit + " OFFSET " + offset;
            }
            list = jdbc.queryForList(sql);
        } else {
            list = jdbc.queryForList(
                "SELECT host(ip) as ip, score, local_score, external_score, array_to_string(attack_types, ',') as attack_types, updated_at FROM ip_reputation ORDER BY score ASC"
            );
        }
        return sanitizeIps(list, "ip");
    }

    // 9a. Get IP Reputation Count
    @GetMapping("/reputation/count")
    public Map<String, Object> getReputationCount(@RequestParam(required = false) String type) {
        Map<String, Object> result = new HashMap<>();
        long count;
        if ("local".equalsIgnoreCase(type)) {
            count = jdbc.queryForObject("SELECT COUNT(*) FROM ip_reputation WHERE local_score < 100", Long.class);
        } else if ("external".equalsIgnoreCase(type)) {
            count = jdbc.queryForObject("SELECT COUNT(*) FROM ip_reputation WHERE external_score < 100", Long.class);
        } else {
            count = jdbc.queryForObject("SELECT COUNT(*) FROM ip_reputation", Long.class);
        }
        result.put("count", count);
        return result;
    }

    // 9b. Clear IP Reputation
    @DeleteMapping("/reputation")
    public Map<String, String> clearReputation(@RequestParam(required = false) String ip) {
        Map<String, String> res = new HashMap<>();
        if (ip != null && !ip.trim().isEmpty()) {
            String ipStr = ip.trim();
            jdbc.update("DELETE FROM ip_reputation WHERE ip = ?::inet", ipStr);
            jdbc.update("DELETE FROM events WHERE src_ip = ?::inet", ipStr);
            jdbc.update("DELETE FROM blocklist WHERE ip_cidr = ?::cidr AND source = 'system'", ipStr);
            notificationService.pushBlocklistUpdateToAgents(ipStr, 4); // 4 = MSG_TYPE_UNBLOCK_IP
            res.put("status", "cleared_ip");
        } else {
            List<String> autoBlockedIps = jdbc.queryForList(
                "SELECT host(ip_cidr) FROM blocklist WHERE source = 'system'",
                String.class
            );
            jdbc.update("DELETE FROM ip_reputation");
            jdbc.update("DELETE FROM events");
            jdbc.update("DELETE FROM blocklist WHERE source = 'system'");
            for (String blockedIp : autoBlockedIps) {
                notificationService.pushBlocklistUpdateToAgents(blockedIp, 4); // 4 = MSG_TYPE_UNBLOCK_IP
            }
            res.put("status", "cleared_all");
        }
        return res;
    }

    // 10. Get YARA rules
    @GetMapping("/yara/rules")
    public List<Map<String, Object>> getYaraRules() {
        return jdbc.queryForList(
            "SELECT id, name, match_count, updated_at FROM yara_rules"
        );
    }

    // 11. Add YARA rule
    @PostMapping("/yara/rules")
    public Map<String, String> addYaraRule(@RequestBody Map<String, String> body) {
        String name = body.get("name");
        String content = body.get("content");
        jdbc.update(
            "INSERT INTO yara_rules (name, content) VALUES (?, ?)",
            name, content
        );
        Map<String, String> res = new HashMap<>();
        res.put("status", "added");
        return res;
    }

    // 12. Delete YARA rule
    @DeleteMapping("/yara/rules/{name}")
    public Map<String, String> deleteYaraRule(@PathVariable String name) {
        jdbc.update("DELETE FROM yara_rules WHERE name = ?", name);
        Map<String, String> res = new HashMap<>();
        res.put("status", "removed");
        return res;
    }

    // 13. Get Configs
    @GetMapping("/config")
    public List<Map<String, Object>> getConfig() {
        return jdbc.queryForList(
            "SELECT key, value, category, description FROM config"
        );
    }

    // 14. Set Config
    @PostMapping("/config")
    public Map<String, String> setConfig(@RequestBody Map<String, Object> body) {
        String key = (String) body.get("key");
        String value = body.get("value").toString();
        String category = (String) body.get("category");
        jdbc.update(
            "INSERT INTO config (key, value, category, description) VALUES (?, ?::jsonb, ?, 'Updated via Spring Boot') " +
            "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
            key, value, category
        );

        if ("block_local_ips".equals(key)) {
            int val = 0;
            if (value.contains("true") || value.contains("1")) {
                val = 1;
            }
            
            // Get all online agents (seen in the last 30 seconds)
            List<String> uuids = jdbc.queryForList(
                "SELECT uuid::text FROM agents WHERE last_seen >= CURRENT_TIMESTAMP - INTERVAL '30 seconds'",
                String.class
            );
            
            for (String uuid : uuids) {
                try (Socket socket = new Socket("127.0.0.1", 8444);
                     OutputStream out = socket.getOutputStream()) {
                    
                    byte[] uuidBytes = new byte[33];
                    byte[] rawUuid = uuid.replace("-", "").getBytes();
                    System.arraycopy(rawUuid, 0, uuidBytes, 0, Math.min(rawUuid.length, 32));
                    
                    out.write(uuidBytes); // 33 bytes agent_uuid_hex
                    out.write(5);         // 1 byte MSG_TYPE_CONFIG_UPDATE (5)
                    
                    byte[] valBytes = new byte[4];
                    valBytes[0] = (byte) (val & 0xFF);
                    valBytes[1] = (byte) ((val >> 8) & 0xFF);
                    valBytes[2] = (byte) ((val >> 16) & 0xFF);
                    valBytes[3] = (byte) ((val >> 24) & 0xFF);
                    out.write(valBytes);   // 4 bytes payload
                    
                    out.flush();
                } catch (Exception e) {
                    System.err.println("Failed to push config update to agent " + uuid + ": " + e.getMessage());
                }
            }
        }

        Map<String, String> res = new HashMap<>();
        res.put("status", "saved");
        return res;
    }

    // 14b. Test Email
    @PostMapping("/config/test-email")
    public Map<String, String> sendTestEmail() {
        Map<String, String> res = new HashMap<>();
        try {
            notificationService.sendTestEmail();
            res.put("status", "success");
        } catch (Exception e) {
            res.put("status", "failed");
            res.put("error", e.getMessage());
        }
        return res;
    }

    // 15. Get Threat Intel
    @GetMapping("/threat-intel")
    public List<Map<String, Object>> getThreatIntel() {
        return jdbc.queryForList(
            "SELECT id, feed_name, indicator_type, indicator_value, threat_type, confidence, source_url, fetched_at FROM threat_intel"
        );
    }

    // 15c. AI Analysis Status & Progress
    @GetMapping("/ai/status")
    public Map<String, Object> getAIStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        try {
            Long totalEvents = jdbc.queryForObject("SELECT COUNT(*) FROM events", Long.class);
            Long analyzedCount = jdbc.queryForObject("SELECT COUNT(*) FROM ai_analysis_dataset", Long.class);
            Long pendingCount = jdbc.queryForObject(
                "SELECT COUNT(*) FROM events e LEFT JOIN ai_analysis_dataset a ON e.id = a.event_id WHERE a.event_id IS NULL",
                Long.class
            );

            status.put("total_events", totalEvents != null ? totalEvents : 0);
            status.put("analyzed_events", analyzedCount != null ? analyzedCount : 0);
            status.put("pending_events", pendingCount != null ? pendingCount : 0);

            // Fetch status from config table
            String[][] configKeys = {{"ai_status", "status"}, {"ai_last_run", "last_run"},
                                     {"ai_pending_count", "pending_count"}, {"ai_analyzed_count", "analyzed_count"}};
            for (String[] pair : configKeys) {
                try {
                    String valJson = jdbc.queryForObject("SELECT value::text FROM config WHERE key = ?", String.class, pair[0]);
                    if (valJson != null) {
                        Map<String, Object> parsed = mapper.readValue(valJson.trim(), Map.class);
                        Object v = parsed.get("value");
                        status.put(pair[1], v != null ? v.toString() : "");
                    }
                } catch (Exception e) {
                    // key might not exist yet
                }
            }

            double progress = (totalEvents != null && totalEvents > 0)
                ? Math.round((analyzedCount * 1000.0 / totalEvents)) / 10.0
                : 0.0;
            status.put("progress_percent", progress);
        } catch (Exception e) {
            status.put("error", e.getMessage());
        }
        return status;
    }

    // 16. Get AI Dataset list
    @GetMapping("/dataset")
    public List<Map<String, Object>> getDatasetList() {
        return jdbc.queryForList(
            "SELECT d.id, d.event_id, host(e.src_ip) as src_ip, host(e.dest_ip) as dest_ip, e.threat_type, e.severity, " +
            "d.threat_detected, d.confidence, d.explanation, d.model_used, d.analyzed_at " +
            "FROM ai_analysis_dataset d " +
            "JOIN events e ON d.event_id = e.id " +
            "ORDER BY d.id DESC LIMIT 50"
        );
    }

    // 17. Download AI Dataset CSV
    @GetMapping("/dataset/download")
    public void downloadDataset(HttpServletResponse response) throws IOException {
        response.setContentType("text/csv");
        response.setHeader("Content-Disposition", "attachment; filename=ai_threat_dataset.csv");
        
        PrintWriter writer = response.getWriter();
        writer.println("id,event_id,src_ip,dest_ip,threat_type,severity,payload_preview,details,threat_detected,confidence,explanation,model_used,analyzed_at");
        
        List<Map<String, Object>> rows = jdbc.queryForList(
            "SELECT d.id, d.event_id, host(e.src_ip) as src_ip, host(e.dest_ip) as dest_ip, e.threat_type, e.severity, " +
            "e.payload_preview, e.details, d.threat_detected, d.confidence, d.explanation, d.model_used, d.analyzed_at " +
            "FROM ai_analysis_dataset d " +
            "JOIN events e ON d.event_id = e.id " +
            "ORDER BY d.id DESC"
        );
        
        for (Map<String, Object> row : rows) {
            writer.printf("%s,%s,%s,%s,%s,%s,\"%s\",\"%s\",%s,%s,\"%s\",\"%s\",%s\n",
                row.get("id"),
                row.get("event_id"),
                row.get("src_ip"),
                row.get("dest_ip"),
                row.get("threat_type"),
                row.get("severity"),
                escapeCsv(row.get("payload_preview")),
                escapeCsv(row.get("details")),
                row.get("threat_detected"),
                row.get("confidence"),
                escapeCsv(row.get("explanation")),
                row.get("model_used"),
                row.get("analyzed_at")
            );
        }
        writer.flush();
    }

    // 19a. Agent Logs - searchable log of agent-server interactions
    @GetMapping("/agent-logs")
    public List<Map<String, Object>> getAgentLogs(
            @RequestParam(defaultValue = "50") int limit,
            @RequestParam(defaultValue = "0") int offset,
            @RequestParam(required = false) String search) {
        StringBuilder sql = new StringBuilder(
            "SELECT l.id, l.agent_uuid::text as agent_uuid, host(l.src_ip) as src_ip, l.log_type, l.message, " +
            "to_char(l.created_at, 'YYYY-MM-DD HH24:MI:SS') as created_at " +
            "FROM agent_logs l WHERE 1=1"
        );
        List<Object> params = new ArrayList<>();
        if (search != null && !search.trim().isEmpty()) {
            sql.append(" AND (l.message ILIKE ? OR l.log_type ILIKE ? OR host(l.src_ip) ILIKE ?)");
            String pattern = "%" + search.trim() + "%";
            params.add(pattern);
            params.add(pattern);
            params.add(pattern);
        }
        sql.append(" ORDER BY l.created_at DESC LIMIT ? OFFSET ?");
        params.add(limit);
        params.add(offset);
        return jdbc.queryForList(sql.toString(), params.toArray());
    }

    // 19b. Trigger Threat Intel Feed Fetch
    @PostMapping("/threat-intel/fetch")
    public Map<String, String> triggerThreatIntelFetch() {
        Map<String, String> res = new HashMap<>();
        try {
            // Forward to C receiver's API via localhost
            java.net.http.HttpClient client = java.net.http.HttpClient.newBuilder()
                .connectTimeout(java.time.Duration.ofSeconds(5))
                .build();
            java.net.http.HttpRequest request = java.net.http.HttpRequest.newBuilder()
                .uri(java.net.URI.create("http://127.0.0.1:8445/api/v2/threat-intel/fetch"))
                .timeout(java.time.Duration.ofSeconds(5))
                .POST(java.net.http.HttpRequest.BodyPublishers.noBody())
                .build();
            client.send(request, java.net.http.HttpResponse.BodyHandlers.discarding());
            res.put("status", "fetching");
        } catch (Exception e) {
            res.put("status", "proxy_error");
            res.put("error", e.getMessage());
        }
        return res;
    }

    // 19. System Health Monitoring (CPU, Memory, Event Throughput, Spike Alerts)
    @GetMapping("/monitor/health")
    public Map<String, Object> getMonitorHealth() {
        return monitorService.getSystemHealth();
    }

    private String escapeCsv(Object value) {
        if (value == null) return "";
        return value.toString().replace("\"", "\"\"");
    }



    private List<Map<String, Object>> sanitizeIps(List<Map<String, Object>> list, String... keys) {
        for (Map<String, Object> map : list) {
            for (String key : keys) {
                Object val = map.get(key);
                if (val != null) {
                    map.put(key, val.toString());
                }
            }
        }
        return list;
    }
}
