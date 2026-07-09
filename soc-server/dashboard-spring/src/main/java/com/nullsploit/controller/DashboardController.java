package com.nullsploit.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import java.io.OutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.BufferedReader;
import java.net.Socket;
import java.util.*;
import org.springframework.security.crypto.bcrypt.BCrypt;

@RestController
@CrossOrigin(origins = "*")
@RequestMapping("/api/v2")
public class DashboardController {

    @Autowired
    private JdbcTemplate jdbc;

    // 1. Dashboard Stats
    @GetMapping("/dashboard/stats")
    public Map<String, Object> getStats() {
        Map<String, Object> res = new HashMap<>();
        
        Integer totalEvents = jdbc.queryForObject("SELECT COUNT(*) FROM events", Integer.class);
        res.put("total_events", totalEvents != null ? totalEvents : 0);

        List<Map<String, Object>> byThreat = jdbc.queryForList(
            "SELECT threat_type, COUNT(*) as count FROM events GROUP BY threat_type"
        );
        Map<String, Object> threatMap = new HashMap<>();
        for (Map<String, Object> row : byThreat) {
            threatMap.put(row.get("threat_type").toString(), row.get("count"));
        }
        res.put("by_threat", threatMap);

        List<Map<String, Object>> bySeverity = jdbc.queryForList(
            "SELECT severity, COUNT(*) as count FROM events GROUP BY severity"
        );
        Map<String, Object> severityMap = new HashMap<>();
        for (Map<String, Object> row : bySeverity) {
            severityMap.put(row.get("severity").toString(), row.get("count"));
        }
        res.put("by_severity", severityMap);

        // Timeline mockup matching 24-hr layout
        List<Map<String, Object>> timeline = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            Map<String, Object> pt = new HashMap<>();
            pt.put("time", (i * 2) + ":00");
            pt.put("count", 5 + (i * 3) % 7);
            timeline.add(pt);
        }
        res.put("timeline", timeline);

        return res;
    }

    // 2. Events List
    @GetMapping("/events")
    public List<Map<String, Object>> getEvents(
            @RequestParam(defaultValue = "50") int limit,
            @RequestParam(defaultValue = "0") int offset) {
        return jdbc.queryForList(
            "SELECT id, agent_uuid::text as agent_uuid, timestamp, src_ip, dest_ip, src_port, dest_port, threat_type, severity, payload_preview, details " +
            "FROM events ORDER BY timestamp DESC LIMIT ? OFFSET ?", limit, offset
        );
    }

    // 3. Agents List (Dynamically calculates online/offline status based on 30-sec heartbeat window)
    @GetMapping("/agents")
    public List<Map<String, Object>> getAgents() {
        return jdbc.queryForList(
            "SELECT uuid::text as uuid, hostname, ip, " +
            "CASE WHEN last_seen >= CURRENT_TIMESTAMP - INTERVAL '30 seconds' THEN 'active' ELSE 'offline' END as status, " +
            "last_seen FROM agents"
        );
    }

    // 3b. Dashboard Authentication
    @PostMapping("/auth")
    public Map<String, Object> login(@RequestBody Map<String, String> credentials) {
        String username = credentials.get("username");
        String password = credentials.get("password");
        Map<String, Object> res = new HashMap<>();

        if (verifyUser(username, password)) {
            res.put("status", "success");
            res.put("token", UUID.randomUUID().toString());
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
                byte[] rawUuid = uuid.getBytes();
                System.arraycopy(rawUuid, 0, uuidBytes, 0, Math.min(rawUuid.length, 32));
                
                out.write(uuidBytes); // 33 bytes agent_uuid_hex
                out.write(1);         // 1 byte MSG_TYPE_BLOCK_IP
                
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
        return jdbc.queryForList(
            "SELECT id, ip_cidr, list_type, reason, created_at FROM blocklist"
        );
    }

    // 7. Add to Blocklist
    @PostMapping("/blocklist")
    public Map<String, String> addBlocklist(@RequestBody Map<String, String> body) {
        String ipCidr = body.get("ip_cidr");
        String reason = body.get("reason");
        jdbc.update(
            "INSERT INTO blocklist (ip_cidr, list_type, reason) VALUES (?, 'block', ?)",
            ipCidr, reason
        );
        Map<String, String> res = new HashMap<>();
        res.put("status", "added");
        return res;
    }

    // 8. Delete from Blocklist
    @DeleteMapping("/blocklist/{ipCidr}")
    public Map<String, String> removeBlocklist(@PathVariable String ipCidr) {
        jdbc.update("DELETE FROM blocklist WHERE ip_cidr = ?", ipCidr);
        Map<String, String> res = new HashMap<>();
        res.put("status", "removed");
        return res;
    }

    // 9. Get IP Reputation
    @GetMapping("/reputation")
    public List<Map<String, Object>> getReputation() {
        return jdbc.queryForList(
            "SELECT ip, score, local_score, external_score, attack_types, updated_at FROM ip_reputation"
        );
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
        Map<String, String> res = new HashMap<>();
        res.put("status", "saved");
        return res;
    }

    // 15. Get Threat Intel
    @GetMapping("/threat-intel")
    public List<Map<String, Object>> getThreatIntel() {
        return jdbc.queryForList(
            "SELECT id, feed_name, indicator_type, indicator_value, threat_type, confidence, source_url, fetched_at FROM threat_intel"
        );
    }
}
