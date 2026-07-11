package com.nullsploit.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import jakarta.mail.internet.MimeMessage;

import java.io.OutputStream;
import java.net.Socket;
import java.util.List;
import java.util.Map;
import java.util.Properties;

@Service
public class NotificationService {

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private org.springframework.context.ApplicationEventPublisher eventPublisher;

    private final ObjectMapper mapper = new ObjectMapper();

    // Cache or track last ID locally, but fallback to DB config key to persist
    private long lastProcessedId = -1;
    private volatile long lastRepUpdate = 0;

    private String getConfigString(String key, String defaultVal) {
        try {
            List<Map<String, Object>> rows = jdbc.queryForList("SELECT value::text FROM config WHERE key = ?", key);
            if (rows.isEmpty()) {
                saveConfig(key, defaultVal, "notifications", "SMTP parameter: " + key);
                return defaultVal;
            }
            String valueJson = (String) rows.get(0).get("value");
            Map<String, Object> map = mapper.readValue(valueJson, Map.class);
            Object v = map.get("value");
            return v != null ? v.toString() : defaultVal;
        } catch (Exception e) {
            return defaultVal;
        }
    }

    private void saveConfig(String key, String value, String category, String description) {
        try {
            String valJson = mapper.writeValueAsString(Map.of("value", value));
            jdbc.update(
                "INSERT INTO config (key, value, category, description, updated_at) VALUES (?, ?::jsonb, ?, ?, NOW()) " +
                "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, category = EXCLUDED.category, updated_at = NOW()",
                key, valJson, category, description
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private JavaMailSenderImpl getMailSender() {
        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
        mailSender.setHost(getConfigString("smtp_host", "smtp.mailtrap.io"));
        mailSender.setPort(Integer.parseInt(getConfigString("smtp_port", "2525")));
        mailSender.setUsername(getConfigString("smtp_username", ""));
        mailSender.setPassword(getConfigString("smtp_password", ""));

        Properties props = mailSender.getJavaMailProperties();
        props.put("mail.transport.protocol", "smtp");
        props.put("mail.smtp.auth", getConfigString("smtp_auth", "true"));
        props.put("mail.smtp.starttls.enable", getConfigString("smtp_tls", "true"));
        props.put("mail.debug", "false");
        // Set connection timeout to 3 seconds to avoid blocking the scheduler
        props.put("mail.smtp.connectiontimeout", "3000");
        props.put("mail.smtp.timeout", "3000");
        props.put("mail.smtp.writetimeout", "3000");

        return mailSender;
    }

    @Scheduled(fixedDelay = 5000)
    public void checkNewEventsAndNotify() {
        // Circuit breaker: only run reputation sync every 30 seconds
        long now = System.currentTimeMillis();
        if (now - lastRepUpdate > 30000) {
            lastRepUpdate = now;
            // Sync events to ip_reputation dynamically based on severity weights
            try {
                jdbc.update(
                "INSERT INTO ip_reputation (ip, local_score, external_score, score, attack_types, updated_at) " +
                "SELECT " +
                "    src_ip, " +
                "    GREATEST(0, 100 - SUM(CASE WHEN severity = 2 THEN 25 WHEN severity = 1 THEN 15 ELSE 5 END)) as calc_local_score, " +
                "    100, " +
                "    GREATEST(0, 100 - SUM(CASE WHEN severity = 2 THEN 25 WHEN severity = 1 THEN 15 ELSE 5 END)) as calc_score, " +
                "    ARRAY_AGG(DISTINCT 'attack'::text), " +
                "    NOW() " +
                "FROM events " +
                "GROUP BY src_ip " +
                "ON CONFLICT (ip) DO UPDATE " +
                "SET " +
                "    local_score = EXCLUDED.local_score, " +
                "    score = LEAST(EXCLUDED.local_score, ip_reputation.external_score), " +
                "    updated_at = NOW()"
            );
        } catch (Exception e) {
            System.err.println("[NotificationService] Dynamic reputation calculations failed: " + e.getMessage());
        }

        // Auto-block low reputation IPs (score <= 20)
        try {
            List<String> ipsToBlock = jdbc.queryForList(
                "SELECT host(ip) as ip FROM ip_reputation r " +
                "WHERE score <= 20 " +
                "  AND NOT EXISTS ( " +
                "      SELECT 1 FROM blocklist b " +
                "      WHERE b.ip_cidr = r.ip " +
                "  )",
                String.class
            );

            if (!ipsToBlock.isEmpty()) {
                jdbc.update(
                    "INSERT INTO blocklist (ip_cidr, list_type, reason, source) " +
                    "SELECT ip, 'block', 'Auto-blocked: Low reputation (Score: ' || score || ')', 'system' " +
                    "FROM ip_reputation r " +
                    "WHERE score <= 20 " +
                    "  AND NOT EXISTS ( " +
                    "      SELECT 1 FROM blocklist b " +
                    "      WHERE b.ip_cidr = r.ip " +
                    "  )"
                );

                for (String ip : ipsToBlock) {
                    System.out.println("[NotificationService] Auto-blocking IP " + ip + " and pushing to agents");
                    pushBlocklistUpdateToAgents(ip, 3); // 3 = MSG_TYPE_BLOCK_IP
                }
            }
        } catch (Exception e) {
            System.err.println("[NotificationService] Auto-block execution failed: " + e.getMessage());
        }
        } // End circuit-breaker for reputation/auto-block

        // Initialize lastProcessedId on first execution
        if (lastProcessedId == -1) {
            String lastIdStr = getConfigString("last_notified_event_id", "0");
            lastProcessedId = Long.parseLong(lastIdStr);

            Long maxId = jdbc.queryForObject("SELECT COALESCE(MAX(id), 0) FROM events", Long.class);
            long dbMaxId = maxId != null ? maxId : 0;
            if (lastProcessedId > dbMaxId) {
                lastProcessedId = dbMaxId;
                saveConfig("last_notified_event_id", String.valueOf(lastProcessedId), "system", "Last processed event ID");
            }

            // If it is 0, let's grab the current max ID in the events table so we don't spam old events
            if (lastProcessedId == 0) {
                lastProcessedId = dbMaxId;
                saveConfig("last_notified_event_id", String.valueOf(lastProcessedId), "system", "Last processed event ID");
            }
            System.out.println("[NotificationService] Initialized. Last processed event ID: " + lastProcessedId);
        }

        try {
            List<Map<String, Object>> newEvents = jdbc.queryForList(
                "SELECT id, src_ip::text as src_ip, dest_ip::text as dest_ip, src_port, dest_port, threat_type, severity, payload_preview, details, timestamp FROM events WHERE id > ? ORDER BY id ASC LIMIT 10",
                lastProcessedId
            );

            if (newEvents.isEmpty()) {
                return;
            }

            boolean enabled = Boolean.parseBoolean(getConfigString("smtp_enabled", "false"));
            JavaMailSenderImpl mailSender = null;
            String from = null;
            String to = null;
            if (enabled) {
                mailSender = getMailSender();
                from = getConfigString("smtp_from", "alerts@nullsploit.local");
                to = getConfigString("smtp_to", "admin@nullsploit.local");
            }

            for (Map<String, Object> event : newEvents) {
                long eventId = ((Number) event.get("id")).longValue();
                int severity = ((Number) event.get("severity")).intValue();

                // Broadcast to SSE clients
                eventPublisher.publishEvent(new com.nullsploit.event.NewEventDetectedEvent(this, event));

                // Notify for WARNING (1) and CRITICAL (2) events if SMTP is enabled
                if (enabled && severity >= 1) {
                    sendEventEmail(mailSender, from, to, event);
                }

                lastProcessedId = eventId;
            }

            saveConfig("last_notified_event_id", String.valueOf(lastProcessedId), "system", "Last processed event ID");

        } catch (Exception e) {
            System.err.println("[NotificationService] Error running check: " + e.getMessage());
        }
    }

    private void sendEventEmail(JavaMailSenderImpl mailSender, String from, String to, Map<String, Object> event) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(from);
            helper.setTo(to);

            String severityStr = event.get("severity").toString().equals("2") ? "CRITICAL" : "WARNING";
            helper.setSubject("[Nullsploit ALERT] " + severityStr + " Threat Detected from " + event.get("src_ip"));

            String htmlContent = String.format(
                "<html><body style='font-family: monospace; background-color: #0d1117; color: #c9d1d9; padding: 20px;'>" +
                "<div style='border: 1px solid #30363d; padding: 15px; border-radius: 6px; background-color: #161b22;'>" +
                "<h2 style='color: #ff7b72; border-bottom: 1px solid #30363d; padding-bottom: 8px;'>[Nullsploit WAF Alert]</h2>" +
                "<p><strong>Severity:</strong> <span style='color: #ff7b72;'>%s</span></p>" +
                "<p><strong>Threat Type:</strong> %s</p>" +
                "<p><strong>Source IP:</strong> %s (Port %s)</p>" +
                "<p><strong>Destination:</strong> %s (Port %s)</p>" +
                "<p><strong>Payload Preview:</strong> <code style='background-color: #21262d; padding: 2px 4px; border-radius: 4px;'>%s</code></p>" +
                "<p><strong>Details:</strong> %s</p>" +
                "<p><strong>Timestamp:</strong> %s</p>" +
                "</div></body></html>",
                severityStr,
                event.get("threat_type"),
                event.get("src_ip"), event.get("src_port"),
                event.get("dest_ip"), event.get("dest_port"),
                event.get("payload_preview"),
                event.get("details"),
                event.get("timestamp")
            );

            helper.setText(htmlContent, true);
            mailSender.send(message);
            System.out.println("[NotificationService] Sent alert email for event ID: " + event.get("id"));
        } catch (Exception e) {
            System.err.println("[NotificationService] Failed to send email for event " + event.get("id") + ": " + e.getMessage());
        }
    }

    public void sendTestEmail() throws Exception {
        JavaMailSenderImpl mailSender = getMailSender();
        String from = getConfigString("smtp_from", "alerts@nullsploit.local");
        String to = getConfigString("smtp_to", "admin@nullsploit.local");

        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

        helper.setFrom(from);
        helper.setTo(to);
        helper.setSubject("[Nullsploit] SMTP Configuration Test");

        String htmlContent = "<html><body style='font-family: monospace; background-color: #0d1117; color: #c9d1d9; padding: 20px;'>" +
                "<div style='border: 1px solid #34d399; padding: 15px; border-radius: 6px; background-color: #161b22;'>" +
                "<h2 style='color: #34d399;'>Connection Test Successful</h2>" +
                "<p>This is a test email from your Nullsploit Enterprise Security Console. Your SMTP settings are correctly configured!</p>" +
                "</div></body></html>";

        helper.setText(htmlContent, true);
        mailSender.send(message);
        System.out.println("[NotificationService] Sent test email successfully to " + to);
    }

    public void pushBlocklistUpdateToAgents(String ipCidr, int commandType) {
        try {
            String ip = ipCidr;
            if (ip.contains("/")) {
                ip = ip.substring(0, ip.indexOf("/"));
            }
            
            String[] parts = ip.split("\\.");
            long ipVal = 0;
            for (int i = 0; i < 4; i++) {
                ipVal |= (Long.parseLong(parts[i]) << (i * 8));
            }

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
                    out.write(commandType); // 1 byte MSG_TYPE_BLOCK_IP (3) or MSG_TYPE_UNBLOCK_IP (4)
                    
                    byte[] ipBytes = new byte[4];
                    ipBytes[0] = (byte) (ipVal & 0xFF);
                    ipBytes[1] = (byte) ((ipVal >> 8) & 0xFF);
                    ipBytes[2] = (byte) ((ipVal >> 16) & 0xFF);
                    ipBytes[3] = (byte) ((ipVal >> 24) & 0xFF);
                    out.write(ipBytes);   // 4 bytes IP address
                    
                    out.flush();
                } catch (Exception e) {
                    System.err.println("Failed to push blocklist update to agent " + uuid + ": " + e.getMessage());
                }
            }
        } catch (Exception e) {
            System.err.println("Failed to parse IP for blocklist update: " + ipCidr);
        }
    }
}
