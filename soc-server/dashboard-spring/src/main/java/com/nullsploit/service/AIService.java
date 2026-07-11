package com.nullsploit.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import jakarta.annotation.PostConstruct;

@Service
public class AIService {

    @Autowired
    private JdbcTemplate jdbc;

    private final ObjectMapper mapper = new ObjectMapper();
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    @PostConstruct
    public void init() {
        try {
            jdbc.update("UPDATE config SET value = '{\"value\":\"https://opencode.ai/zen/v1/chat/completions\"}' WHERE key = 'opencode_url'");
            jdbc.update("UPDATE config SET value = '{\"value\":\"opencode/deepseek-v4-flash-free\"}' WHERE key = 'opencode_model'");
        } catch (Exception e) {
            System.err.println("[AIService] Failed to run database config migration: " + e.getMessage());
        }
    }

    private String getConfigString(String key, String defaultVal) {
        try {
            List<Map<String, Object>> rows = jdbc.queryForList("SELECT value::text FROM config WHERE key = ?", key);
            if (rows.isEmpty()) {
                return defaultVal;
            }
            String valueJson = (String) rows.get(0).get("value");
            if (valueJson == null) return defaultVal;

            try {
                Map<String, Object> map = mapper.readValue(valueJson.trim(), Map.class);
                Object v = map.get("value");
                return v != null ? v.toString().trim() : defaultVal;
            } catch (Exception parseEx) {
                System.err.println("[AIService] Config value for '" + key + "' is not valid JSON, returning raw value: " + parseEx.getMessage());
                return valueJson.trim();
            }
        } catch (Exception e) {
            System.err.println("[AIService] DB error fetching config '" + key + "': " + e.getMessage());
            return defaultVal;
        }
    }

    private void setAIConfig(String key, String value) {
        try {
            String valJson = mapper.writeValueAsString(Map.of("value", value));
            jdbc.update(
                "INSERT INTO config (key, value, category, description, updated_at) VALUES (?, ?::jsonb, ?, ?, NOW()) " +
                "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()",
                key, valJson, "ai", "AI analysis " + key
            );
        } catch (Exception e) {
            System.err.println("[AIService] Failed to save config key '" + key + "': " + e.getMessage());
        }
    }

    @Scheduled(fixedDelay = 10000)
    public void runAIAnalysis() {
        // Fetch the OpenCode API Key
        String apiKey = getConfigString("opencode_api_key", "").trim();
        
        if (apiKey.isEmpty()) {
            setAIConfig("ai_status", "idle (no API key)");
            return; // AI analysis is not enabled yet
        }

        String model = getConfigString("opencode_model", "opencode/deepseek-v4-flash-free").trim();
        if (model.contains("/")) {
            model = model.substring(model.indexOf("/") + 1);
        }
        // Default to OpenCode Zen API completions endpoint
        String apiUrl = getConfigString("opencode_url", "https://opencode.ai/zen/v1/chat/completions").trim();

        // Enforce HTTPS for secure transmission of payloads and API keys
        if (!apiUrl.toLowerCase().startsWith("https://")) {
            setAIConfig("ai_status", "stopped (HTTPS required)");
            System.err.println("[AIService] SECURITY BLOCK: API URL must use HTTPS to prevent credential leakage.");
            return;
        }

        try {
            // Count pending events for status display
            Long pendingCount = jdbc.queryForObject(
                "SELECT COUNT(*) FROM events e LEFT JOIN ai_analysis_dataset a ON e.id = a.event_id WHERE a.event_id IS NULL",
                Long.class
            );
            setAIConfig("ai_pending_count", String.valueOf(pendingCount != null ? pendingCount : 0));
            setAIConfig("ai_status", "running (" + (pendingCount != null ? pendingCount : 0) + " pending)");

            // Priority query: non-slowloris events first (up to 5 analyzed individually)
            List<Map<String, Object>> unanalyzedEvents = jdbc.queryForList(
                    "SELECT e.id, e.payload_preview, e.details, e.threat_type, e.severity, host(e.src_ip) as src_ip " +
                    "FROM events e " +
                    "LEFT JOIN ai_analysis_dataset a ON e.id = a.event_id " +
                    "WHERE a.event_id IS NULL " +
                    "ORDER BY e.id ASC LIMIT 5"
            );

            for (Map<String, Object> event : unanalyzedEvents) {
                analyzeEvent(event, apiKey, model, apiUrl);
            }

            // Batch slowloris events: collect up to 100 and send as a single AI request
            analyzeSlowlorisBatch(apiKey, model, apiUrl);

            // Update final status after analysis completes
            Long remainingPending = jdbc.queryForObject(
                "SELECT COUNT(*) FROM events e LEFT JOIN ai_analysis_dataset a ON e.id = a.event_id WHERE a.event_id IS NULL",
                Long.class
            );
            setAIConfig("ai_pending_count", String.valueOf(remainingPending != null ? remainingPending : 0));
            setAIConfig("ai_analyzed_count", String.valueOf(
                jdbc.queryForObject("SELECT COUNT(*) FROM ai_analysis_dataset", Long.class)
            ));
            setAIConfig("ai_last_run", new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new java.util.Date()));
            setAIConfig("ai_status", "idle");

        } catch (Exception e) {
            setAIConfig("ai_status", "error: " + e.getMessage());
            System.err.println("[AIService] Error during AI analysis: " + e.getMessage());
        }
    }

    /**
     * Batch-analyze slowloris events (threat_type=4). Slowloris attacks generate
     * thousands of near-identical events; sending each to the AI would exhaust
     * the queue and waste API credits. Instead, we collect up to 100 at once,
     * send a single aggregated prompt, and apply the same result to all events
     * in the batch.
     */
    private void analyzeSlowlorisBatch(String apiKey, String model, String apiUrl) {
        try {
            List<Map<String, Object>> slowlorisEvents = jdbc.queryForList(
                    "SELECT e.id, e.payload_preview, e.details, e.threat_type, e.severity, host(e.src_ip) as src_ip, " +
                    "EXTRACT(EPOCH FROM e.timestamp)::bigint as ts " +
                    "FROM events e " +
                    "LEFT JOIN ai_analysis_dataset a ON e.id = a.event_id " +
                    "WHERE a.event_id IS NULL AND e.threat_type = 4 " +
                    "ORDER BY e.id ASC LIMIT 100"
            );

            if (slowlorisEvents.isEmpty()) {
                return;
            }

            long firstId = ((Number) slowlorisEvents.get(0).get("id")).longValue();
            long lastId = ((Number) slowlorisEvents.get(slowlorisEvents.size() - 1).get("id")).longValue();

            // Aggregate data for the AI prompt
            java.util.Set<String> uniqueIps = new java.util.LinkedHashSet<>();
            StringBuilder samplePayloads = new StringBuilder();
            int sampleCount = 0;
            for (Map<String, Object> evt : slowlorisEvents) {
                uniqueIps.add((String) evt.get("src_ip"));
                if (sampleCount < 3) {
                    samplePayloads.append("  - ").append(evt.get("payload_preview")).append("\n");
                    sampleCount++;
                }
            }

            String systemPrompt = "You are a WAF Security Expert. Analyze the following batch of Slowloris (TCP Connection Slow) attack events captured by our firewall. " +
                    "Based on the aggregate data, determine if this is a genuine slowloris denial-of-service attack. " +
                    "You must respond ONLY with a JSON object containing the fields: 'threat_detected' (boolean), 'confidence' (integer from 0 to 100), and 'explanation' (string).";

            String userPrompt = String.format(
                    "Slowloris Attack Batch Summary:\n" +
                    "- Total Events in Batch: %d\n" +
                    "- Event ID Range: %d to %d\n" +
                    "- Unique Source IPs: %s\n" +
                    "- Sample Payloads:\n%s\n" +
                    "Assess whether this is a genuine slowloris attack and explain your reasoning.",
                    slowlorisEvents.size(), firstId, lastId,
                    String.join(", ", uniqueIps),
                    samplePayloads.toString()
            );

            // Send a single AI request for the batch
            Map<String, Object> reqBody = new HashMap<>();
            reqBody.put("model", model);
            reqBody.put("messages", List.of(
                    Map.of("role", "system", "content", systemPrompt),
                    Map.of("role", "user", "content", userPrompt)
            ));

            Map<String, Object> extraBody = new HashMap<>();
            extraBody.put("thinking", Map.of("type", "disabled"));
            reqBody.put("extra_body", extraBody);

            String jsonReq = mapper.writeValueAsString(reqBody);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(apiUrl))
                    .header("Content-Type", "application/json")
                    .header("Authorization", "Bearer " + apiKey)
                    .POST(HttpRequest.BodyPublishers.ofString(jsonReq))
                    .timeout(Duration.ofSeconds(30))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 401) {
                System.err.println("[AIService] Slowloris batch: Authorization Bearer rejected (401), retrying with X-API-Key...");
                request = HttpRequest.newBuilder()
                        .uri(URI.create(apiUrl))
                        .header("Content-Type", "application/json")
                        .header("X-API-Key", apiKey)
                        .POST(HttpRequest.BodyPublishers.ofString(jsonReq))
                        .timeout(Duration.ofSeconds(30))
                        .build();
                response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            }

            boolean success = false;
            boolean threatDetected = false;
            int confidence = 50;
            String explanation = "Batch analysis failed.";

            if (response.statusCode() == 200 || response.statusCode() == 201) {
                Map<String, Object> resMap = mapper.readValue(response.body(), Map.class);
                List<Map<String, Object>> choices = (List<Map<String, Object>>) resMap.get("choices");

                if (choices != null && !choices.isEmpty()) {
                    Map<String, Object> message = (Map<String, Object>) choices.get(0).get("message");
                    String content = (String) message.get("content");

                    if (content.startsWith("```")) {
                        content = content.replaceAll("```json|```", "").trim();
                    }

                    Map<String, Object> aiResult = mapper.readValue(content, Map.class);
                    threatDetected = Boolean.parseBoolean(String.valueOf(aiResult.get("threat_detected")));
                    confidence = ((Number) aiResult.getOrDefault("confidence", 50)).intValue();
                    explanation = (String) aiResult.getOrDefault("explanation", "No explanation provided.");
                    success = true;
                }
            } else {
                System.err.println("[AIService] Slowloris batch API error: HTTP " + response.statusCode() + " -> " + response.body());
            }

            // Apply the same AI result to ALL events in the batch
            int appliedCount = 0;
            for (Map<String, Object> evt : slowlorisEvents) {
                long eventId = ((Number) evt.get("id")).longValue();
                try {
                    jdbc.update(
                            "INSERT INTO ai_analysis_dataset (event_id, threat_detected, confidence, explanation, model_used) " +
                            "VALUES (?, ?, ?, ?, ?) ON CONFLICT (event_id) DO NOTHING",
                            eventId, threatDetected, confidence, explanation,
                            success ? model + " (batch)" : "batch_failed"
                    );
                    appliedCount++;
                } catch (DataIntegrityViolationException e) {
                    System.out.println("[AIService] Event " + eventId + " was deleted during batch analysis, skipping insert.");
                } catch (Exception e) {
                    System.err.println("[AIService] Slowloris batch: failed to insert event " + eventId + ": " + e.getMessage());
                }
            }

            System.out.println("[AIService] Slowloris batch: " + appliedCount + "/" + slowlorisEvents.size() +
                    " events analyzed in one shot (detected=" + threatDetected + ", confidence=" + confidence + ")");

        } catch (Exception e) {
            System.err.println("[AIService] Slowloris batch analysis failed: " + e.getMessage());
        }
    }

    private void analyzeEvent(Map<String, Object> event, String apiKey, String model, String apiUrl) {
        long eventId = ((Number) event.get("id")).longValue();
        String payload = (String) event.get("payload_preview");
        String details = (String) event.get("details");
        int threatType = ((Number) event.get("threat_type")).intValue();
        int severity = ((Number) event.get("severity")).intValue();
        String srcIp = (String) event.get("src_ip");

        String systemPrompt = "You are a WAF Security Expert. Analyze the following network packet captured by our firewall and determine if it represents a real threat. " +
                "You must respond ONLY with a JSON object containing the fields: 'threat_detected' (boolean), 'confidence' (integer from 0 to 100), and 'explanation' (string).";

        String userPrompt = String.format(
                "Event ID: %d\nSource IP: %s\nThreat Type: %d\nSeverity: %d\nPayload Preview: %s\nDetails: %s\n",
                eventId, srcIp, threatType, severity, payload, details
        );

        try {
            // Build the OpenAI-compatible request body
            Map<String, Object> reqBody = new HashMap<>();
            reqBody.put("model", model);

            Map<String, String> systemMsg = new HashMap<>();
            systemMsg.put("role", "system");
            systemMsg.put("content", systemPrompt);

            Map<String, String> userMsg = new HashMap<>();
            userMsg.put("role", "user");
            userMsg.put("content", userPrompt);

            reqBody.put("messages", List.of(systemMsg, userMsg));

            // Z.ai specific thinking configuration (default to disabled)
            Map<String, Object> extraBody = new HashMap<>();
            Map<String, Object> thinking = new HashMap<>();
            thinking.put("type", "disabled");
            extraBody.put("thinking", thinking);
            reqBody.put("extra_body", extraBody);

            String jsonReq = mapper.writeValueAsString(reqBody);

            // Primary auth: Authorization: Bearer <key> (standard for OpenCode Go)
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(apiUrl))
                    .header("Content-Type", "application/json")
                    .header("Authorization", "Bearer " + apiKey)
                    .POST(HttpRequest.BodyPublishers.ofString(jsonReq))
                    .timeout(Duration.ofSeconds(20))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            // Fallback: If Authorization Bearer got a 401, retry with X-API-Key (OpenCode.ai style)
            if (response.statusCode() == 401) {
                System.err.println("[AIService] Authorization: Bearer rejected (401), retrying with X-API-Key...");
                request = HttpRequest.newBuilder()
                        .uri(URI.create(apiUrl))
                        .header("Content-Type", "application/json")
                        .header("X-API-Key", apiKey)
                        .POST(HttpRequest.BodyPublishers.ofString(jsonReq))
                        .timeout(Duration.ofSeconds(20))
                        .build();
                response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            }

            if (response.statusCode() == 200 || response.statusCode() == 201) {
                Map<String, Object> resMap = mapper.readValue(response.body(), Map.class);
                List<Map<String, Object>> choices = (List<Map<String, Object>>) resMap.get("choices");
                
                if (choices != null && !choices.isEmpty()) {
                    Map<String, Object> message = (Map<String, Object>) choices.get(0).get("message");
                    String content = (String) message.get("content");
                    
                    if (content.startsWith("```")) {
                        content = content.replaceAll("```json|```", "").trim();
                    }

                    Map<String, Object> aiResult = mapper.readValue(content, Map.class);
                    boolean threatDetected = Boolean.parseBoolean(String.valueOf(aiResult.get("threat_detected")));
                    int confidence = ((Number) aiResult.getOrDefault("confidence", 50)).intValue();
                    String explanation = (String) aiResult.getOrDefault("explanation", "No explanation provided.");

                    try {
                        jdbc.update(
                                "INSERT INTO ai_analysis_dataset (event_id, threat_detected, confidence, explanation, model_used) " +
                                "VALUES (?, ?, ?, ?, ?) ON CONFLICT (event_id) DO NOTHING",
                                eventId, threatDetected, confidence, explanation, model
                        );
                        System.out.println("[AIService] Successfully analyzed event " + eventId);
                    } catch (DataIntegrityViolationException e) {
                        System.out.println("[AIService] Event " + eventId + " was deleted during analysis, skipping insert.");
                    }
                }
            } else {
                System.err.println("[AIService] API error: HTTP " + response.statusCode() + " -> " + response.body());
            }

        } catch (Exception e) {
            System.err.println("[AIService] Failed to analyze event " + eventId + ": " + e.getMessage());
        }
    }
}