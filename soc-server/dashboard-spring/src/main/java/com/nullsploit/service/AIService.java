package com.nullsploit.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
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

@Service
public class AIService {

    @Autowired
    private JdbcTemplate jdbc;

    private final ObjectMapper mapper = new ObjectMapper();
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    private String getConfigString(String key, String defaultVal) {
        try {
            List<Map<String, Object>> rows = jdbc.queryForList("SELECT value::text FROM config WHERE key = ?", key);
            if (rows.isEmpty()) {
                return defaultVal;
            }
            String valueJson = (String) rows.get(0).get("value");
            
            try {
                Map<String, Object> map = mapper.readValue(valueJson, Map.class);
                Object v = map.get("value");
                return v != null ? v.toString() : defaultVal;
            } catch (Exception parseEx) {
                return valueJson != null ? valueJson : defaultVal;
            }
        } catch (Exception e) {
            return defaultVal;
        }
    }

    @Scheduled(fixedDelay = 10000)
    public void runAIAnalysis() {
        // Fetch the OpenCode API Key
        String apiKey = getConfigString("opencode_api_key", "").trim();
        
        if (apiKey.isEmpty()) {
            return; // AI analysis is not enabled yet
        }

        String model = getConfigString("opencode_model", "deepseek-v4-flash-free").trim();
        // Updated to the OpenCode Go API default endpoint
        String apiUrl = getConfigString("opencode_url", "https://opencode.ai/zen/go/v1/chat/completions").trim();

        // Enforce HTTPS for secure transmission of payloads and API keys
        if (!apiUrl.toLowerCase().startsWith("https://")) {
            System.err.println("[AIService] SECURITY BLOCK: API URL must use HTTPS to prevent credential leakage.");
            return;
        }

        try {
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
        } catch (Exception e) {
            System.err.println("[AIService] Error fetching unanalyzed events: " + e.getMessage());
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

            String jsonReq = mapper.writeValueAsString(reqBody);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(apiUrl))
                    .header("Content-Type", "application/json")
                    // Applied OpenCode Go API Auth Header format: Bearer <Token>
                    .header("Authorization", "Bearer " + apiKey) 
                    .POST(HttpRequest.BodyPublishers.ofString(jsonReq))
                    .timeout(Duration.ofSeconds(20))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

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

                    jdbc.update(
                            "INSERT INTO ai_analysis_dataset (event_id, threat_detected, confidence, explanation, model_used) " +
                            "VALUES (?, ?, ?, ?, ?) ON CONFLICT (event_id) DO NOTHING",
                            eventId, threatDetected, confidence, explanation, model
                    );
                    System.out.println("[AIService] Successfully analyzed event " + eventId);
                }
            } else {
                System.err.println("[AIService] API error: HTTP " + response.statusCode() + " -> " + response.body());
            }

        } catch (Exception e) {
            System.err.println("[AIService] Failed to analyze event " + eventId + ": " + e.getMessage());
        }
    }
}