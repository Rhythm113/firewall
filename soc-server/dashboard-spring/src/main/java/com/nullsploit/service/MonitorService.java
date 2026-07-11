package com.nullsploit.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.lang.management.ManagementFactory;
import java.lang.management.OperatingSystemMXBean;
import java.lang.management.RuntimeMXBean;
import java.lang.management.ThreadMXBean;
import java.util.*;

@Service
public class MonitorService {

    @Autowired
    private JdbcTemplate jdbc;

    private final ObjectMapper mapper = new ObjectMapper();

    private final OperatingSystemMXBean osBean = ManagementFactory.getOperatingSystemMXBean();
    private final RuntimeMXBean runtimeBean = ManagementFactory.getRuntimeMXBean();
    private final ThreadMXBean threadBean = ManagementFactory.getThreadMXBean();
    private final Runtime jvm = Runtime.getRuntime();

    // Rolling window for spike detection
    private final int SPIKE_WINDOW_SIZE = 10;
    private final LinkedList<Long> eventRateHistory = new LinkedList<>();
    private long lastSpikeCheckTimestamp = 0;
    private long lastSpikeCheckEventCount = 0;
    private double lastEventRate = 0;

    public Map<String, Object> getSystemHealth() {
        Map<String, Object> health = new LinkedHashMap<>();

        // --- JVM Uptime ---
        long uptimeMs = runtimeBean.getUptime();
        health.put("uptime_seconds", uptimeMs / 1000);

        // --- CPU ---
        double processCpuLoad = -1.0;
        if (osBean instanceof com.sun.management.OperatingSystemMXBean sunOsBean) {
            processCpuLoad = sunOsBean.getProcessCpuLoad() * 100.0;
        }
        // Fallback: system load average
        double systemLoadAverage = osBean.getSystemLoadAverage();
        int availableProcessors = osBean.getAvailableProcessors();

        Map<String, Object> cpu = new LinkedHashMap<>();
        cpu.put("process_cpu_percent", processCpuLoad >= 0 ? Math.round(processCpuLoad * 10.0) / 10.0 : null);
        cpu.put("system_load_average", systemLoadAverage >= 0 ? Math.round(systemLoadAverage * 100.0) / 100.0 : null);
        cpu.put("available_processors", availableProcessors);
        health.put("cpu", cpu);

        // --- Memory (JVM Heap) ---
        long maxMemory = jvm.maxMemory();
        long totalMemory = jvm.totalMemory();
        long freeMemory = jvm.freeMemory();
        long usedMemory = totalMemory - freeMemory;

        Map<String, Object> memory = new LinkedHashMap<>();
        memory.put("max_bytes", maxMemory);
        memory.put("used_bytes", usedMemory);
        memory.put("free_bytes", freeMemory);
        memory.put("used_percent", maxMemory > 0 ? Math.round((usedMemory * 1000.0 / maxMemory)) / 10.0 : 0);
        health.put("memory", memory);

        // --- Threads ---
        int threadCount = threadBean.getThreadCount();
        int daemonCount = threadBean.getDaemonThreadCount();
        int peakCount = threadBean.getPeakThreadCount();

        Map<String, Object> threads = new LinkedHashMap<>();
        threads.put("current", threadCount);
        threads.put("daemon", daemonCount);
        threads.put("peak", peakCount);
        health.put("threads", threads);

        // --- Event Throughput ---
        Map<String, Object> throughput = getEventThroughput();
        health.put("event_throughput", throughput);

        // --- Spike Detection ---
        Map<String, Object> spike = detectSpike(throughput);
        health.put("spike_alert", spike);

        // --- Node Health Stats ---
        List<Map<String, Object>> nodes = new ArrayList<>();
        try {
            List<Map<String, Object>> rows = jdbc.queryForList(
                "SELECT uuid::text as id, hostname, ip::text as ip, " +
                "CASE WHEN last_seen >= CURRENT_TIMESTAMP - INTERVAL '30 seconds' THEN 'active' ELSE 'offline' END as status, " +
                "config FROM agents"
            );
            for (Map<String, Object> row : rows) {
                Map<String, Object> node = new LinkedHashMap<>();
                node.put("id", row.get("id"));
                node.put("hostname", row.get("hostname"));
                node.put("ip", row.get("ip"));
                node.put("status", row.get("status"));
                
                double cpuVal = -1;
                double memVal = -1;
                long uptimeVal = -1;

                Object configObj = row.get("config");
                if (configObj != null) {
                    String configJson = configObj.toString();
                    try {
                        Map<String, Object> configMap = mapper.readValue(configJson, Map.class);
                        if (configMap.containsKey("cpu")) {
                            cpuVal = ((Number) configMap.get("cpu")).doubleValue();
                        }
                        if (configMap.containsKey("mem")) {
                            memVal = ((Number) configMap.get("mem")).doubleValue();
                        }
                        if (configMap.containsKey("uptime")) {
                            uptimeVal = ((Number) configMap.get("uptime")).longValue();
                        }
                    } catch (Exception ignored) {}
                }
                
                node.put("cpu", cpuVal >= 0 ? cpuVal : null);
                node.put("mem", memVal >= 0 ? memVal : null);
                node.put("uptime", uptimeVal >= 0 ? uptimeVal : null);
                nodes.add(node);
            }
        } catch (Exception e) {
            System.err.println("[MonitorService] Failed to query nodes health: " + e.getMessage());
        }
        health.put("nodes", nodes);

        return health;
    }

    private Map<String, Object> getEventThroughput() {
        Map<String, Object> result = new LinkedHashMap<>();

        try {
            // Events in last 60 seconds
            Long countLastMin = jdbc.queryForObject(
                "SELECT COUNT(*) FROM events WHERE timestamp >= NOW() - INTERVAL '60 seconds'",
                Long.class
            );
            result.put("last_60s", countLastMin != null ? countLastMin : 0);

            // Events in last 5 minutes
            Long countLast5min = jdbc.queryForObject(
                "SELECT COUNT(*) FROM events WHERE timestamp >= NOW() - INTERVAL '5 minutes'",
                Long.class
            );
            result.put("last_5min", countLast5min != null ? countLast5min : 0);

            // Events in last 1 hour
            Long countLastHour = jdbc.queryForObject(
                "SELECT COUNT(*) FROM events WHERE timestamp >= NOW() - INTERVAL '1 hour'",
                Long.class
            );
            result.put("last_1h", countLastHour != null ? countLastHour : 0);

            // Per-minute breakdown for last 10 minutes (sparkline data)
            List<Map<String, Object>> timeline = jdbc.queryForList(
                "SELECT to_char(timestamp, 'HH24:MI') as minute, COUNT(*) as count " +
                "FROM events WHERE timestamp >= NOW() - INTERVAL '10 minutes' " +
                "GROUP BY minute ORDER BY MIN(timestamp) ASC"
            );
            result.put("timeline", timeline);

            // Current event rate (events/min over last minute)
            double ratePerMin = (countLastMin != null ? countLastMin : 0);
            // Convert to per-second rate for the last minute
            result.put("rate_per_sec", Math.round(ratePerMin / 60.0 * 100.0) / 100.0);

        } catch (Exception e) {
            result.put("error", e.getMessage());
            result.put("last_60s", 0);
            result.put("last_5min", 0);
            result.put("last_1h", 0);
            result.put("rate_per_sec", 0.0);
        }

        return result;
    }

    private Map<String, Object> detectSpike(Map<String, Object> throughput) {
        Map<String, Object> alert = new LinkedHashMap<>();
        alert.put("active", false);
        alert.put("message", "Normal");

        try {
            long currentCount = ((Number) throughput.getOrDefault("last_60s", 0)).longValue();

            // Update rolling history
            eventRateHistory.addLast(currentCount);
            if (eventRateHistory.size() > SPIKE_WINDOW_SIZE) {
                eventRateHistory.removeFirst();
            }

            // Need at least 3 data points for comparison
            if (eventRateHistory.size() < 3) {
                return alert;
            }

            // Calculate average of history (excluding current)
            double sum = 0;
            for (int i = 0; i < eventRateHistory.size() - 1; i++) {
                sum += eventRateHistory.get(i);
            }
            double avg = sum / (eventRateHistory.size() - 1);
            double currentRate = currentCount;

            // Spike: current rate is > 2x the rolling average AND > 10 events/min
            if (avg > 0 && currentRate > avg * 2 && currentRate > 10) {
                alert.put("active", true);
                alert.put("severity", currentRate > avg * 3 ? "CRITICAL" : "WARNING");
                alert.put("message", String.format(
                    "Event rate spike: %.0f events/min (%.0f%% above %.0f/min baseline)",
                    currentRate, ((currentRate - avg) / avg) * 100.0, avg
                ));
                alert.put("current_rate", currentRate);
                alert.put("baseline_avg", Math.round(avg * 100.0) / 100.0);
            }

        } catch (Exception e) {
            alert.put("error", e.getMessage());
        }

        return alert;
    }
}
