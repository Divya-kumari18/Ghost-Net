package com.ghostnet.controller;

import java.time.ZonedDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ghostnet.capture.PacketCaptureEngine;
import com.ghostnet.service.IncidentService;
import com.ghostnet.service.MalwareDetectionService;
import com.ghostnet.service.NetworkAnalysisService;
import com.ghostnet.service.WindowsEventService;
import com.ghostnet.websocket.AlertBroadcaster;
import com.ghostnet.windows.WindowsEventLogReader;

@RestController
@RequestMapping("/dashboard")
public class DashboardController {

    @Value("${spring.application.name:ghostnet}")
    private String appName;

    @Value("${ghostnet.app.version:1.0.0}")
    private String appVersion;

    private final NetworkAnalysisService networkService;
    private final WindowsEventService eventService;
    private final IncidentService incidentService;
    private final MalwareDetectionService malwareService;
    private final PacketCaptureEngine captureEngine;
    private final WindowsEventLogReader eventReader;
    private final AlertBroadcaster broadcaster;
    private final org.springframework.jdbc.core.JdbcTemplate jdbc;

    public DashboardController(NetworkAnalysisService networkService,
                               WindowsEventService eventService,
                               IncidentService incidentService,
                               MalwareDetectionService malwareService,
                               PacketCaptureEngine captureEngine,
                               WindowsEventLogReader eventReader,
                               AlertBroadcaster broadcaster,
                               org.springframework.jdbc.core.JdbcTemplate jdbc) {
        this.networkService = networkService;
        this.eventService = eventService;
        this.incidentService = incidentService;
        this.malwareService = malwareService;
        this.captureEngine = captureEngine;
        this.eventReader = eventReader;
        this.broadcaster = broadcaster;
        this.jdbc = jdbc;
    }

    @GetMapping("/metrics")
    public Map<String,Object> metrics(@org.springframework.web.bind.annotation.RequestParam(defaultValue="24h") String range) {
        long hours=switch(range) {case "1h"->1;case "24h"->24;case "30d"->720;default->throw new IllegalArgumentException("Invalid dashboard range");};
        var since=java.sql.Timestamp.from(java.time.Instant.now().minusSeconds(hours*3600));
        return Map.of("activeAlerts",jdbc.queryForObject("select count(*) from network_alerts where timestamp>=? and severity in ('CRITICAL','HIGH') and status not in ('resolved','false_positive')",Long.class,since),
            "openIncidents",jdbc.queryForObject("select count(*) from incidents where created_at>=? and status in ('open','investigating','contained')",Long.class,since),
            "securityEvents",jdbc.queryForObject("select count(*) from windows_event_logs where event_time>=? and is_security_relevant=true",Long.class,since),
            "packets",jdbc.queryForObject("select count(*) from network_traffic where timestamp>=?",Long.class,since));
    }

    /**
     * Returns a single aggregated stats object for the dashboard.
     */
    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getDashboardStats() {
        return ResponseEntity.ok(buildStats());
    }

    @GetMapping("/version")
    public ResponseEntity<Map<String, Object>> getVersionInfo() {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("name", appName);
        payload.put("version", appVersion);
        payload.put("javaVersion", System.getProperty("java.version"));
        payload.put("timestamp", ZonedDateTime.now().toString());
        return ResponseEntity.ok(payload);
    }

    /**
     * Scheduled broadcast of dashboard stats every 10 seconds via WebSocket.
     */
    @Scheduled(fixedDelay = 10_000)
    public void broadcastDashboardStats() {
        try {
            broadcaster.broadcastDashboardUpdate(buildStats());
        } catch (Exception e) {
            // Non-critical, don't let scheduler die
        }
    }

    private Map<String, Object> buildStats() {
        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("timestamp", ZonedDateTime.now().toString());

        // Capture engine status
        stats.put("capture", Map.of(
            "running",   captureEngine.isCapturing(),
            "workerRunning", captureEngine.isRunning(),
            "error", captureEngine.getLastError(),
            "interface", captureEngine.getActiveInterface() != null ? captureEngine.getActiveInterface() : "none",
            "packets",   captureEngine.getPacketCount(),
            "loops",     captureEngine.getCaptureLoopCount(),
            "restarts",  captureEngine.getRestartCount(),
            "lastLoopAt", String.valueOf(captureEngine.getLastLoopStartedAt()),
            "lastPacketAt", String.valueOf(captureEngine.getLastPacketAt())
        ));

        // Windows event reader status
        stats.put("eventReader", Map.of(
            "running", eventReader.isRunning()
        ));

        // Network & IDS stats
        try { stats.put("network", networkService.getAlertStats()); }
        catch (Exception e) { stats.put("network", Map.of("error", e.getMessage())); }

        // Windows event stats
        try { stats.put("events", eventService.getEventStats()); }
        catch (Exception e) { stats.put("events", Map.of("error", e.getMessage())); }

        // Incident stats
        try { stats.put("incidents", incidentService.getIncidentStats()); }
        catch (Exception e) { stats.put("incidents", Map.of("error", e.getMessage())); }

        // Malware stats
        try { stats.put("malware", malwareService.getMalwareStats()); }
        catch (Exception e) { stats.put("malware", Map.of("error", e.getMessage())); }
        try { stats.put("malwareFilesystem", malwareService.getFileSystemRuntimeStats()); }
        catch (Exception e) { stats.put("malwareFilesystem", Map.of("error", e.getMessage())); }

        return stats;
    }
}
