package com.ghostnet.integration.zap;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component
public class OwaspZapClient {

    @org.springframework.beans.factory.annotation.Autowired(required=false)
    private com.ghostnet.service.IntegrationSettingsService settings;
    private com.ghostnet.service.IntegrationSettingsService.Config config() { return settings==null?new com.ghostnet.service.IntegrationSettingsService.Config(enabled,baseUrl,apiKey):settings.get("zap"); }
    private final HttpClient httpClient;
    private final ObjectMapper mapper;
    private final String baseUrl;
    private final String apiKey;
    private final boolean enabled;
    private final Duration pollInterval;
    private final Duration timeout;

    public OwaspZapClient(
            @Value("${ghostnet.zap.base-url:http://localhost:8090}") String baseUrl,
            @Value("${ghostnet.zap.api-key:}") String apiKey,
            @Value("${ghostnet.zap.enabled:false}") boolean enabled,
            @Value("${ghostnet.zap.poll-interval-ms:2000}") long pollIntervalMs,
            @Value("${ghostnet.zap.scan-timeout-seconds:900}") long timeoutSeconds) {
        this.baseUrl = sanitizeBaseUrl(baseUrl);
        this.apiKey = apiKey;
        this.enabled = enabled;
        this.pollInterval = Duration.ofMillis(Math.max(500L, pollIntervalMs));
        this.timeout = Duration.ofSeconds(Math.max(60L, timeoutSeconds));
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();
        this.mapper = new ObjectMapper().findAndRegisterModules();
    }

    public boolean isEnabled() {
        return config().enabled();
    }

    public boolean isConfigured() { return config().apiKey() != null && !config().apiKey().isBlank(); }

    public String checkConnection() throws Exception {
        if (!isEnabled()) return "Disabled";
        if (!isConfigured()) return "API key missing";
        JsonNode version = invokeJson("/JSON/core/view/version/");
        if (!version.hasNonNull("version")) throw new IllegalStateException("Invalid ZAP response");
        return "Connected · ZAP " + version.path("version").asText();
    }

    public ZapScanResult scanUrl(String targetUrl) throws Exception { return scanUrl(targetUrl,()->false); }
    public ZapScanResult scanUrl(String targetUrl,java.util.function.BooleanSupplier stopped) throws Exception {
        if (!isEnabled()) {
            throw new IllegalStateException("OWASP ZAP integration is disabled");
        }
        if (!isConfigured()) throw new IllegalStateException("Configure GHOSTNET_ZAP_API_KEY on the backend");
        URI target = URI.create(targetUrl);
        if (target.getHost() == null || !("http".equalsIgnoreCase(target.getScheme()) || "https".equalsIgnoreCase(target.getScheme()))) {
            throw new IllegalArgumentException("ZAP target must be an HTTP or HTTPS URL");
        }
        String encodedTarget = URLEncoder.encode(targetUrl, StandardCharsets.UTF_8);
        // ZAP must know the target before an active scan can start.
        invokeJson("/JSON/core/action/accessUrl/?url=" + encodedTarget + "&followRedirects=true");
        String scanId = startScan(encodedTarget);
        try { waitForCompletion(scanId,stopped); }
        catch(Exception ex) { try { invokeJson("/JSON/ascan/action/stop/?scanId="+scanId); } catch(Exception ignored) {} throw ex; }
        List<ZapAlert> alerts = fetchAlerts(encodedTarget);
        return new ZapScanResult(scanId, targetUrl, alerts);
    }

    private String startScan(String encodedTarget) throws Exception {
        JsonNode node = invokeJson("/JSON/ascan/action/scan/?url=" + encodedTarget + "&recurse=true");
        String scanId = node.path("scan").asText(null);
        if (scanId == null) {
            throw new IllegalStateException("OWASP ZAP did not return a scan id");
        }
        log.info("OWASP ZAP scan started: {}", scanId);
        return scanId;
    }

    private void waitForCompletion(String scanId,java.util.function.BooleanSupplier stopped) throws Exception {
        Instant deadline = Instant.now().plus(timeout);
        while (Instant.now().isBefore(deadline)) {
            if(stopped.getAsBoolean() || Thread.currentThread().isInterrupted()) throw new java.util.concurrent.CancellationException("ZAP scan stopped");
            JsonNode node = invokeJson("/JSON/ascan/view/status/?scanId=" + scanId);
            int status = node.path("status").asInt(0);
            if (status >= 100) {
                log.info("OWASP ZAP scan {} completed", scanId);
                return;
            }
            Thread.sleep(pollInterval.toMillis());
        }
        throw new IllegalStateException("OWASP ZAP scan timed out after " + timeout.toSeconds() + " seconds");
    }

    private List<ZapAlert> fetchAlerts(String encodedTarget) throws Exception {
        JsonNode node = invokeJson("/JSON/core/view/alerts/?baseurl=" + encodedTarget + "&start=0&count=9999");
        List<ZapAlert> alerts = new ArrayList<>();
        if (node.has("alerts")) {
            for (JsonNode alertNode : node.get("alerts")) {
                alerts.add(parseAlert(alertNode));
            }
        }
        return alerts;
    }

    private ZapAlert parseAlert(JsonNode node) {
        String risk = node.path("risk").asText("info");
        return new ZapAlert(
                node.path("alert").asText("Unknown"),
                risk,
                node.path("description").asText(""),
                node.path("solution").asText(""),
                node.path("reference").asText(""),
                node.path("url").asText(""),
                node.path("param").asText(""),
                node.path("attack").asText(""),
                node.path("evidence").asText(""),
                node.path("cweid").asText("")
        );
    }

    private JsonNode invokeJson(String pathAndQuery) throws Exception {
        var config=config();
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(config.baseUrl() + pathAndQuery))
                .timeout(Duration.ofSeconds(30))
                .GET();
        if (isConfigured()) request.header("X-ZAP-API-Key", config.apiKey().trim());
        HttpRequest req = request.build();
        HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
        if (resp.statusCode() != 200) {
            throw new IllegalStateException("OWASP ZAP API call failed (HTTP " + resp.statusCode() + ")");
        }
        JsonNode body = mapper.readTree(resp.body());
        if (body == null || body.has("code")) throw new IllegalStateException("OWASP ZAP rejected the API request; check its key, permissions and target");
        return body;
    }

    private String sanitizeBaseUrl(String raw) {
        if (raw == null || raw.isBlank()) {
            return "http://localhost:8090";
        }
        String trimmed = raw.trim();
        return trimmed.endsWith("/") ? trimmed.substring(0, trimmed.length() - 1) : trimmed;
    }

    public record ZapAlert(
            String alertName,
            String risk,
            String description,
            String solution,
            String reference,
            String url,
            String parameter,
            String attack,
            String evidence,
            String cweId) {

        public String severity() {
            String normalized = risk == null ? "" : risk.toLowerCase(Locale.ROOT);
            return switch (normalized) {
                case "high" -> "high";
                case "medium" -> "medium";
                case "low" -> "low";
                default -> "info";
            };
        }
    }

    @Getter
    public static class ZapScanResult {
        private final String scanId;
        private final String targetUrl;
        private final List<ZapAlert> alerts;

        public ZapScanResult(String scanId, String targetUrl, List<ZapAlert> alerts) {
            this.scanId = scanId;
            this.targetUrl = targetUrl;
            this.alerts = alerts == null ? List.of() : List.copyOf(alerts);
        }

        public boolean hasAlerts() {
            return !alerts.isEmpty();
        }
    }
}
