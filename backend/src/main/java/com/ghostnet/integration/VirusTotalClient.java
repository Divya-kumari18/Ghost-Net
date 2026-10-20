package com.ghostnet.integration;

import java.net.URI;
import java.net.http.*;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.UUID;
import com.fasterxml.jackson.databind.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class VirusTotalClient {
    @org.springframework.beans.factory.annotation.Autowired(required=false)
    private com.ghostnet.service.IntegrationSettingsService settings;
    private com.ghostnet.service.IntegrationSettingsService.Config config() {
        var current = settings == null
                ? new com.ghostnet.service.IntegrationSettingsService.Config(enabled, baseUrl, key)
                : settings.get("virustotal");
        return new com.ghostnet.service.IntegrationSettingsService.Config(
                current.enabled(),
                current.baseUrl().trim().replaceAll("/+$", ""),
                current.apiKey().trim());
    }
    private final boolean enabled;
    private final String key;
    private final String baseUrl;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NEVER).build();
    private final ObjectMapper mapper = new ObjectMapper();

    public VirusTotalClient(@Value("${ghostnet.virustotal.enabled:false}") boolean enabled,
            @Value("${ghostnet.virustotal.api-key:}") String key,
            @Value("${ghostnet.virustotal.base-url:https://www.virustotal.com/api/v3}") String baseUrl) {
        this.enabled = enabled;
        this.key = key == null ? "" : key.trim();
        this.baseUrl = baseUrl.replaceAll("/+$", "");
    }

    public boolean isEnabled() { return config().enabled(); }
    public boolean isConfigured() {
        String currentKey = config().apiKey();
        return !currentKey.isBlank() && !currentKey.equals("YOUR_VIRUSTOTAL_API_KEY")
                && !currentKey.startsWith("CHANGE_ME");
    }

    public JsonNode lookup(String resource) throws Exception {
        if (!isEnabled()) throw new IllegalStateException("VirusTotal is disabled");
        if (!isConfigured()) throw new IllegalStateException("Configure GHOSTNET_VIRUSTOTAL_API_KEY on the backend");
        var current = config();
        var request = HttpRequest.newBuilder(URI.create(current.baseUrl() + resource)).timeout(Duration.ofSeconds(15))
                .header("x-apikey", current.apiKey()).header("Accept", "application/json").GET().build();
        var response = http.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() == 404) return null;
        if (response.statusCode() != 200) {
            throw upstreamError("VirusTotal request", response.statusCode(), response.body());
        }
        JsonNode body = mapper.readTree(response.body());
        if (body == null || !body.has("data")) throw new IllegalStateException("Invalid VirusTotal response");
        return body;
    }

    public FileAnalysis uploadAndAnalyze(Path file) throws Exception {
        if (!isEnabled()) throw new IllegalStateException("VirusTotal is disabled");
        if (!isConfigured()) throw new IllegalStateException("Configure GHOSTNET_VIRUSTOTAL_API_KEY on the backend");
        if (!Files.isRegularFile(file) || !Files.isReadable(file)) {
            throw new IllegalArgumentException("VirusTotal upload requires a readable regular file");
        }

        URI uploadUri;
        boolean includeApiKey = true;
        if (Files.size(file) > 32L * 1024L * 1024L) {
            JsonNode uploadUrlResponse = lookup("/files/upload_url");
            String uploadUrl = uploadUrlResponse == null ? "" : uploadUrlResponse.path("data").asText();
            if (uploadUrl.isBlank()) throw new IllegalStateException("VirusTotal did not return a large-file upload URL");
            uploadUri = URI.create(uploadUrl);
            includeApiKey = false;
        } else {
            uploadUri = URI.create(config().baseUrl() + "/files");
        }

        JsonNode uploadResponse = postFile(uploadUri, file, includeApiKey);
        String analysisId = uploadResponse.path("data").path("id").asText();
        if (analysisId.isBlank()) {
            throw new IllegalStateException("VirusTotal returned an invalid file upload response");
        }

        JsonNode analysis = null;
        for (int attempt = 0; attempt < 7; attempt++) {
            if (attempt > 0) Thread.sleep(Duration.ofSeconds(5));
            analysis = lookup("/analyses/" + URLEncoder.encode(analysisId, StandardCharsets.UTF_8)
                    .replace("+", "%20"));
            if (analysis == null || "completed".equalsIgnoreCase(
                    analysis.path("data").path("attributes").path("status").asText())) {
                break;
            }
        }
        if (analysis == null) return new FileAnalysis(0, 0, 0, 0, "", "NOT_FOUND");

        JsonNode attributes = analysis.path("data").path("attributes");
        JsonNode stats = attributes.path("stats");
        if (!stats.isObject()) {
            return new FileAnalysis(0, 0, 0, 0, "", "INVALID_RESPONSE");
        }

        String status = attributes.path("status").asText();
        if (!"completed".equalsIgnoreCase(status)) {
            return new FileAnalysis(0, 0, 0, 0, "", "PROCESSING");
        }

        String threatName = firstMaliciousEngineResult(attributes.path("results"));
        return new FileAnalysis(
                stats.path("malicious").asInt(),
                stats.path("suspicious").asInt(),
                stats.path("harmless").asInt(),
                stats.path("undetected").asInt(),
                threatName,
                "OK");
    }

    private JsonNode postFile(URI uri, Path file, boolean includeApiKey) throws Exception {
        String boundary = "----GhostNet" + UUID.randomUUID();
        String filename = file.getFileName().toString().replaceAll("[\\r\\n\"]", "_");
        byte[] prefix = ("--" + boundary + "\r\n"
                + "Content-Disposition: form-data; name=\"file\"; filename=\"" + filename + "\"\r\n"
                + "Content-Type: application/octet-stream\r\n\r\n").getBytes(StandardCharsets.UTF_8);
        byte[] suffix = ("\r\n--" + boundary + "--\r\n").getBytes(StandardCharsets.UTF_8);
        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofMinutes(2))
                .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.concat(
                        HttpRequest.BodyPublishers.ofByteArray(prefix),
                        HttpRequest.BodyPublishers.ofFile(file),
                        HttpRequest.BodyPublishers.ofByteArray(suffix)));
        if (includeApiKey) requestBuilder.header("x-apikey", config().apiKey());

        HttpResponse<String> response = http.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString());
        int status = response.statusCode();
        if (status != 200 && status != 201) {
            throw upstreamError("VirusTotal file upload", status, response.body());
        }
        JsonNode body = mapper.readTree(response.body());
        if (body == null || !body.path("data").isObject()) {
            throw new IllegalStateException("Invalid VirusTotal file upload response");
        }
        return body;
    }

    private IllegalStateException upstreamError(String operation, int status, String responseBody) {
        if (status == 401 || status == 403) {
            return new IllegalStateException(
                    "VirusTotal rejected the API key or account permissions (HTTP " + status + ")");
        }
        if (status == 429) {
            return new IllegalStateException("VirusTotal quota exceeded; try again after the quota resets");
        }
        String code = "";
        try {
            code = mapper.readTree(responseBody).path("error").path("code").asText("");
        } catch (com.fasterxml.jackson.core.JsonProcessingException ignored) {
            // Keep the sanitized HTTP status if the provider response isn't JSON.
        }
        return new IllegalStateException(operation + " failed (HTTP " + status
                + (code.isBlank() ? "" : ", " + code) + ")");
    }

    private String firstMaliciousEngineResult(JsonNode results) {
        if (!results.isObject()) return "";
        var values = results.elements();
        while (values.hasNext()) {
            JsonNode result = values.next();
            String category = result.path("category").asText();
            if ("malicious".equalsIgnoreCase(category) || "suspicious".equalsIgnoreCase(category)) {
                String engineName = result.path("engine_name").asText();
                String detection = result.path("result").asText();
                if (!detection.isBlank()) return detection;
                if (!engineName.isBlank()) return "VirusTotal." + engineName;
            }
        }
        return "";
    }

    public record FileAnalysis(
            int malicious,
            int suspicious,
            int harmless,
            int undetected,
            String threatName,
            String status) {
    }

    public String checkConnection() throws Exception {
        if (!isEnabled()) return "Disabled";
        if (!isConfigured()) return "API key missing";
        // This checks read access only; VirusTotal may separately restrict file uploads.
        lookup("/files/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        return "API key accepted for reputation lookup; file-upload permissions are not verified";
    }
}
