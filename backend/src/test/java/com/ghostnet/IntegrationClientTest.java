package com.ghostnet;

import com.ghostnet.integration.VirusTotalClient;
import com.ghostnet.integration.zap.OwaspZapClient;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.*;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicBoolean;
import static org.junit.jupiter.api.Assertions.*;

class IntegrationClientTest {
    private HttpServer server;
    private String base;
    @BeforeEach void start() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        base = "http://127.0.0.1:" + server.getAddress().getPort();
        server.start();
    }
    @AfterEach void stop() { server.stop(0); }
    private void reply(int status, String body) {
        server.createContext("/", exchange -> {
            assertEquals("test-secret", exchange.getRequestHeaders().getFirst("x-apikey"));
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status, bytes.length);
            try (var out = exchange.getResponseBody()) { out.write(bytes); }
        });
    }
    @Test void virusTotalAuthenticatesWithHeaderAndParsesResponse() throws Exception {
        reply(200, "{\"data\":{\"id\":\"hash\"}}");
        assertEquals("hash", new VirusTotalClient(true, "test-secret", base).lookup("/files/hash").path("data").path("id").asText());
    }
    @Test void virusTotalUsesSavedSettingsWithoutRestartingTheClient() throws Exception {
        reply(200,"{\"data\":{\"id\":\"hash\"}}");
        var settings=org.mockito.Mockito.mock(com.ghostnet.service.IntegrationSettingsService.class);
        var client=new VirusTotalClient(false,"old-key","https://unused.test");
        org.springframework.test.util.ReflectionTestUtils.setField(client,"settings",settings);
        org.mockito.Mockito.when(settings.get("virustotal")).thenReturn(new com.ghostnet.service.IntegrationSettingsService.Config(true,base,"test-secret"));
        assertEquals("hash",client.lookup("/files/hash").path("data").path("id").asText());
        org.mockito.Mockito.when(settings.get("virustotal")).thenReturn(new com.ghostnet.service.IntegrationSettingsService.Config(false,base,"test-secret"));
        assertThrows(IllegalStateException.class,()->client.lookup("/files/hash"));
    }
    @Test void virusTotalUnknownHashHasNoVerdict() throws Exception {
        reply(404, "{}");
        assertNull(new VirusTotalClient(true, "test-secret", base).lookup("/files/hash"));
    }
    @Test void virusTotalUploadsFileAndReturnsCompletedAnalysis() throws Exception {
        var uploadReceived = new AtomicBoolean();
        server.createContext("/", exchange -> {
            String response;
            if ("POST".equals(exchange.getRequestMethod()) && "/files".equals(exchange.getRequestURI().getPath())) {
                byte[] body = exchange.getRequestBody().readAllBytes();
                String multipart = new String(body, StandardCharsets.UTF_8);
                uploadReceived.set("test-secret".equals(exchange.getRequestHeaders().getFirst("x-apikey"))
                        && exchange.getRequestHeaders().getFirst("Content-Type").startsWith("multipart/form-data;")
                        && multipart.contains("name=\"file\"")
                        && multipart.contains("test sample content"));
                response = "{\"data\":{\"id\":\"analysis-123\"}}";
            } else {
                response = "{\"data\":{\"attributes\":{\"status\":\"completed\","
                        + "\"stats\":{\"malicious\":2,\"suspicious\":1,\"harmless\":3,\"undetected\":4},"
                        + "\"results\":{\"engine\":{\"category\":\"malicious\",\"engine_name\":\"TestEngine\","
                        + "\"result\":\"Test.Trojan\"}}}}}";
            }
            byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, bytes.length);
            try (var out = exchange.getResponseBody()) { out.write(bytes); }
        });

        Path file = Files.createTempFile("ghostnet-vt-", ".bin");
        try {
            Files.writeString(file, "test sample content");
            var result = new VirusTotalClient(true, "test-secret", base).uploadAndAnalyze(file);
            assertTrue(uploadReceived.get());
            assertEquals(2, result.malicious());
            assertEquals(1, result.suspicious());
            assertEquals("Test.Trojan", result.threatName());
            assertEquals("OK", result.status());
        } finally {
            Files.deleteIfExists(file);
        }
    }
    @Test void virusTotalEncodesAnalysisIdAsOnePathSegment() throws Exception {
        var encodedPathSeen = new AtomicBoolean();
        server.createContext("/", exchange -> {
            String response;
            if ("POST".equals(exchange.getRequestMethod())) {
                exchange.getRequestBody().readAllBytes();
                response = "{\"data\":{\"id\":\"analysis+/id==\"}}";
            } else {
                encodedPathSeen.set("/analyses/analysis%2B%2Fid%3D%3D".equals(exchange.getRequestURI().getRawPath()));
                response = "{\"data\":{\"attributes\":{\"status\":\"completed\","
                        + "\"stats\":{\"malicious\":0,\"suspicious\":0,\"harmless\":1,\"undetected\":0},"
                        + "\"results\":{}}}}";
            }
            byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, bytes.length);
            try (var out = exchange.getResponseBody()) { out.write(bytes); }
        });

        Path file = Files.createTempFile("ghostnet-vt-path-", ".bin");
        try {
            Files.writeString(file, "sample");
            var result = new VirusTotalClient(true, "test-secret", base).uploadAndAnalyze(file);
            assertTrue(encodedPathSeen.get());
            assertEquals("OK", result.status());
        } finally {
            Files.deleteIfExists(file);
        }
    }
    @Test void virusTotalReportsQuotaAndRejectedCredentials() {
        reply(429, "{}");
        var error = assertThrows(IllegalStateException.class, () -> new VirusTotalClient(true, "test-secret", base).lookup("/files/hash"));
        assertTrue(error.getMessage().contains("quota"));
        assertFalse(error.getMessage().contains("test-secret"));
    }
    @Test void virusTotalRejectsMissingKeyBeforeNetworkRequest() {
        assertThrows(IllegalStateException.class, () -> new VirusTotalClient(true, "", base).lookup("/files/hash"));
    }
    @Test void zapDiscoversTargetBeforeScanningAndKeepsKeyOutOfUrl() throws Exception {
        var discovered = new AtomicBoolean();
        server.createContext("/", exchange -> {
            assertEquals("test-secret", exchange.getRequestHeaders().getFirst("X-ZAP-API-Key"));
            assertFalse(exchange.getRequestURI().toString().contains("test-secret"));
            String path = exchange.getRequestURI().getPath();
            String response;
            if (path.contains("accessUrl")) { discovered.set(true); response = "{}"; }
            else if (path.contains("/action/scan/")) { assertTrue(discovered.get()); response = "{\"scan\":\"1\"}"; }
            else if (path.contains("/status/")) response = "{\"status\":\"100\"}";
            else response = "{\"alerts\":[]}";
            byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, bytes.length);
            try (var out = exchange.getResponseBody()) { out.write(bytes); }
        });
        var result = new OwaspZapClient(base, "test-secret", true, 500, 60).scanUrl("http://127.0.0.1:1234");
        assertEquals("1", result.getScanId());
        assertTrue(result.getAlerts().isEmpty());
    }
    @Test void zapRejectsApiErrorEvenWithHttp200() {
        server.createContext("/", exchange -> {
            byte[] bytes = "{\"code\":\"bad_api_key\",\"message\":\"secret details\"}".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, bytes.length);
            try (var out = exchange.getResponseBody()) { out.write(bytes); }
        });
        var error = assertThrows(IllegalStateException.class, () -> new OwaspZapClient(base, "test-secret", true, 500, 60).checkConnection());
        assertFalse(error.getMessage().contains("secret details"));
    }
}
