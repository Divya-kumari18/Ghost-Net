package com.ghostnet.controller;

import java.time.Instant;
import java.util.Map;
import com.ghostnet.integration.VirusTotalClient;
import com.ghostnet.integration.zap.OwaspZapClient;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/integrations")
@RequiredArgsConstructor
public class IntegrationController {
    private final OwaspZapClient zap;
    private final VirusTotalClient virusTotal;
    private final com.ghostnet.service.IntegrationSettingsService settings;

    @GetMapping
    public Map<String, Object> status() {
        return Map.of("zap", settings.metadata("zap"), "virustotal", settings.metadata("virustotal"));
    }

    @PutMapping("/{service}")
    @PreAuthorize("hasRole('ADMIN')")
    public Map<String,Object> save(@PathVariable String service,@RequestBody com.ghostnet.service.IntegrationSettingsService.Update update) {
        return settings.save(service,update);
    }

    @PostMapping("/{service}/check")
    @PreAuthorize("hasRole('ADMIN')")
    public Map<String, Object> check(@PathVariable String service) {
        if (!service.equals("zap") && !service.equals("virustotal")) throw new IllegalArgumentException("Unknown integration");
        boolean enabled = service.equals("zap") ? zap.isEnabled() : virusTotal.isEnabled();
        boolean configured = service.equals("zap") ? zap.isConfigured() : virusTotal.isConfigured();
        String message;
        boolean connected = false;
        try {
            message = service.equals("zap") ? zap.checkConnection() : virusTotal.checkConnection();
            connected = enabled && configured;
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt(); message = "Connection check interrupted";
        } catch (Exception ex) {
            // Never return upstream bodies, request URLs or credentials.
            message = ex instanceof IllegalStateException ? ex.getMessage() : "Service unreachable; check endpoint and server connectivity";
        }
        return Map.of("enabled", enabled, "configured", configured, "connected", connected,
                "message", message, "checkedAt", Instant.now().toString());
    }
}
