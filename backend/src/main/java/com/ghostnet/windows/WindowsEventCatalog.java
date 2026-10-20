package com.ghostnet.windows;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import com.fasterxml.jackson.databind.ObjectMapper;

@Slf4j
@Component
public class WindowsEventCatalog {

    private final ResourceLoader resourceLoader;

    @Value("${ghostnet.events.details-path:src/main/java/com/ghostnet/windows/eventdetails.md}")
    private String detailsPath;

    private volatile Map<Long, EventMeta> byEventId = Collections.emptyMap();
    private volatile Map<String, EventMeta> byProvider = Collections.emptyMap();

    public WindowsEventCatalog(ResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    @PostConstruct
    public void load() {
        Map<Long, EventMeta> loaded = new LinkedHashMap<>();

        if (!loadFromFileSystem(loaded)) {
            loadFromResource(loaded);
        }

        Map<String, EventMeta> scoped = new LinkedHashMap<>();
        try (InputStream in = resourceLoader.getResource("classpath:windows-events.json").getInputStream()) {
            for (var entry : new ObjectMapper().readTree(in)) {
                long id = entry.path("eventId").asLong();
                String source = entry.path("source").asText();
                String channel = entry.path("channel").asText();
                String name = entry.path("name").asText();
                var meta = new EventMeta(id, source, name, inferCategory(name));
                scoped.put(key(id, source, channel), meta);
                // The ID-only endpoint remains a Security catalog for older clients.
                if ("Security".equals(channel)) loaded.put(id, meta);
            }
        } catch (Exception ex) {
            throw new IllegalStateException("Cannot load bundled Windows event definitions", ex);
        }

        byEventId = Collections.unmodifiableMap(loaded);
        byProvider = Collections.unmodifiableMap(scoped);
        log.info("Windows event catalog loaded: {} provider-specific entries", byProvider.size());
    }

    public Optional<EventMeta> find(long eventId) {
        return Optional.ofNullable(byEventId.get(eventId));
    }

    public Optional<EventMeta> find(long eventId, String source, String channel) {
        EventMeta exact = byProvider.get(key(eventId, source, channel));
        if (exact != null) return Optional.of(exact);
        boolean auditProvider = "Microsoft-Windows-Security-Auditing".equalsIgnoreCase(source);
        boolean unspecifiedProvider = source == null || source.isBlank();
        if ((auditProvider || unspecifiedProvider) && "Security".equalsIgnoreCase(channel)) return find(eventId);
        return Optional.empty();
    }

    private String key(long id, String source, String channel) {
        return (source == null ? "" : source.trim().toLowerCase(Locale.ROOT)) + "|"
                + (channel == null ? "" : channel.trim().toLowerCase(Locale.ROOT)) + "|" + id;
    }

    public int size() {
        return byProvider.size();
    }

    private boolean loadFromFileSystem(Map<Long, EventMeta> target) {
        try {
            Path p = Path.of(detailsPath);
            if (!Files.exists(p)) {
                return false;
            }
            try (BufferedReader reader = Files.newBufferedReader(p, StandardCharsets.UTF_8)) {
                parseLines(reader, target);
            }
            return true;
        } catch (Exception ex) {
            log.warn("Failed to load Windows event catalog from file {}: {}", detailsPath, ex.getMessage());
            return false;
        }
    }

    private void loadFromResource(Map<Long, EventMeta> target) {
        String normalized = detailsPath.replace('\\', '/');
        String candidate = normalized.startsWith("classpath:") ? normalized : "classpath:" + normalized;
        try {
            Resource resource = resourceLoader.getResource(candidate);
            if (!resource.exists()) {
                return;
            }
            try (InputStream in = resource.getInputStream();
                 BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
                parseLines(reader, target);
            }
        } catch (Exception ex) {
            log.warn("Failed to load Windows event catalog from classpath {}: {}", candidate, ex.getMessage());
        }
    }

    private void parseLines(BufferedReader reader, Map<Long, EventMeta> target) throws Exception {
        String line;
        while ((line = reader.readLine()) != null) {
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#") || trimmed.startsWith("```")) {
                continue;
            }

            String[] parts = trimmed.split("\\t", 3);
            if (parts.length < 3) {
                parts = trimmed.split("\\s+", 3);
                if (parts.length < 3) {
                    continue;
                }
            }

            String sourceName = parts[0].trim();
            String eventIdToken = parts[1].trim();
            String description = parts[2].trim();
            if (eventIdToken.isEmpty() || description.isEmpty()) {
                continue;
            }

            long eventId;
            try {
                eventId = Long.parseLong(eventIdToken);
            } catch (NumberFormatException ignored) {
                continue;
            }

            target.put(eventId, new EventMeta(eventId, sourceName, description, inferCategory(description)));
        }
    }

    private String inferCategory(String description) {
        String d = description == null ? "" : description.toLowerCase(Locale.ROOT);
        if (d.contains("logon") || d.contains("kerberos") || d.contains("account") || d.contains("credential")) {
            return "AUTH";
        }
        if (d.contains("firewall") || d.contains("ipsec") || d.contains("network")) {
            return "NETWORK";
        }
        if (d.contains("service") || d.contains("process") || d.contains("task")) {
            return "SYSTEM";
        }
        if (d.contains("certificate") || d.contains("crypto")) {
            return "CRYPTO";
        }
        return "GENERAL";
    }

    public record EventMeta(long eventId, String sourceName, String description, String category) {
    }
}
