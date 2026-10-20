package com.ghostnet.integration.cowrie;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ghostnet.config.CowrieIntegrationProperties;
import com.ghostnet.model.Honeypot;
import com.ghostnet.repository.HoneypotRepository;
import com.ghostnet.service.HoneypotService;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;

/**
 * Polls Cowrie's JSON log (var/log/cowrie/cowrie.json) and turns interesting
 * events into persisted honeypot interactions inside GhostNet.
 */
@Slf4j
@Component
@ConditionalOnProperty(prefix = "ghostnet.honeypot.cowrie", name = "enabled", havingValue = "true")
public class CowrieLogIngestor {

    private static final Set<String> INTERESTING_EVENTS = Set.of(
        "cowrie.session.connect",
        "cowrie.command.input",
        "cowrie.session.input",
        "cowrie.session.file_download",
        "cowrie.session.file_upload",
        "cowrie.command.failed",
        "cowrie.login.success",
        "cowrie.login.failed"
    );

    private final CowrieIntegrationProperties props;
    private final HoneypotRepository honeypotRepository;
    private final HoneypotService honeypotService;
    private final ObjectMapper objectMapper;
    private final com.ghostnet.repository.IngestionCursorRepository cursors;
    private final org.springframework.transaction.support.TransactionTemplate tx;
    private final com.ghostnet.service.SecurityEventPipeline pipeline;
    private String fileIdentity="";
    private final java.util.Map<String,String> sessionIps=new java.util.HashMap<>();

    private final AtomicLong lastOffset = new AtomicLong(0L);
    private Path logPath;
    private Long honeypotId;

    public CowrieLogIngestor(
            CowrieIntegrationProperties props,
            HoneypotRepository honeypotRepository,
            HoneypotService honeypotService,
            ObjectMapper objectMapper,
            com.ghostnet.repository.IngestionCursorRepository cursors,
            org.springframework.transaction.support.TransactionTemplate tx,
            com.ghostnet.service.SecurityEventPipeline pipeline) {
        this.props = props;
        this.honeypotRepository = honeypotRepository;
        this.honeypotService = honeypotService;
        this.objectMapper = objectMapper;
        this.cursors = cursors;
        this.tx = tx;
        this.pipeline = pipeline;
    }

    @PostConstruct
    void init() {
        if (props.getLogPath() == null || props.getLogPath().isBlank()) {
            log.warn("Cowrie ingestion enabled but ghostnet.honeypot.cowrie.log-path is not set.");
            return;
        }
        logPath = Paths.get(props.getLogPath().trim()).toAbsolutePath().normalize();
        try {
            if (props.isTailFromEnd() && Files.exists(logPath)) {
                lastOffset.set(Files.size(logPath));
            }
        } catch (IOException e) {
            log.warn("Unable to determine initial Cowrie log size: {}", e.getMessage());
        }
        cursors.findById("cowrie:"+logPath).ifPresent(cursor->{lastOffset.set(cursor.getPosition());fileIdentity=cursor.getIdentity();});
        ensureHoneypotRecord();
    }

    @Scheduled(fixedDelayString = "${ghostnet.honeypot.cowrie.poll-interval-ms:4000}")
    public synchronized void pollCowrieLog() {
        if (logPath == null || honeypotId == null) {
            return;
        }
        if (!Files.exists(logPath)) {
            log.debug("Cowrie log not found yet at {}", logPath);
            return;
        }
        try (RandomAccessFile raf = new RandomAccessFile(logPath.toFile(), "r")) {
            long fileLength = raf.length();
            var attributes=Files.readAttributes(logPath,java.nio.file.attribute.BasicFileAttributes.class);
            String identity=String.valueOf(attributes.fileKey())+":"+attributes.creationTime();
            if(!fileIdentity.isEmpty() && !identity.equals(fileIdentity)) lastOffset.set(0);
            fileIdentity=identity;
            long pointer = lastOffset.get();
            if (pointer > fileLength) {
                pointer = 0;
            }
            raf.seek(pointer);
            int count=0;
            while(count++ < 1000) {
                long start=raf.getFilePointer();
                String raw=raf.readLine();
                if(raw==null) break;
                long next=raf.getFilePointer();
                raf.seek(next-1);int terminator=raf.read();raf.seek(next);
                if(terminator!=10 && terminator!=13) {raf.seek(start);break;}
                String line=new String(raw.getBytes(StandardCharsets.ISO_8859_1),StandardCharsets.UTF_8).trim();
                tx.executeWithoutResult(status->{
                    if(!line.isEmpty()) processLine(line);
                    cursors.save(new com.ghostnet.model.IngestionCursor("cowrie:"+logPath,next,fileIdentity));
                });
                lastOffset.set(next);
            }
        } catch (Exception e) {
            log.error("Failed to read Cowrie log: {}", e.getMessage());
        }
    }

    private void ensureHoneypotRecord() {
        Honeypot honeypot = honeypotRepository.findByHoneypotName(props.getHoneypotName())
            .orElseGet(() -> honeypotRepository.save(Honeypot.builder()
                .honeypotName(props.getHoneypotName())
                .honeypotType(props.getHoneypotType())
                .ipAddress(props.getHostIp())
                .port(props.getHostPort())
                .deploymentType("external")
                .dockerImage("cowrie/cowrie:latest")
                .lastKnownState("external")
                .active(true)
                .build()));
        this.honeypotId = honeypot.getHoneypotId();
    }

    private void processLine(String jsonLine) {
        try {
            CowrieEvent event = objectMapper.readValue(jsonLine, CowrieEvent.class);
            if (event.eventid == null || !INTERESTING_EVENTS.contains(event.eventid)) {
                return;
            }
            String sessionKey=event.session==null?null:"cowrie-session:"+event.session;
            String persisted=sessionKey==null?null:cursors.findById(sessionKey).map(com.ghostnet.model.IngestionCursor::getIdentity).orElse(null);
            String attackerIp = firstNonBlank(event.srcIp, event.peerIp,sessionIps.get(event.session),persisted);
            if(attackerIp!=null && event.session!=null) {
                if(sessionIps.size()>10000) sessionIps.clear();
                sessionIps.put(event.session,attackerIp);
                cursors.save(new com.ghostnet.model.IngestionCursor(sessionKey,System.currentTimeMillis(),attackerIp));
            }
            if (attackerIp == null) {
                return;
            }
            String data = buildSummary(event);
            honeypotService.recordInteraction(honeypotId, attackerIp, data);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            // Record the rejected line's identity without retaining credentials or arbitrary log content.
            try {
                String digest=java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(jsonLine.getBytes(StandardCharsets.UTF_8)));
                pipeline.record("cowrie-invalid:"+digest,"ingestion",props.getHostIp(),null,"low",
                    "Rejected malformed Cowrie JSON record SHA256="+digest,java.time.ZonedDateTime.now());
                log.warn("Rejected malformed Cowrie JSON record {}; diagnostic persisted",digest);
            } catch(Exception failure) {throw new IllegalStateException("Cannot persist rejected-record diagnostic; offset retained",failure);}
        } catch (Exception e) {
            throw new IllegalStateException("Cowrie event failed; offset retained",e);
        }
    }

    private static String buildSummary(CowrieEvent event) {
        StringBuilder sb = new StringBuilder(event.eventid);
        if (event.input != null && !event.input.isBlank()) {
            sb.append(" :: ").append(event.input.trim());
        } else if (event.message != null && !event.message.isBlank()) {
            sb.append(" :: ").append(event.message.trim());
        }
        if (event.filename != null) {
            sb.append(" | file=").append(event.filename);
        }
        if (event.url != null) {
            sb.append(" | url=").append(event.url);
        }
        if (event.outfile != null) {
            sb.append(" | saved=").append(event.outfile);
        }
        if (event.username != null || event.password != null) {
            sb.append(" | creds=")
              .append(event.username != null ? event.username : "?")
              .append('/')
              .append("[redacted]");
        }
        if (event.session != null) {
            sb.append(" | session=").append(event.session);
        }
        String summary = sb.toString();
        return summary.length() > 1900 ? summary.substring(0, 1900) : summary;
    }

    private static String firstNonBlank(String... values) {
        for (String v : values) {
            if (v != null) {
                String trimmed = v.trim();
                if (!trimmed.isEmpty()) {
                    return trimmed;
                }
            }
        }
        return null;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private static class CowrieEvent {
        @JsonProperty("eventid")
        private String eventid;
        @JsonProperty("message")
        private String message;
        @JsonProperty("src_ip")
        private String srcIp;
        @JsonProperty("peer_ip")
        private String peerIp;
        @JsonProperty("input")
        private String input;
        @JsonProperty("outfile")
        private String outfile;
        @JsonProperty("filename")
        private String filename;
        @JsonProperty("url")
        private String url;
        @JsonProperty("username")
        private String username;
        @JsonProperty("password")
        private String password;
        @JsonProperty("session")
        private String session;
    }
}
