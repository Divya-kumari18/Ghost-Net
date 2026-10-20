package com.ghostnet.service;

import com.ghostnet.model.*;
import com.ghostnet.repository.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import java.time.ZonedDateTime;
import java.util.*;
import java.util.concurrent.TimeUnit;
import com.fasterxml.jackson.databind.ObjectMapper;

/** Database outbox: local correlation survives restarts; optional Kafka publication retries. */
@Service @Slf4j
public class SecurityEventPipeline {
    private final SecurityEventRepository events;
    private final IncidentRepository incidents;
    private final IncidentTimelineRepository timeline;
    private final IncidentService incidentService;
    private final TransactionTemplate tx;
    private final JdbcTemplate jdbc;
    private final KafkaTemplate<String,String> kafka;
    @Value("${ghostnet.kafka.enabled:false}") private boolean kafkaEnabled;
    @Value("${ghostnet.kafka.topic:ghostnet.security-events}") private String topic;
    private final ObjectMapper json = new ObjectMapper().findAndRegisterModules();

    public SecurityEventPipeline(
            SecurityEventRepository events,
            IncidentRepository incidents,
            IncidentTimelineRepository timeline,
            IncidentService incidentService,
            TransactionTemplate tx,
            JdbcTemplate jdbc,
            KafkaTemplate<String, String> kafka) {
        this.events = events;
        this.incidents = incidents;
        this.timeline = timeline;
        this.incidentService = incidentService;
        this.tx = tx;
        this.jdbc = jdbc;
        this.kafka = kafka;
    }

    public SecurityEvent record(String id, String source, String asset, String actor, String severity, String evidence, ZonedDateTime time) {
        if (id == null || source == null || asset == null || asset.isBlank()) throw new IllegalArgumentException("Event identity, source and asset required");
        return tx.execute(status -> {
            // PostgreSQL transaction lock makes repeated ingestion idempotent across application instances.
            jdbc.query("select pg_advisory_xact_lock(hashtext(?))", rs -> {}, id);
            return events.findById(id).orElseGet(() -> events.save(SecurityEvent.builder().eventId(id).source(source)
                .asset(asset).actor(actor).severity(severity.toLowerCase(Locale.ROOT)).evidence(evidence)
                .occurredAt(time == null ? ZonedDateTime.now() : time).receivedAt(ZonedDateTime.now()).build()));
        });
    }

    @Scheduled(fixedDelay=1000)
    public synchronized void correlate() {
        for (var pending : events.findByProcessedFalseOrderByReceivedAtAsc(PageRequest.of(0,200))) {
            try { tx.executeWithoutResult(status -> {
                var event = events.lock(pending.getEventId()).orElseThrow();
                if (event.isProcessed()) return;
                if(Set.of("capture","ingestion").contains(event.getSource())) {event.setProcessed(true);return;}
                jdbc.query("select pg_advisory_xact_lock(hashtext(?))", rs -> {}, "asset:" + event.getAsset());
                var related = events.findByAssetAndOccurredAtAfter(event.getAsset(), event.getOccurredAt().minusMinutes(10)).stream()
                    .filter(e -> !Set.of("capture","ingestion").contains(e.getSource()))
                    .filter(e -> !e.getOccurredAt().isAfter(event.getOccurredAt().plusMinutes(10))).toList();
                long sources = related.stream().map(SecurityEvent::getSource).distinct().count();
                var existing = related.stream().map(SecurityEvent::getIncidentId).filter(Objects::nonNull)
                    .map(incidents::findById).flatMap(Optional::stream)
                    .filter(i -> !Set.of("resolved","closed").contains(i.getStatus())).findFirst();
                if (existing.isPresent() || sources >= 2 || "critical".equals(event.getSeverity())) {
                    var incident = existing.orElseGet(() -> incidentService.createIncident(
                        "Correlated threat on " + event.getAsset(), event.getEvidence(),
                        "critical".equals(event.getSeverity()) ? "critical" : "high", "system", event.getAsset()));
                    if(related.stream().anyMatch(e -> "critical".equals(e.getSeverity()))) incident.setSeverity("critical");
                    for(var evidence : related) {
                        if(evidence.getIncidentId()!=null) continue;
                        evidence.setIncidentId(incident.getIncidentId());
                        events.save(evidence);
                        timeline.save(IncidentTimeline.builder().incident(incident).actionType("note")
                            .description("Evidence " + evidence.getEventId() + " from " + evidence.getSource() + ": " + evidence.getEvidence()).build());
                    }
                }
                event.setProcessed(true);
            }); } catch (Exception ex) { log.error("Correlation failed for {}; retained for retry", pending.getEventId(), ex); break; }
        }
    }

    @Scheduled(fixedDelay=2000)
    public synchronized void publishOutbox() {
        if (!kafkaEnabled) return;
        for (var event : events.findByPublishedFalseOrderByReceivedAtAsc(PageRequest.of(0,100))) {
            try {
                kafka.send(topic, event.getEventId(), json.writeValueAsString(event)).get(3, TimeUnit.SECONDS);
                tx.executeWithoutResult(status -> events.lock(event.getEventId()).ifPresent(e -> e.setPublished(true)));
            } catch (Exception ex) { log.warn("Kafka unavailable; outbox retained: {}", ex.getMessage()); break; }
        }
    }
    public Map<String,Object> status() {
        return Map.of("mode", kafkaEnabled ? "database-outbox-and-kafka" : "database-local", "pendingCorrelation",events.countByProcessedFalse(),
            "pendingPublication",events.countByPublishedFalse(),"kafkaEnabled",kafkaEnabled,"pendingModelBatches",events.countBySourceAndAnalyzedFalse("capture"));
    }
}
