package com.ghostnet.config;
import com.ghostnet.model.SecurityEvent;
import com.ghostnet.repository.SecurityEventRepository;
import com.ghostnet.service.SecurityEventPipeline;
import org.springframework.stereotype.Component;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.transaction.annotation.Transactional;
import com.fasterxml.jackson.databind.ObjectMapper;
@Component
@ConditionalOnProperty(name="ghostnet.kafka.enabled",havingValue="true")
public class KafkaEventConsumer {
    private final SecurityEventPipeline pipeline;
    private final SecurityEventRepository events;
    private final ObjectMapper json=new ObjectMapper().findAndRegisterModules();

    public KafkaEventConsumer(SecurityEventPipeline pipeline, SecurityEventRepository events) {
        this.pipeline = pipeline;
        this.events = events;
    }

    @KafkaListener(topics="${ghostnet.kafka.topic:ghostnet.security-events}",groupId="${ghostnet.kafka.group:ghostnet-correlation}")
    @Transactional public void receive(String payload) throws Exception {
        var event=json.readValue(payload,SecurityEvent.class);
        pipeline.record(event.getEventId(),event.getSource(),event.getAsset(),event.getActor(),event.getSeverity(),event.getEvidence(),event.getOccurredAt());
        events.findById(event.getEventId()).ifPresent(e->e.setPublished(true));
    }
}
