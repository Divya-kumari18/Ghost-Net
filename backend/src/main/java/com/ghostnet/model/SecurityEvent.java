package com.ghostnet.model;

import jakarta.persistence.*;
import lombok.*;
import java.time.ZonedDateTime;

@Entity @Table(name="security_events", indexes={@Index(columnList="asset,occurredAt"), @Index(columnList="processed,published")})
@Data @Builder @NoArgsConstructor @AllArgsConstructor
public class SecurityEvent {
    @Id private String eventId;
    @Column(nullable=false) private String source;
    @Column(nullable=false, length=500) private String asset;
    private String actor;
    private String severity;
    @Column(columnDefinition="TEXT") private String evidence;
    @Column(nullable=false) private ZonedDateTime occurredAt;
    @Column(nullable=false) private ZonedDateTime receivedAt;
    private boolean processed;
    @org.hibernate.annotations.ColumnDefault("false") private boolean analyzed;
    private boolean published;
    private Long incidentId;
}
