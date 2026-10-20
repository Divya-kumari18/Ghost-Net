package com.ghostnet.model;
import jakarta.persistence.*;
import lombok.*;
import java.time.ZonedDateTime;
@Entity @Data @NoArgsConstructor
public class OperationalSettings {
    @Id private Long id=1L;
    private int criticalThreshold=85;
    private boolean retentionEnabled=false;
    private int retentionHotDays=90;
    private String updatedBy;
    private ZonedDateTime updatedAt;
}
