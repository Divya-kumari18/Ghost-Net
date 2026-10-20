package com.ghostnet.model;
import jakarta.persistence.*;
import lombok.*;
import java.time.ZonedDateTime;
@Entity @Data @NoArgsConstructor @AllArgsConstructor @Builder
public class OperationalJob {
    @Id private String jobId;
    private String name;
    private String type;
    private String target;
    private String createdBy;
    private long intervalSeconds;
    private boolean enabled;
    private ZonedDateTime nextRun;
    private ZonedDateTime lastRun;
    private String lastStatus;
    @Column(columnDefinition="TEXT") private String lastError;
    @Column(columnDefinition="TEXT") private String output;
}
