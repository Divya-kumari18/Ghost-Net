package com.ghostnet.model;
import jakarta.persistence.*;
import lombok.*;
import java.time.ZonedDateTime;
@Entity @Data @NoArgsConstructor @AllArgsConstructor @Builder
public class FileIntegrityBaseline {
    @Id @Column(length=64) private String baselineId;
    @Column(columnDefinition="TEXT",nullable=false) private String path;
    private String approvedHash;
    private String observedHash;
    private String approvedBy;
    private ZonedDateTime approvedAt;
    private ZonedDateTime checkedAt;
}
