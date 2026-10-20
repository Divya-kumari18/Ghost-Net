package com.ghostnet.model;
import jakarta.persistence.*;
import lombok.*;
@Entity @Data @NoArgsConstructor @AllArgsConstructor
public class IngestionCursor {
    @Id private String cursorId;
    private long position;
    @Column(columnDefinition="TEXT") private String identity;
}
