package com.ghostnet.model;

import jakarta.persistence.*;
import lombok.*;

@Entity @Table(name="integration_settings") @Getter @Setter @NoArgsConstructor
public class IntegrationSetting {
    @Id private String service;
    private boolean enabled;
    @Column(nullable=false, length=1000) private String baseUrl;
    @com.fasterxml.jackson.annotation.JsonIgnore
    @Column(columnDefinition="TEXT") private String encryptedKey;
}
