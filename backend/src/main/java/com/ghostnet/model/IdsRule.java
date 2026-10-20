package com.ghostnet.model;

import java.time.ZonedDateTime;

import org.hibernate.annotations.CreationTimestamp;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

// ─────────────────────────────────────────────────────
// IDS Rule entity
// ─────────────────────────────────────────────────────
@Entity
@Table(
    name = "ids_rules",
    uniqueConstraints = @UniqueConstraint(name = "uk_ids_rule_name", columnNames = "rule_name")
)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IdsRule {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "rule_id")
    private Long ruleId;

    @Column(name = "rule_name", nullable = false, length = 200)
    private String ruleName;

    @Column(name = "rule_content", nullable = false, columnDefinition = "TEXT")
    private String ruleContent;

    @Column(name = "rule_type", nullable = false, length = 20)
    private String ruleType; // snort, suricata, custom

    @Column(nullable = false)
    private Integer severity; // 1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL

    @Column(name = "is_active", nullable = false)
    @Builder.Default
    private boolean active = true;

    @Column(name = "source_ip_pattern", length = 100)
    private String sourceIpPattern;

    @Column(name = "dest_ip_pattern", length = 100)
    private String destIpPattern;

    @Column(name = "port_pattern", length = 50)
    private String portPattern;

    @Column(name = "protocol_pattern", length = 20)
    private String protocolPattern;

    @Column(name = "payload_pattern", length = 500)
    private String payloadPattern;
    @org.hibernate.annotations.ColumnDefault("1")
    @Builder.Default private Integer thresholdCount=1;
    @org.hibernate.annotations.ColumnDefault("60")
    @Builder.Default private Integer windowSeconds=60;
    @org.hibernate.annotations.ColumnDefault("false")
    @Builder.Default private Boolean distinctPorts=false;
    public int getThresholdCount() {return thresholdCount==null?1:thresholdCount;}
    public int getWindowSeconds() {return windowSeconds==null?60:windowSeconds;}
    public boolean isDistinctPorts() {return Boolean.TRUE.equals(distinctPorts);}

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private ZonedDateTime createdAt;

    @Column(name = "match_count")
    @Builder.Default
    private long matchCount = 0;
}
