-- GhostNet: Uncovering Invisible Threats in Modern Networks Database Schema
-- V1: Initial Schema
-- Project team: Divya Kumari, Arnitha P, Aishwarya Girani, Arun Prasad

-- ─────────────────────────────────────────────────────────────────────
-- Module 1: Secure Login
-- ─────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    user_id       SERIAL PRIMARY KEY,
    username      VARCHAR(50)  UNIQUE NOT NULL,
    email         VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    salt          VARCHAR(32)  NOT NULL,
    role          VARCHAR(20)  NOT NULL CHECK (role IN ('admin','analyst','operator','auditor','viewer')),
    is_active     BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS user_sessions (
    session_id VARCHAR(255) PRIMARY KEY,
    user_id    INTEGER      REFERENCES users(user_id) ON DELETE CASCADE,
    ip_address VARCHAR(45)  NOT NULL,
    user_agent VARCHAR(500),
    expires_at TIMESTAMPTZ  NOT NULL,
    is_active  BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ─────────────────────────────────────────────────────────────────────
-- Module 2: Security Event Pipeline
-- ─────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS security_events (
    event_id    VARCHAR(255) PRIMARY KEY,
    source      VARCHAR(100) NOT NULL,
    asset       VARCHAR(500) NOT NULL,
    actor       VARCHAR(255),
    severity    VARCHAR(20),
    evidence    TEXT,
    occurred_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL,
    processed   BOOLEAN NOT NULL DEFAULT FALSE,
    analyzed    BOOLEAN NOT NULL DEFAULT FALSE,
    published   BOOLEAN NOT NULL DEFAULT FALSE,
    incident_id BIGINT
);
CREATE INDEX IF NOT EXISTS idx_security_event_asset_time
    ON security_events(asset, occurred_at);
CREATE INDEX IF NOT EXISTS idx_security_event_processing
    ON security_events(processed, published);

-- ─────────────────────────────────────────────────────────────────────
-- Module 3: Network Analysis & IDS
-- ─────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS network_traffic (
    traffic_id       BIGSERIAL    PRIMARY KEY,
    source_ip        VARCHAR(45)  NOT NULL,
    destination_ip   VARCHAR(45)  NOT NULL,
    source_port      INTEGER,
    destination_port INTEGER,
    protocol         VARCHAR(20)  NOT NULL,
    packet_size      INTEGER,
    flags            VARCHAR(50),
    ttl              INTEGER,
    payload_preview  VARCHAR(500),
    interface_name   VARCHAR(50),
    timestamp        TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_traffic_ts       ON network_traffic(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_traffic_src_ip   ON network_traffic(source_ip);
CREATE INDEX IF NOT EXISTS idx_traffic_protocol ON network_traffic(protocol);

CREATE TABLE IF NOT EXISTS ids_rules (
    rule_id          SERIAL       PRIMARY KEY,
    rule_name        VARCHAR(200) NOT NULL UNIQUE,
    rule_content     TEXT         NOT NULL,
    rule_type        VARCHAR(20)  NOT NULL CHECK (rule_type IN ('snort','suricata','custom')),
    severity         INTEGER      NOT NULL CHECK (severity BETWEEN 1 AND 4),
    is_active        BOOLEAN      NOT NULL DEFAULT TRUE,
    source_ip_pattern  VARCHAR(100),
    dest_ip_pattern    VARCHAR(100),
    port_pattern       VARCHAR(50),
    protocol_pattern   VARCHAR(20),
    payload_pattern    VARCHAR(500),
    match_count      BIGINT       NOT NULL DEFAULT 0,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);

DELETE FROM ids_rules a
USING ids_rules b
WHERE a.rule_id > b.rule_id
  AND a.rule_name = b.rule_name;

CREATE UNIQUE INDEX IF NOT EXISTS ux_ids_rule_name ON ids_rules(rule_name);

CREATE TABLE IF NOT EXISTS network_alerts (
    alert_id         BIGSERIAL    PRIMARY KEY,
    rule_id          INTEGER      REFERENCES ids_rules(rule_id) ON DELETE SET NULL,
    source_ip        VARCHAR(45)  NOT NULL,
    destination_ip   VARCHAR(45)  NOT NULL,
    source_port      INTEGER,
    destination_port INTEGER,
    severity         VARCHAR(20)  NOT NULL CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    timestamp        TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status           VARCHAR(20)  NOT NULL DEFAULT 'new'
                                  CHECK (status IN ('new','investigating','acknowledged','resolved','false_positive')),
    alert_message    VARCHAR(1000),
    protocol         VARCHAR(20),
    packet_data      TEXT,
    alert_type       VARCHAR(50)  DEFAULT 'IDS'
);
CREATE INDEX IF NOT EXISTS idx_alert_ts       ON network_alerts(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alert_severity ON network_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alert_status   ON network_alerts(status);

-- ─────────────────────────────────────────────────────────────────────
-- Module 4: Vulnerability Assessment
-- ─────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS vulnerability_scans (
    scan_id      SERIAL       PRIMARY KEY,
    scan_name    VARCHAR(200) NOT NULL,
    scan_type    VARCHAR(20)  NOT NULL CHECK (scan_type IN ('network','web','host','full','port')),
    targets      VARCHAR(500),
    initiated_by INTEGER      REFERENCES users(user_id),
    scan_status  VARCHAR(20)  NOT NULL DEFAULT 'pending'
                              CHECK (scan_status IN ('pending','running','completed','failed','stopped')),
    start_time   TIMESTAMPTZ,
    end_time     TIMESTAMPTZ,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS vulnerability_findings (
    finding_id         BIGSERIAL    PRIMARY KEY,
    scan_id            INTEGER      REFERENCES vulnerability_scans(scan_id),
    host_ip            VARCHAR(45)  NOT NULL,
    cve_id             VARCHAR(20),
    vulnerability_name VARCHAR(500) NOT NULL,
    severity           VARCHAR(20)  NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
    status             VARCHAR(20)  NOT NULL DEFAULT 'open'
                                   CHECK (status IN ('open','in_progress','patched','accepted_risk')),
    description        TEXT,
    remediation        TEXT,
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS cve_records (
    cve_id           VARCHAR(20)  PRIMARY KEY,
    description      TEXT,
    published_date   DATE,
    cvss_score       DECIMAL(3,1),
    reference_links  TEXT[]
);

-- ─────────────────────────────────────────────────────────────────────
-- Module 5: Malware Detection & File Integrity
-- ─────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS malware_scans (
    scan_id               BIGSERIAL    PRIMARY KEY,
    file_path             TEXT         NOT NULL,
    file_name             VARCHAR(500) NOT NULL,
    file_hash             VARCHAR(64),
    file_size             BIGINT,
    scan_engine           VARCHAR(100) NOT NULL,
    scan_result           VARCHAR(20)  NOT NULL CHECK (scan_result IN ('clean','infected','suspicious','error')),
    threat_name           VARCHAR(500),
    yara_rule_matched     VARCHAR(200),
    virustotal_positives  INTEGER,
    virustotal_total      INTEGER,
    quarantined           BOOLEAN      NOT NULL DEFAULT FALSE,
    quarantine_path       TEXT,
    scan_time             TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_malware_hash   ON malware_scans(file_hash);
CREATE INDEX IF NOT EXISTS idx_malware_result ON malware_scans(scan_result);

CREATE TABLE IF NOT EXISTS yara_rules (
    rule_id      SERIAL       PRIMARY KEY,
    rule_name    VARCHAR(200) NOT NULL,
    rule_content TEXT         NOT NULL,
    is_active    BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS virustotal_results (
    result_id    BIGSERIAL    PRIMARY KEY,
    file_hash    VARCHAR(64)  NOT NULL,
    scan_date    TIMESTAMPTZ,
    positives    INTEGER,
    total_scans  INTEGER,
    scan_results JSONB,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ─────────────────────────────────────────────────────────────────────
-- Module 6: Incident Management
-- ─────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS incidents (
    incident_id     SERIAL       PRIMARY KEY,
    incident_number VARCHAR(50)  UNIQUE NOT NULL,
    title           VARCHAR(500) NOT NULL,
    description     TEXT,
    severity        VARCHAR(20)  NOT NULL CHECK (severity IN ('critical','high','medium','low')),
    status          VARCHAR(20)  NOT NULL DEFAULT 'open'
                                 CHECK (status IN ('open','investigating','contained','resolved','closed')),
    created_by      INTEGER      REFERENCES users(user_id),
    assigned_to     VARCHAR(100),
    source_alert_id BIGINT,
    affected_assets VARCHAR(500),
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at     TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_incident_status   ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incident_severity ON incidents(severity);

CREATE TABLE IF NOT EXISTS incident_timeline (
    timeline_id  BIGSERIAL    PRIMARY KEY,
    incident_id  INTEGER      NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    action_type  VARCHAR(20)  NOT NULL CHECK (action_type IN ('created','updated','note','escalated','contained','resolved')),
    description  TEXT         NOT NULL,
    performed_by INTEGER      REFERENCES users(user_id),
    timestamp    TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS incident_attachments (
    attachment_id SERIAL       PRIMARY KEY,
    incident_id   INTEGER      NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    file_name     VARCHAR(500) NOT NULL,
    file_path     TEXT         NOT NULL,
    uploaded_by   INTEGER      REFERENCES users(user_id),
    uploaded_at   TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ─────────────────────────────────────────────────────────────────────
-- Module 7: Honeypots & Rules Engine
-- ─────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS honeypots (
    honeypot_id   SERIAL       PRIMARY KEY,
    honeypot_name VARCHAR(200) NOT NULL,
    honeypot_type VARCHAR(20)  NOT NULL CHECK (honeypot_type IN ('ssh','http','ftp','smtp','telnet','rdp')),
    ip_address    VARCHAR(45)  NOT NULL,
    port          INTEGER      NOT NULL,
    is_active     BOOLEAN      NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS honeypot_interactions (
    interaction_id BIGSERIAL    PRIMARY KEY,
    honeypot_id    INTEGER      REFERENCES honeypots(honeypot_id),
    attacker_ip    VARCHAR(45)  NOT NULL,
    timestamp      TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    data           TEXT
);

CREATE TABLE IF NOT EXISTS deception_rules (
    rule_id     SERIAL       PRIMARY KEY,
    rule_name   VARCHAR(200) NOT NULL,
    condition   JSONB        NOT NULL,
    action      JSONB        NOT NULL,
    is_active   BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS attacker_profiles (
    profile_id   SERIAL       PRIMARY KEY,
    attacker_ip  VARCHAR(45)  NOT NULL UNIQUE,
    first_seen   TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen    TIMESTAMPTZ,
    threat_level VARCHAR(20)  NOT NULL DEFAULT 'low'
                              CHECK (threat_level IN ('low','medium','high','critical'))
);

-- ─────────────────────────────────────────────────────────────────────
-- Module 8: Alert Notification & Report Generation
-- ─────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS notifications (
    notification_id   BIGSERIAL    PRIMARY KEY,
    recipient_id      INTEGER      REFERENCES users(user_id),
    notification_type VARCHAR(20)  NOT NULL CHECK (notification_type IN ('alert','incident','report','system')),
    title             VARCHAR(500) NOT NULL,
    message           TEXT,
    channel           VARCHAR(20)  NOT NULL CHECK (channel IN ('email','sms','websocket','slack')),
    priority          VARCHAR(20)  NOT NULL DEFAULT 'medium' CHECK (priority IN ('low','medium','high','critical')),
    status            VARCHAR(20)  NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','sent','failed','read')),
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    sent_at           TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS report_templates (
    template_id   SERIAL       PRIMARY KEY,
    name          VARCHAR(200) NOT NULL,
    report_type   VARCHAR(20)  NOT NULL CHECK (report_type IN ('security','compliance','executive','incident','vulnerability')),
    template      JSONB        NOT NULL,
    parameters    JSONB,
    output_format VARCHAR(10)  NOT NULL DEFAULT 'pdf' CHECK (output_format IN ('pdf','html','csv','json')),
    is_active     BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS generated_reports (
    report_id    BIGSERIAL    PRIMARY KEY,
    template_id  INTEGER      REFERENCES report_templates(template_id),
    generated_by INTEGER      REFERENCES users(user_id),
    parameters   JSONB,
    file_path    TEXT,
    file_size    BIGINT,
    status       VARCHAR(20)  NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','generating','completed','failed')),
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Windows Event Logs
CREATE TABLE IF NOT EXISTS windows_event_logs (
    log_id              BIGSERIAL    PRIMARY KEY,
    event_id            BIGINT       NOT NULL,
    channel             VARCHAR(100) NOT NULL,
    level               VARCHAR(20)  NOT NULL,
    source              VARCHAR(200) NOT NULL,
    computer_name       VARCHAR(200),
    user_name           VARCHAR(200),
    event_time          TIMESTAMPTZ  NOT NULL,
    message             TEXT,
    raw_xml             TEXT,
    is_security_relevant BOOLEAN     NOT NULL DEFAULT FALSE,
    alert_generated     BOOLEAN      NOT NULL DEFAULT FALSE,
    ingested_at         TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_winevent_time     ON windows_event_logs(event_time DESC);
CREATE INDEX IF NOT EXISTS idx_winevent_id       ON windows_event_logs(event_id);
CREATE INDEX IF NOT EXISTS idx_winevent_channel  ON windows_event_logs(channel);
CREATE INDEX IF NOT EXISTS idx_winevent_security ON windows_event_logs(is_security_relevant) WHERE is_security_relevant = TRUE;

-- ─────────────────────────────────────────────────────────────────────
-- Accounts and structured IDS rules are initialized by the application.
-- Enable the one-time bootstrap with a unique password in the local environment.
