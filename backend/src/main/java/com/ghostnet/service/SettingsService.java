package com.ghostnet.service;
import com.ghostnet.model.OperationalSettings;
import com.ghostnet.repository.OperationalSettingsRepository;
import org.springframework.stereotype.Service;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.jdbc.core.JdbcTemplate;
import lombok.RequiredArgsConstructor;
import java.time.ZonedDateTime;
@Service @RequiredArgsConstructor
public class SettingsService {
    private final OperationalSettingsRepository settings;
    private final JdbcTemplate jdbc;
    public OperationalSettings get() { return settings.findById(1L).orElseGet(OperationalSettings::new); }
    @Transactional public OperationalSettings save(int threshold,int days,boolean retention,String user) {
        if(threshold<50 || threshold>100 || days<1 || days>3650) throw new IllegalArgumentException("Threshold must be 50..100 and retention days 1..3650");
        var value=get();value.setCriticalThreshold(threshold);value.setRetentionHotDays(days);value.setRetentionEnabled(retention);value.setUpdatedBy(user);value.setUpdatedAt(ZonedDateTime.now());return settings.save(value);
    }
    @Scheduled(fixedDelay=3600000) @Transactional public void retention() {
        var value=get();if(!value.isRetentionEnabled()) return;
        var since=java.sql.Timestamp.from(ZonedDateTime.now().minusDays(value.getRetentionHotDays()).toInstant());
        // Security evidence and incident timelines are retained. This policy covers raw telemetry only.
        jdbc.update("delete from network_traffic where timestamp < ?",since);
        jdbc.update("delete from windows_event_logs where event_time < ? and alert_generated = false",since);
        jdbc.update("delete from user_sessions where expires_at < ?",java.sql.Timestamp.from(java.time.Instant.now()));
    }
}
