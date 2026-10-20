package com.ghostnet.config;
import org.springframework.boot.*;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.init.ScriptUtils;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;
import lombok.RequiredArgsConstructor;
@Component @Order(-100) @RequiredArgsConstructor
public class SchemaCompatibilityMigration implements ApplicationRunner {
    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    @Override public void run(ApplicationArguments args) {
        tx.executeWithoutResult(status->{
            jdbc.execute("create table if not exists ghostnet_schema_history(version integer primary key, applied_at timestamp with time zone default current_timestamp)");
            jdbc.query("select pg_advisory_xact_lock(74320118)",rs->{});
            var scripts=java.util.Map.of(
                2,"V002__runtime_compatibility.sql",
                3,"V003__detection_defaults.sql",
                4,"V004__vulnerability_scan_errors.sql");
            for(int version:java.util.List.of(2,3,4)) {
                if(Boolean.TRUE.equals(jdbc.queryForObject("select exists(select 1 from ghostnet_schema_history where version=?)",Boolean.class,version))) continue;
                jdbc.execute((org.springframework.jdbc.core.ConnectionCallback<Void>)connection->{
                    ScriptUtils.executeSqlScript(connection,new ClassPathResource("db/migrations/"+scripts.get(version)));return null;
                });
                jdbc.update("insert into ghostnet_schema_history(version) values(?)",version);
            }
        });
    }
}
