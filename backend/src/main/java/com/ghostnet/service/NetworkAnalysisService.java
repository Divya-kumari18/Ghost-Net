package com.ghostnet.service;

import com.ghostnet.capture.IdsRuleEngine;
import com.ghostnet.model.IdsRule;
import com.ghostnet.model.NetworkAlert;
import com.ghostnet.model.NetworkTraffic;
import com.ghostnet.repository.IdsRuleRepository;
import com.ghostnet.repository.NetworkAlertsRepository;
import com.ghostnet.repository.NetworkTrafficRepository;
import com.ghostnet.websocket.AlertBroadcaster;

import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.ZonedDateTime;
import java.util.*;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicLong;

@Slf4j
@Service
public class NetworkAnalysisService {

    private final NetworkTrafficRepository trafficRepo;
    private final NetworkAlertsRepository alertRepo;
    private final IdsRuleRepository ruleRepo;
    private final IdsRuleEngine ruleEngine;
    private final AlertBroadcaster broadcaster;
    private final SecurityEventPipeline pipeline;
    private final org.springframework.transaction.support.TransactionTemplate tx;

    // Async queue to avoid blocking the capture thread
    private final BlockingQueue<NetworkTraffic> trafficQueue = new LinkedBlockingQueue<>(10_000);
    private final AtomicLong droppedPackets = new AtomicLong(0);
    private final AtomicLong processedPackets = new AtomicLong(0);
    private final AtomicLong generatedAlerts = new AtomicLong(0);

    public NetworkAnalysisService(
            NetworkTrafficRepository trafficRepo,
            NetworkAlertsRepository alertRepo,
            IdsRuleRepository ruleRepo,
            IdsRuleEngine ruleEngine,
            AlertBroadcaster broadcaster,
            SecurityEventPipeline pipeline,
            org.springframework.transaction.support.TransactionTemplate tx) {
        this.trafficRepo = trafficRepo;
        this.alertRepo = alertRepo;
        this.ruleRepo = ruleRepo;
        this.ruleEngine = ruleEngine;
        this.broadcaster = broadcaster;
        this.pipeline = pipeline;
        this.tx = tx;
    }

    /**
     * Called by PacketCaptureEngine for every captured packet.
     * Non-blocking: queues the packet for async processing.
     */
    public void processTraffic(NetworkTraffic traffic) {
        if (!trafficQueue.offer(traffic)) {
            droppedPackets.incrementAndGet();
        }
    }

    /**
     * Background processor: drains the queue and persists + analyzes traffic.
     */
    private final java.util.concurrent.atomic.AtomicBoolean draining = new java.util.concurrent.atomic.AtomicBoolean();
    private List<NetworkTraffic> retryBatch = List.of();
    private List<NetworkAlert> retryAlerts;
    public void drainQueue() {
        if (!draining.compareAndSet(false,true)) return;
        try {
            List<NetworkTraffic> batch = new ArrayList<>(retryBatch);
            if (batch.isEmpty()) trafficQueue.drainTo(batch, 1000);
            if (batch.isEmpty()) return;
            retryBatch = batch;
            if(retryAlerts==null) {
                retryAlerts=new ArrayList<>();
                for(var traffic:batch) retryAlerts.addAll(ruleEngine.match(traffic));
            }
            List<NetworkAlert> alerts = retryAlerts;
            tx.executeWithoutResult(status -> {
                trafficRepo.saveAllAndFlush(batch);
                List<Map<String,Object>> records=new ArrayList<>();
                for(var t:batch) {
                    Map<String,Object> record=new LinkedHashMap<>();
                    record.put("sourceIp",t.getSourceIp());record.put("destinationIp",t.getDestinationIp());
                    record.put("packet_size",t.getPacketSize()==null?0:t.getPacketSize());
                    record.put("source_port",t.getSourcePort()==null?0:t.getSourcePort());
                    record.put("destination_port",t.getDestinationPort()==null?0:t.getDestinationPort());
                    record.put("ttl",t.getTtl()==null?0:t.getTtl());record.put("protocol_id","TCP".equals(t.getProtocol())?6:"UDP".equals(t.getProtocol())?17:1);
                    records.add(record);
                }
                try { pipeline.record("capture:"+batch.getFirst().getTrafficId()+":"+batch.getLast().getTrafficId(),"capture","127.0.0.1",null,"low",
                    new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(Map.of("records",records)),batch.getLast().getTimestamp()); }
                catch(com.fasterxml.jackson.core.JsonProcessingException ex) {throw new IllegalStateException(ex);}
                alertRepo.saveAllAndFlush(alerts);
                alerts.stream().filter(a->a.getRule()!=null).collect(java.util.stream.Collectors.groupingBy(a->a.getRule().getRuleId(),java.util.stream.Collectors.counting()))
                    .forEach(ruleRepo::incrementMatches);
                for (var alert : alerts) pipeline.record("network:"+alert.getAlertId(), "network", alert.getDestinationIp(),
                    alert.getSourceIp(), alert.getSeverity(), alert.getAlertMessage(), alert.getTimestamp());
            });
            retryBatch = List.of();
            retryAlerts = null;
            processedPackets.addAndGet(batch.size()); generatedAlerts.addAndGet(alerts.size());
            batch.forEach(broadcaster::broadcastTraffic);
            alerts.forEach(broadcaster::broadcastAlert);
        } catch (Exception ex) {
            log.error("Traffic batch failed; retained for retry", ex);
            // IDs generated in a rolled-back transaction must not be reused on retry.
            retryBatch.forEach(t -> t.setTrafficId(null));
            if(retryAlerts!=null) retryAlerts.forEach(a->a.setAlertId(null));
        } finally { draining.set(false); }
    }

    // ─── Query methods ──────────────────────────────────────────────

    @Transactional(readOnly = true)
    public Page<NetworkTraffic> getRecentTraffic(int page, int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by("timestamp").descending());
        return trafficRepo.findAll(pageable);
    }

    @Transactional(readOnly = true)
    public Page<NetworkAlert> getAlerts(String status, int page, int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by("timestamp").descending());
        if (status != null && !status.isBlank()) {
            return alertRepo.findByStatusOrderByTimestampDesc(status, pageable);
        }
        return alertRepo.findAll(pageable);
    }

    @Transactional(readOnly = true)
    public Map<String, Object> getAlertStats() {
        ZonedDateTime last24h = ZonedDateTime.now().minusHours(24);
        ZonedDateTime last1h  = ZonedDateTime.now().minusHours(1);

        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("totalAlerts24h",    alertRepo.countActiveSince(last24h));
        stats.put("criticalAlerts1h",  alertRepo.countBySeveritySince("CRITICAL", last1h));
        stats.put("highAlerts24h",     alertRepo.countBySeveritySince("HIGH", last24h));
        stats.put("packetCount24h",    trafficRepo.countSince(last24h));
        stats.put("droppedPackets",    droppedPackets.get());
        stats.put("queueSize",         trafficQueue.size());
        stats.put("processedPacketsRuntime", processedPackets.get());
        stats.put("generatedAlertsRuntime", generatedAlerts.get());

        // Severity breakdown
        List<Object[]> sevRows = alertRepo.severityStats(last24h);
        Map<String, Long> sevMap = new LinkedHashMap<>();
        for (Object[] row : sevRows) {
            sevMap.put((String) row[0], (Long) row[1]);
        }
        stats.put("bySeverity", sevMap);

        // Protocol stats
        List<Object[]> protoRows = trafficRepo.protocolStats(last24h);
        Map<String, Long> protoMap = new LinkedHashMap<>();
        for (Object[] row : protoRows) {
            protoMap.put((String) row[0], (Long) row[1]);
        }
        stats.put("byProtocol", protoMap);

        // Top source IPs
        List<Object[]> topIps = trafficRepo.topSourceIps(last24h, PageRequest.of(0, 10));
        List<Map<String, Object>> ipList = new ArrayList<>();
        for (Object[] row : topIps) {
            ipList.add(Map.of("ip", row[0], "count", row[1]));
        }
        stats.put("topSourceIps", ipList);

        return stats;
    }

    @Transactional
    public NetworkAlert updateAlertStatus(Long alertId, String status) {
        if (!Set.of("new","investigating","acknowledged","resolved","false_positive").contains(status)) throw new IllegalArgumentException("Invalid alert status");
        alertRepo.updateStatus(alertId, status);
        return alertRepo.findById(alertId).orElseThrow();
    }

    @Transactional(readOnly = true)
    public List<IdsRule> getAllRules() {
        return ruleRepo.findAll();
    }

    @Transactional
    public IdsRule createRule(IdsRule rule) {
        IdsRuleEngine.validateRule(rule);
        IdsRule saved = ruleRepo.save(rule);
        ruleEngine.reloadRules();
        return saved;
    }

    @Transactional
    public void deleteRule(Long ruleId) {
        ruleRepo.deleteById(ruleId);
        ruleEngine.reloadRules();
    }

    @Transactional
    public IdsRule toggleRule(Long ruleId, boolean active) {
        IdsRule rule = ruleRepo.findById(ruleId).orElseThrow();
        rule.setActive(active);
        IdsRuleEngine.validateRule(rule);
        IdsRule saved = ruleRepo.save(rule);
        ruleEngine.reloadRules();
        return saved;
    }
}
