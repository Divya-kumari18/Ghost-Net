package com.ghostnet.capture;

import com.ghostnet.model.IdsRule;
import com.ghostnet.model.NetworkAlert;
import com.ghostnet.model.NetworkTraffic;
import com.ghostnet.repository.IdsRuleRepository;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * In-memory IDS Rule Engine.
 * Loads active rules from DB and matches each captured packet against them.
 * Rules are hot-reloaded every 60 seconds.
 */
@Slf4j
@Component
public class IdsRuleEngine {

    private final IdsRuleRepository ruleRepository;

    // In-memory rule cache with compiled patterns
    private volatile List<CompiledRule> compiledRules = List.of();

    public IdsRuleEngine(IdsRuleRepository ruleRepository) {
        this.ruleRepository = ruleRepository;
    }

    @PostConstruct
    public void loadRules() {
        reloadRules();
        log.info("IDS Rule Engine ready with {} active rules.", compiledRules.size());
    }

    @Scheduled(fixedDelay = 60_000)
    public void reloadRules() {
        List<IdsRule> activeRules = ruleRepository.findByActiveTrue();
        List<CompiledRule> freshList = new ArrayList<>();
        for (IdsRule rule : activeRules) {
            try {
                validateRule(rule);
                freshList.add(new CompiledRule(rule));
            } catch (Exception e) {
                log.warn("Failed to compile rule '{}': {}", rule.getRuleName(), e.getMessage());
            }
        }
        compiledRules = List.copyOf(freshList);
        log.debug("IDS rules reloaded: {} active rules.", compiledRules.size());
    }

    /**
     * Match a traffic record against all active IDS rules.
     * Returns a list of triggered alerts (one per matching rule).
     */
    public List<NetworkAlert> match(NetworkTraffic traffic) {
        List<NetworkAlert> alerts = new ArrayList<>();
        for (CompiledRule cr : compiledRules) {
            if (matches(cr, traffic) && threshold(cr.rule,traffic)) {
                alerts.add(buildAlert(cr.rule, traffic));
            }
        }
        return alerts;
    }

    private boolean matches(CompiledRule cr, NetworkTraffic t) {
        // Source IP check
        if (cr.sourceIpPattern != null) {
            if (t.getSourceIp() == null || !cr.sourceIpPattern.matcher(t.getSourceIp()).matches()) return false;
        }
        // Destination IP check
        if (cr.destIpPattern != null) {
            if (t.getDestinationIp() == null || !cr.destIpPattern.matcher(t.getDestinationIp()).matches()) return false;
        }
        // Protocol check
        if (cr.protocolPattern != null) {
            if (t.getProtocol() == null || !cr.protocolPattern.matcher(t.getProtocol()).matches()) return false;
        }
        // Port check (destination port)
        if (cr.rule.getPortPattern() != null && !cr.rule.getPortPattern().isBlank()) {
            if (!matchesPort(cr.rule.getPortPattern(), t.getDestinationPort())) return false;
        }
        // Payload check
        if (cr.payloadPattern != null) {
            String payload = t.getDetectionPayload() != null ? t.getDetectionPayload() : t.getPayloadPreview();
            if (payload == null || !cr.payloadPattern.matcher(payload).find()) return false;
        }
        return true;
    }

    private boolean matchesPort(String portPattern, Integer port) {
        if (port == null) return false;
        if (portPattern.equalsIgnoreCase("any")) return true;
        for (String segment : portPattern.split(",")) {
            String[] ends = segment.trim().split("-");
            int lo = Integer.parseInt(ends[0].trim());
            int hi = ends.length == 2 ? Integer.parseInt(ends[1].trim()) : lo;
            if (port >= lo && port <= hi) return true;
        }
        return false;
    }

    private final java.util.Map<String,java.util.ArrayDeque<Observation>> windows=new java.util.concurrent.ConcurrentHashMap<>();
    private record Observation(long time,Integer port) {}
    private boolean threshold(IdsRule rule,NetworkTraffic traffic) {
        if(rule.getThresholdCount()<=1) return true;
        if("TCP".equalsIgnoreCase(traffic.getProtocol()) && (traffic.getFlags()==null || !traffic.getFlags().contains("SYN") || traffic.getFlags().contains("ACK"))) return false;
        long now=traffic.getTimestamp()==null?System.currentTimeMillis():traffic.getTimestamp().toInstant().toEpochMilli();
        String key=rule.getRuleId()+":"+rule.getRuleName()+":"+traffic.getSourceIp()+":"+traffic.getDestinationIp();
        if(windows.size()>10000) windows.entrySet().removeIf(e->{synchronized(e.getValue()) {return e.getValue().isEmpty() || e.getValue().getLast().time()<now-3600000;}});
        if(windows.size()>20000) return false;
        var queue=windows.computeIfAbsent(key,k->new java.util.ArrayDeque<>());
        synchronized(queue) {
            while(!queue.isEmpty() && queue.getFirst().time()<now-rule.getWindowSeconds()*1000L) queue.removeFirst();
            if(rule.isDistinctPorts()) queue.removeIf(o->java.util.Objects.equals(o.port(),traffic.getDestinationPort()));
            queue.addLast(new Observation(now,traffic.getDestinationPort()));
            long count=rule.isDistinctPorts()?queue.stream().map(Observation::port).distinct().count():queue.size();
            if(count<rule.getThresholdCount()) return false;
            queue.clear();return true;
        }
    }
    private NetworkAlert buildAlert(IdsRule rule, NetworkTraffic traffic) {
        String severity = mapSeverity(rule.getSeverity());
        return NetworkAlert.builder()
                .rule(rule)
                .sourceIp(traffic.getSourceIp())
                .destinationIp(traffic.getDestinationIp())
                .sourcePort(traffic.getSourcePort())
                .destinationPort(traffic.getDestinationPort())
                .protocol(traffic.getProtocol())
                .severity(severity)
                .timestamp(ZonedDateTime.now())
                .status("new")
                .alertType("IDS")
                .alertMessage(String.format("[%s] Rule '%s' triggered: %s -> %s:%s",
                        severity,
                        rule.getRuleName(),
                        traffic.getSourceIp(),
                        traffic.getDestinationIp(),
                        Optional.ofNullable(traffic.getDestinationPort()).map(String::valueOf).orElse("?")
                ))
                .packetData(traffic.getPayloadPreview())
                .build();
    }

    private String mapSeverity(int level) {
        return switch (level) {
            case 4  -> "CRITICAL";
            case 3  -> "HIGH";
            case 2  -> "MEDIUM";
            default -> "LOW";
        };
    }

    public int getRuleCount() { return compiledRules.size(); }

    // ─── Inner helper: compiled rule ────────────────────────────────
    private static class CompiledRule {
        final IdsRule rule;
        final Pattern sourceIpPattern;
        final Pattern destIpPattern;
        final Pattern protocolPattern;
        final Pattern payloadPattern;

        CompiledRule(IdsRule rule) {
            this.rule = rule;
            this.sourceIpPattern  = compileIp(rule.getSourceIpPattern());
            this.destIpPattern    = compileIp(rule.getDestIpPattern());
            this.protocolPattern  = compile(rule.getProtocolPattern());
            this.payloadPattern   = compile(rule.getPayloadPattern());
        }

        private Pattern compileIp(String value) {
            if(value==null || value.isBlank() || value.equals(".*") || value.equals("*") || value.equalsIgnoreCase("any")) return null;
            if(value.startsWith("regex:")) return compile(value.substring(6));
            if(value.contains("/")) throw new IllegalArgumentException("Use an IP glob or regex: expression; CIDR rules are not supported");
            StringBuilder regex=new StringBuilder();
            for(char ch:value.toCharArray()) regex.append(ch=='*'?".*":ch=='?'?".":Pattern.quote(String.valueOf(ch)));
            return Pattern.compile(regex.toString(),Pattern.CASE_INSENSITIVE);
        }
        private Pattern compile(String pattern) {
            if (pattern == null || pattern.isBlank() || pattern.equalsIgnoreCase("any") || pattern.equals(".*") || pattern.equals("*")) return null;
            if (pattern.length() > 1000) throw new IllegalArgumentException("Pattern too long");
            return Pattern.compile(pattern, Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
        }
    }
    public static void validateRule(IdsRule rule) {
        if(rule.getThresholdCount()<1 || rule.getThresholdCount()>10000 || rule.getWindowSeconds()<1 || rule.getWindowSeconds()>3600) throw new IllegalArgumentException("Invalid count/window");
        if (rule.getSeverity() < 1 || rule.getSeverity() > 4) throw new IllegalArgumentException("Severity must be 1..4");
        if (rule.getRuleType() != null && !rule.getRuleType().equalsIgnoreCase("custom"))
            throw new IllegalArgumentException("Only structured custom rules are supported; Snort syntax cannot be evaluated");
        if(rule.getRuleContent()!=null && rule.getRuleContent().trim().startsWith("alert "))
            throw new IllegalArgumentException("Snort text is not executable; use the structured rule fields");
        new CompiledRule(rule);
        String ports = rule.getPortPattern();
        if (ports != null && !ports.isBlank() && !ports.equalsIgnoreCase("any")) {
            for (String part : ports.split(",", -1)) {
                String[] ends = part.trim().split("-", -1);
                if (ends.length > 2) throw new IllegalArgumentException("Invalid port range");
                int lo = Integer.parseInt(ends[0]);
                int hi = ends.length == 2 ? Integer.parseInt(ends[1]) : lo;
                if (lo < 0 || hi > 65535 || lo > hi) throw new IllegalArgumentException("Invalid port range");
            }
        }
    }
}
