package com.ghostnet.service;
import com.ghostnet.model.OperationalJob;
import com.ghostnet.repository.*;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.transaction.support.TransactionTemplate;
import java.time.ZonedDateTime;
import java.util.*;
import com.fasterxml.jackson.databind.ObjectMapper;
@Service
public class OperationalJobService {
    private final OperationalJobRepository jobs;
    private final NetworkAlertsRepository alerts;
    private final IncidentRepository incidents;
    private final VulnerabilityFindingRepository findings;
    private final MalwareDetectionService malware;
    private final VulnerabilityAssessmentService vulnerability;
    private final TransactionTemplate tx;
    private final ObjectMapper json=new ObjectMapper().findAndRegisterModules();

    public OperationalJobService(OperationalJobRepository jobs, NetworkAlertsRepository alerts,
            IncidentRepository incidents, VulnerabilityFindingRepository findings,
            MalwareDetectionService malware, VulnerabilityAssessmentService vulnerability,
            TransactionTemplate tx) {
        this.jobs = jobs;
        this.alerts = alerts;
        this.incidents = incidents;
        this.findings = findings;
        this.malware = malware;
        this.vulnerability = vulnerability;
        this.tx = tx;
    }

    public OperationalJob create(String name,String type,String target,long interval,String user) {
        if(name==null || name.isBlank() || !Set.of("report","network","malware").contains(type) || interval<300 || interval>2678400)
            throw new IllegalArgumentException("Valid name/type and interval 300..2678400 seconds required");
        if(!type.equals("report") && (target==null || target.isBlank())) throw new IllegalArgumentException("Target required");
        return jobs.save(OperationalJob.builder().jobId(UUID.randomUUID().toString()).name(name).type(type).target(target)
            .intervalSeconds(interval).createdBy(user).enabled(true).nextRun(ZonedDateTime.now().plusSeconds(interval)).lastStatus("scheduled").build());
    }
    @Scheduled(fixedDelay=5000) public synchronized void runDue() {
        for(var candidate:jobs.findByEnabledTrueAndNextRunBefore(ZonedDateTime.now())) {
            var claimed=tx.execute(status->{
                var j=jobs.lock(candidate.getJobId()).orElseThrow();
                if(!j.isEnabled() || j.getNextRun().isAfter(ZonedDateTime.now())) return null;
                j.setNextRun(ZonedDateTime.now().plusSeconds(j.getIntervalSeconds()));j.setLastRun(ZonedDateTime.now());j.setLastStatus("running");return j;
            });
            if(claimed==null) continue;
            try {
                String output;
                if("report".equals(claimed.getType())) output=json.writeValueAsString(Map.of("generatedAt",ZonedDateTime.now(),"alerts",alerts.count(),"openIncidents",incidents.countOpenIncidents(),"vulnerabilities",findings.count()));
                else if("malware".equals(claimed.getType())) output=json.writeValueAsString(malware.startFullSystemScan(claimed.getTarget()));
                else {
                    var scan=vulnerability.createScan(claimed.getName(),"network",claimed.getTarget(),claimed.getCreatedBy());
                    vulnerability.runNmapScan(scan.getScanId(),claimed.getTarget());output=json.writeValueAsString(Map.of("scanId",scan.getScanId()));
                }
                tx.executeWithoutResult(status->jobs.lock(claimed.getJobId()).ifPresent(j->{j.setOutput(output);j.setLastStatus("report".equals(j.getType())?"completed":"dispatched");j.setLastError(null);}));
            } catch(Exception ex) { tx.executeWithoutResult(status->jobs.lock(claimed.getJobId()).ifPresent(j->{j.setLastStatus("failed");j.setLastError(ex.getMessage());})); }
        }
    }
}
