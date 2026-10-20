package com.ghostnet.service;
import com.ghostnet.model.*;
import com.ghostnet.repository.*;
import com.ghostnet.websocket.AlertBroadcaster;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.data.domain.PageRequest;
import java.time.*;
import java.net.*;
import java.net.http.*;
import java.util.*;
import com.fasterxml.jackson.databind.ObjectMapper;
@Service
public class TrafficMlWorker {
    private final SecurityEventRepository events;
    private final SecurityEventPipeline pipeline;
    private final NetworkAlertsRepository alerts;
    private final TransactionTemplate tx;
    private final AlertBroadcaster broadcaster;
    @Value("${python.anomaly.enabled:false}") private boolean enabled;
    @Value("${python.malware.base-url:http://127.0.0.1:5000}") private String base;
    @Value("${python.api-key:}") private String key;
    private final ObjectMapper json=new ObjectMapper().findAndRegisterModules();
    private final HttpClient client=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
    private volatile String lastError="";
    private volatile Instant retryAfter=Instant.EPOCH;

    public TrafficMlWorker(SecurityEventRepository events, SecurityEventPipeline pipeline,
            NetworkAlertsRepository alerts, TransactionTemplate tx, AlertBroadcaster broadcaster) {
        this.events = events;
        this.pipeline = pipeline;
        this.alerts = alerts;
        this.tx = tx;
        this.broadcaster = broadcaster;
    }

    public String getLastError() { return lastError; }
    @Scheduled(fixedDelay=1000) public synchronized void analyze() {
        if(!enabled || Instant.now().isBefore(retryAfter)) return;
        for(var batch:events.findBySourceAndAnalyzedFalseOrderByReceivedAtAsc("capture",PageRequest.of(0,10))) {
            try {
                var request=HttpRequest.newBuilder(URI.create(base+"/api/traffic/analyze")).timeout(Duration.ofSeconds(10))
                    .header("X-API-Key",key).header("Content-Type","application/json").POST(HttpRequest.BodyPublishers.ofString(batch.getEvidence())).build();
                var response=client.send(request,HttpResponse.BodyHandlers.ofString());
                if(response.statusCode()!=200) throw new IllegalStateException("Traffic model HTTP "+response.statusCode());
                var results=json.readTree(response.body()).path("results");
                var input=json.readTree(batch.getEvidence()).path("records");
                if(!results.isArray() || results.size()!=input.size()) throw new IllegalStateException("Invalid traffic model response");
                tx.executeWithoutResult(status->{
                    var locked=events.lock(batch.getEventId()).orElseThrow();if(locked.isAnalyzed()) return;
                    for(int i=0;i<results.size();i++) if(results.get(i).path("anomaly").asBoolean(false)) {
                        var row=input.get(i);String actor=row.path("sourceIp").asText(),asset=row.path("destinationIp").asText();
                        var alert=alerts.save(NetworkAlert.builder().sourceIp(actor).destinationIp(asset).severity("HIGH").status("new")
                            .alertType("ANOMALY").timestamp(batch.getOccurredAt()).alertMessage("Model detected anomalous traffic: "+results.get(i)).build());
                        pipeline.record("ml:"+batch.getEventId()+":"+i,"anomaly",asset,actor,"high",alert.getAlertMessage(),batch.getOccurredAt());
                        broadcaster.broadcastAlert(alert);
                    }
                    locked.setAnalyzed(true);
                });lastError="";
            } catch(Exception ex) {lastError=ex.getMessage();retryAfter=Instant.now().plusSeconds(30);return;}
        }
    }
}
