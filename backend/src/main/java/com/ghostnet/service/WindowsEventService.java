package com.ghostnet.service;

import com.ghostnet.model.*;
import com.ghostnet.repository.*;
import com.ghostnet.websocket.AlertBroadcaster;
import com.ghostnet.windows.WindowsEventCatalog;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.data.domain.*;
import java.time.ZonedDateTime;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class WindowsEventService {
    private final WindowsEventLogRepository eventRepo;
    private final NetworkAlertsRepository alertRepo;
    private final AlertBroadcaster broadcaster;
    private final SecurityEventPipeline pipeline;
    private final WindowsEventCatalog windowsEventCatalog;
    private final AtomicLong ingested=new AtomicLong();
    private final AtomicLong generated=new AtomicLong();
    private static final Set<Long> SECURITY_IDS=Set.of(4625L,4648L,4672L,4698L,4699L,4719L,4720L,4726L,4728L,4732L,4740L,7045L,4688L);
    private static final Set<Long> CRITICAL_IDS=Set.of(4719L,4720L,4726L,4740L,7045L,4698L);

    public WindowsEventService(WindowsEventLogRepository eventRepo,
                               NetworkAlertsRepository alertRepo,
                               AlertBroadcaster broadcaster,
                               SecurityEventPipeline pipeline,
                               WindowsEventCatalog windowsEventCatalog) {
        this.eventRepo = eventRepo;
        this.alertRepo = alertRepo;
        this.broadcaster = broadcaster;
        this.pipeline = pipeline;
        this.windowsEventCatalog = windowsEventCatalog;
    }

    @Transactional public void ingestEvents(List<WindowsEventLog> events) {
        if(events==null || events.isEmpty()) return;
        for(var event:events) {
            if(event.getIngestionKey()!=null && eventRepo.existsByIngestionKey(event.getIngestionKey())) continue;
            eventRepo.saveAndFlush(event);
            broadcaster.broadcastWindowsEvent(event);
            if(SECURITY_IDS.contains(event.getEventId())) {
                String severity=CRITICAL_IDS.contains(event.getEventId())?"CRITICAL":"HIGH";
                String alertText="Windows event "+event.getEventId()+" on "+event.getComputerName()+": "+event.getMessage();
                var alert=alertRepo.save(NetworkAlert.builder().sourceIp("127.0.0.1").destinationIp("127.0.0.1")
                    .severity(severity).timestamp(event.getEventTime()).status("new").alertType("WINDOWS_EVENT")
                    .alertMessage(alertText.substring(0,Math.min(1000,alertText.length()))).build());
                event.setAlertGenerated(true);
                pipeline.record("windows-alert:"+alert.getAlertId(),"windows","127.0.0.1",event.getUserName(),severity,alertText,event.getEventTime());
                broadcaster.broadcastAlert(alert); generated.incrementAndGet();
            }
            ingested.incrementAndGet();
        }
    }
    @Transactional(readOnly=true) public Page<WindowsEventLog> getEvents(String channel,String level,int page,int size) {
        var pageable=PageRequest.of(page,Math.min(size,1000),Sort.by("eventTime").descending());
        if(channel!=null&&!channel.isBlank()) return eventRepo.findByChannelOrderByEventTimeDesc(channel,pageable);
        if(level!=null&&!level.isBlank()) return eventRepo.findByLevelOrderByEventTimeDesc(level,pageable);
        return eventRepo.findAll(pageable);
    }
    @Transactional(readOnly=true) public Map<String,Object> getEventStats() {
        var day=ZonedDateTime.now().minusHours(24);
        var top=new ArrayList<Map<String,Object>>();
        for(var row:eventRepo.topEventIds(day,PageRequest.of(0,10))) top.add(Map.of("eventId",row[0],"count",row[1],"source",row[2],"channel",row[3],"name",windowsEventCatalog.find((Long)row[0],(String)row[2],(String)row[3]).map(WindowsEventCatalog.EventMeta::description).orElse(row[2]+" · Event "+row[0])));
        return Map.of("totalEvents24h",eventRepo.countSince(day),"securityEvents24h",eventRepo.countSecurityEventsSince(day),
            "securityEvents1h",eventRepo.countSecurityEventsSince(ZonedDateTime.now().minusHours(1)),"eventsIngestedRuntime",ingested.get(),"alertsGeneratedRuntime",generated.get(),"topEventIds",top);
    }
    @Transactional(readOnly=true) public List<WindowsEventLog> getRecentSecurityEvents(int limit) { return eventRepo.findBySecurityRelevantTrueOrderByEventTimeDesc(PageRequest.of(0,Math.min(limit,1000))); }
    public Map<String,Object> getEventCatalogEntry(long id) {
        return getEventCatalogEntry(id,null,null);
    }
    public Map<String,Object> getEventCatalogEntry(long id,String source,String channel) {
        Map<String,Object> result=new LinkedHashMap<>();result.put("eventId",id);
        var entry=source==null && channel==null ? windowsEventCatalog.find(id) : windowsEventCatalog.find(id,source,channel);
        entry.ifPresentOrElse(m->{result.put("known",true);result.put("description",m.description());result.put("source",m.sourceName());result.put("category",m.category());},()->{result.put("known",false);result.put("description",(source==null||source.isBlank()?"Windows":source)+" · Event "+id);});
        return result;
    }
    public Map<String,Object> getCatalogStatus() { return Map.of("entries",windowsEventCatalog.size(),"loaded",windowsEventCatalog.size()>0); }
}
