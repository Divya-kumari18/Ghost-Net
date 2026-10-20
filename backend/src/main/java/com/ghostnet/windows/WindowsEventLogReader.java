package com.ghostnet.windows;

import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import com.ghostnet.model.WindowsEventLog;
import com.ghostnet.service.WindowsEventService;
import com.sun.jna.Memory;
import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.W32Errors;
import com.sun.jna.platform.win32.WinBase;
import com.sun.jna.platform.win32.WinNT;
import com.sun.jna.ptr.IntByReference;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;

/**
 * Reads Windows Event Logs from Security, System, and Application channels
 * using the Windows Event Log API (EvtQuery / EvtNext / EvtRender) via JNA.
 * Requires Windows OS. On non-Windows systems it degrades gracefully.
 */
@Slf4j
@Component
public class WindowsEventLogReader {

    private final WindowsEventService windowsEventService;
    private final WindowsEventCatalog eventCatalog;
    private final com.ghostnet.repository.IngestionCursorRepository cursors;
    private final org.springframework.transaction.support.TransactionTemplate tx;

    @Value("${ghostnet.events.enabled:true}")
    private boolean enabled;

    @Value("${ghostnet.events.channels:Security,System,Application}")
    private String channelsConfig;

    @Value("${ghostnet.events.max-events-per-poll:100}")
    private int maxEventsPerPoll;

    private final AtomicBoolean running = new AtomicBoolean(false);
    private final Object pollLock = new Object();
    private final Map<String, Long> lastReadTimestamp = new HashMap<>();

    public WindowsEventLogReader(WindowsEventService windowsEventService,
                                 WindowsEventCatalog eventCatalog,
                                 com.ghostnet.repository.IngestionCursorRepository cursors,
                                 org.springframework.transaction.support.TransactionTemplate tx) {
        this.windowsEventService = windowsEventService;
        this.eventCatalog = eventCatalog;
        this.cursors = cursors;
        this.tx = tx;
    }

    // Security-relevant Windows Event IDs
    private static final Set<Long> SECURITY_EVENT_IDS = Set.of(
        4624L,  // Successful logon
        4625L,  // Failed logon
        4634L,  // Logoff
        4648L,  // Logon with explicit credentials
        4672L,  // Special privileges assigned
        4688L,  // Process creation
        4698L,  // Scheduled task created
        4699L,  // Scheduled task deleted
        4700L,  // Scheduled task enabled
        4701L,  // Scheduled task disabled
        4702L,  // Scheduled task updated
        4719L,  // System audit policy changed
        4720L,  // User account created
        4722L,  // User account enabled
        4725L,  // User account disabled
        4726L,  // User account deleted
        4728L,  // Member added to security-enabled global group
        4732L,  // Member added to security-enabled local group
        4738L,  // User account changed
        4740L,  // User account locked out
        4756L,  // Member added to security-enabled universal group
        4768L,  // Kerberos auth ticket requested
        4769L,  // Kerberos service ticket requested
        4771L,  // Kerberos pre-authentication failed
        4776L,  // Domain controller validated credentials
        4798L,  // User's local group membership enumerated
        4799L,  // Security-enabled local group membership enumerated
        5140L,  // Network share accessed
        5145L,  // Network share object checked
        7034L,  // Service crashed
        7035L,  // Service control sent
        7036L,  // Service started/stopped
        7045L   // New service installed
    );

    private static final boolean IS_WINDOWS =
            System.getProperty("os.name", "").toLowerCase().contains("win");

    @PostConstruct
    public void init() {
        if (!IS_WINDOWS) {
            log.warn("Windows Event Log reader disabled: not running on Windows.");
            return;
        }
        if (!enabled) {
            log.info("Windows Event Log reader disabled via config.");
            return;
        }
        running.set(true);
        log.info("Windows Event Log reader initialized. Channels: {}", channelsConfig);
        // Initialize lastRead timestamps to now (only read future events)
        for (String ch : channelsConfig.split(",")) {
            lastReadTimestamp.put(ch.trim(), cursors.findById("windows:"+ch.trim()).map(com.ghostnet.model.IngestionCursor::getPosition).orElse(0L)); // last 1 min on startup
        }
    }

    @PreDestroy
    public void shutdown() {
        synchronized (pollLock) {
            running.set(false);
        }
        log.info("Windows Event Log reader shutdown initiated.");
    }

    @Scheduled(fixedDelayString = "${ghostnet.events.poll-interval-ms:5000}")
    public void pollEvents() {
        synchronized (pollLock) {
            if (!running.get() || !IS_WINDOWS) return;

            for (String channel : channelsConfig.split(",")) {
                String ch = channel.trim();
                try {
                    List<WindowsEventLog> events = readChannel(ch);
                    if (!events.isEmpty()) {
                        long next=events.stream().mapToLong(e->e.getRecordId()).max().orElseThrow();
                        tx.executeWithoutResult(status->{
                            windowsEventService.ingestEvents(events);
                            cursors.save(new com.ghostnet.model.IngestionCursor("windows:"+ch,next,"record-id"));
                        });
                        lastReadTimestamp.put(ch,next);
                        log.debug("Ingested {} events from channel: {}", events.size(), ch);
                    }
                } catch (Exception e) {
                    log.warn("Error reading channel {}: {}", ch, e.getMessage());
                }
            }
        }
    }

    private List<WindowsEventLog> readChannel(String channel) {
        return readChannel(channel,false);
    }
    private List<WindowsEventLog> readChannel(String channel,boolean afterReset) {
        List<WindowsEventLog> results = new ArrayList<>();
        long since = lastReadTimestamp.getOrDefault(channel,0L);
        String query = since > 0 ? "*[System[EventRecordID > " + since + "]]"
                : afterReset ? "*" : "*[System[TimeCreated[@SystemTime >= '" + toW3CDateTime(System.currentTimeMillis()-60000L) + "']]]";

        WinNT.HANDLE hQuery = null;
        try {
            // EvtQuery: open event query
            hQuery = Wevtapi.INSTANCE.EvtQuery(
                null,
                channel,
                query,
                Wevtapi.EvtQueryChannelPath | Wevtapi.EvtQueryForwardDirection
            );

            if (hQuery == null || hQuery == WinBase.INVALID_HANDLE_VALUE) {
                int err = Kernel32.INSTANCE.GetLastError();
                if (err == W32Errors.ERROR_EVT_CHANNEL_NOT_FOUND) {
                    log.warn("Event channel not found: {}", channel);
                }
                return results;
            }

            WinNT.HANDLE[] events = new WinNT.HANDLE[maxEventsPerPoll];
            IntByReference returned = new IntByReference(0);

            while (Wevtapi.INSTANCE.EvtNext(hQuery, maxEventsPerPoll, events, 0, 0, returned)) {
                int count = returned.getValue();
                for (int i = 0; i < count; i++) {
                    try {
                        WindowsEventLog evt = renderEvent(events[i], channel);
                        if (evt == null) throw new IllegalStateException("Unable to render event; bookmark retained");
                        results.add(evt);
                    } finally {
                        if (events[i] != null) Wevtapi.INSTANCE.EvtClose(events[i]);
                    }
                }
                if (results.size() >= maxEventsPerPoll) break;
            }

        } catch (Exception e) {
            throw new IllegalStateException("Event query failed for "+channel,e);
        } finally {
            if (hQuery != null && hQuery != WinBase.INVALID_HANDLE_VALUE) {
                try { Wevtapi.INSTANCE.EvtClose(hQuery); } catch (Exception ignored) {}
            }
        }

        if(results.isEmpty() && since>0 && latestRecordId(channel)<since) {
            log.warn("Windows channel {} record IDs reset; replaying retained events",channel);
            cursors.save(new com.ghostnet.model.IngestionCursor("windows:"+channel,0,"record-id"));
            lastReadTimestamp.put(channel,0L);
            return readChannel(channel,true);
        }
        return results;
    }

    private long latestRecordId(String channel) {
        var query=Wevtapi.INSTANCE.EvtQuery(null,channel,"*",Wevtapi.EvtQueryChannelPath|Wevtapi.EvtQueryReverseDirection);
        if(query==null || query==WinBase.INVALID_HANDLE_VALUE) throw new IllegalStateException("Cannot inspect channel bookmark");
        var handles=new WinNT.HANDLE[1];var returned=new IntByReference();
        try {
            if(!Wevtapi.INSTANCE.EvtNext(query,1,handles,0,0,returned)) {
                int error=Kernel32.INSTANCE.GetLastError();
                if(error==259) return 0; // ERROR_NO_MORE_ITEMS: cleared or empty channel
                throw new IllegalStateException("Cannot inspect latest event: "+error);
            }
            var event=renderEvent(handles[0],channel);
            if(event==null) throw new IllegalStateException("Cannot render latest event");
            return event.getRecordId();
        } finally {
            if(handles[0]!=null) Wevtapi.INSTANCE.EvtClose(handles[0]);
            Wevtapi.INSTANCE.EvtClose(query);
        }
    }

    private WindowsEventLog renderEvent(WinNT.HANDLE hEvent, String channel) {
        try {
            // Render event as XML
            IntByReference bufferUsed = new IntByReference(0);
            IntByReference propertyCount = new IntByReference(0);

            // First call to get required buffer size
            Wevtapi.INSTANCE.EvtRender(
                null, hEvent, Wevtapi.EvtRenderEventXml,
                0, null, bufferUsed, propertyCount
            );

            int size = bufferUsed.getValue();
            if (size <= 0) return null;

            Memory buffer = new Memory(size + 2L);
            if (!Wevtapi.INSTANCE.EvtRender(
                null, hEvent, Wevtapi.EvtRenderEventXml,
                size, buffer, bufferUsed, propertyCount
            )) {
                return null;
            }

            String xml = buffer.getWideString(0);
            return parseEventXml(xml, channel);

        } catch (Exception e) {
            log.trace("Error rendering event: {}", e.getMessage());
            return null;
        }
    }

    WindowsEventLog parseEventXml(String xml, String channel) {
        try {
            var factory=javax.xml.parsers.DocumentBuilderFactory.newInstance();
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities",false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities",false);
            var doc=factory.newDocumentBuilder().parse(new org.xml.sax.InputSource(new java.io.StringReader(xml)));
            long eventId=Long.parseLong(doc.getElementsByTagName("EventID").item(0).getTextContent());
            long recordId=Long.parseLong(doc.getElementsByTagName("EventRecordID").item(0).getTextContent());
            String level=mapLevel(Long.parseLong(doc.getElementsByTagName("Level").item(0).getTextContent()));
            String provider=((org.w3c.dom.Element)doc.getElementsByTagName("Provider").item(0)).getAttribute("Name");
            String computer=doc.getElementsByTagName("Computer").item(0).getTextContent();
            String time=((org.w3c.dom.Element)doc.getElementsByTagName("TimeCreated").item(0)).getAttribute("SystemTime");
            var security=doc.getElementsByTagName("Security");
            String user=security.getLength()==0?"":((org.w3c.dom.Element)security.item(0)).getAttribute("UserID");
            List<String> data=new ArrayList<>();var nodes=doc.getElementsByTagName("Data");
            for(int i=0;i<nodes.getLength();i++) {
                var node=(org.w3c.dom.Element)nodes.item(i);
                data.add(node.getAttribute("Name")+"="+node.getTextContent());
            }
            String message=String.join(" | ",data);
            var meta=eventCatalog.find(eventId,provider,channel).orElse(null);
            if(meta!=null) message=meta.description()+" | "+message;
            String key=java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256")
                .digest((computer+"|"+channel+"|"+recordId+"|"+time).getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            return WindowsEventLog.builder().eventId(eventId).recordId(recordId).ingestionKey(key).channel(channel).level(level)
                .source(provider).computerName(computer).userName(user).eventTime(ZonedDateTime.parse(time))
                .message(message).rawXml(xml).securityRelevant(SECURITY_EVENT_IDS.contains(eventId)).build();
        } catch(Exception ex) { throw new IllegalArgumentException("Invalid Windows event XML",ex); }
    }

    private String mapLevel(long levelCode) {
        return switch ((int) levelCode) {
            case 0  -> "LogAlways"; // Audit events have no severity level filtering.
            case 1  -> "Critical";
            case 2  -> "Error";
            case 3  -> "Warning";
            case 4  -> "Information";
            case 5  -> "Verbose";
            default -> "Level " + levelCode;
        };
    }

    private String toW3CDateTime(long epochMs) {
        return Instant.ofEpochMilli(epochMs)
                .atZone(ZoneId.of("UTC"))
                .toString()
                .replace("[UTC]", "");
    }

    public boolean isRunning() { return running.get() && IS_WINDOWS; }

    public Map<String, Object> getStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("running", running.get());
        status.put("isWindows", IS_WINDOWS);
        status.put("enabled", enabled);
        status.put("channels", Arrays.asList(channelsConfig.split(",")));
        status.put("lastReadRecordIds", Map.copyOf(lastReadTimestamp));
        status.put("catalogEntries", eventCatalog.size());
        return status;
    }
}
