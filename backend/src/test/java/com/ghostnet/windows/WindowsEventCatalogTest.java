package com.ghostnet.windows;

import org.junit.jupiter.api.*;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.test.util.ReflectionTestUtils;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class WindowsEventCatalogTest {
    private WindowsEventCatalog catalog;
    @BeforeEach void load() {
        catalog=new WindowsEventCatalog(new DefaultResourceLoader());
        ReflectionTestUtils.setField(catalog,"detailsPath","missing-event-catalog.md");
        catalog.load();
    }
    @Test void bundledCatalogWorksWithoutSourceMarkdown() {
        assertTrue(catalog.size()>450);
        assertEquals("Service state changed",catalog.find(7036,"Service Control Manager","System").orElseThrow().description());
        assertTrue(catalog.find(4634).orElseThrow().description().contains("logged off"));
    }
    @Test void codesAreScopedToProviderAndChannel() {
        assertEquals("Windows error report generated",catalog.find(1001,"Windows Error Reporting","Application").orElseThrow().description());
        assertEquals("System restarted after a bug check",catalog.find(1001,"Microsoft-Windows-WER-SystemErrorReporting","System").orElseThrow().description());
        assertTrue(catalog.find(4624,"CustomProvider","Application").isEmpty());
    }
    @Test void auditLevelZeroAndServiceNameAreParsed() {
        var reader=new WindowsEventLogReader(mock(com.ghostnet.service.WindowsEventService.class),catalog,
                mock(com.ghostnet.repository.IngestionCursorRepository.class),mock(org.springframework.transaction.support.TransactionTemplate.class));
        String xml="<Event><System><Provider Name=\"Service Control Manager\"/><EventID>7036</EventID><EventRecordID>1</EventRecordID><Level>0</Level><TimeCreated SystemTime=\"2026-10-11T10:00:00Z\"/><Computer>test-host</Computer></System><EventData><Data Name=\"param1\">Example service</Data></EventData></Event>";
        var event=reader.parseEventXml(xml,"System");
        assertEquals("LogAlways",event.getLevel());
        assertTrue(event.getMessage().startsWith("Service state changed"));
    }
}
