package com.ghostnet.controller;
import com.ghostnet.repository.*;
import com.ghostnet.service.VulnerabilityReportService;
import com.ghostnet.model.*;
import org.junit.jupiter.api.Test;
import org.springframework.data.domain.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.*;

class ReportControllerTest {
    @Test void totalsAreIndependentOfPageSizeAndCoverageIsExplicit() {
        var reports=mock(VulnerabilityReportService.class);
        var alerts=mock(NetworkAlertsRepository.class);var incidents=mock(IncidentRepository.class);
        var malware=mock(MalwareScanRepository.class);var events=mock(WindowsEventLogRepository.class);var findings=mock(VulnerabilityFindingRepository.class);
        var page=PageRequest.of(0,100);
        when(alerts.findByTimestampBetweenOrderByTimestampDesc(any(),any(),any())).thenReturn(new PageImpl<>(List.of(NetworkAlert.builder().alertId(1L).build()),page,701));
        when(incidents.findByCreatedAtBetweenOrderByCreatedAtDesc(any(),any(),any())).thenReturn(new PageImpl<>(List.of(),page,0));
        when(malware.findByScanTimeBetweenOrderByScanTimeDesc(any(),any(),any())).thenReturn(new PageImpl<>(List.of(),page,0));
        when(events.findByEventTimeBetweenOrderByEventTimeDesc(any(),any(),any())).thenReturn(new PageImpl<>(List.of(),page,0));
        when(findings.findByCreatedAtBetweenOrderByCreatedAtDesc(any(),any(),any())).thenReturn(new PageImpl<>(List.of(),page,0));
        when(incidents.countOpenInWindow(any(),any())).thenReturn(321L);
        when(findings.countCriticalInWindow(any(),any())).thenReturn(55L);
        var result=new ReportController(reports,alerts,incidents,malware,events,findings).syncReportData(1,100).getBody();
        var summary=(Map<?,?>)result.get("summary");
        assertEquals(701L,summary.get("alerts"));assertEquals(321L,summary.get("openIncidents"));assertEquals(55L,summary.get("criticalVulns"));
        var coverage=(Map<?,?>)((Map<?,?>)result.get("coverage")).get("alerts");
        assertEquals(1,coverage.get("included"));assertEquals(701L,coverage.get("total"));
        assertNotNull(result.get("until"));assertEquals(1,result.get("days"));
    }
}
