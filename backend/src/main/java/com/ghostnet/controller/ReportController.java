package com.ghostnet.controller;

import java.time.LocalDate;
import java.time.ZonedDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.ghostnet.dto.CveRecordSummary;
import com.ghostnet.dto.ReportChecklistItem;
import com.ghostnet.repository.IncidentRepository;
import com.ghostnet.repository.MalwareScanRepository;
import com.ghostnet.repository.NetworkAlertsRepository;
import com.ghostnet.repository.WindowsEventLogRepository;
import com.ghostnet.service.VulnerabilityReportService;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/reports")
@RequiredArgsConstructor
public class ReportController {

    private final VulnerabilityReportService reportService;
    private final NetworkAlertsRepository networkAlertsRepository;
    private final IncidentRepository incidentRepository;
    private final MalwareScanRepository malwareScanRepository;
    private final WindowsEventLogRepository windowsEventLogRepository;
    private final com.ghostnet.repository.VulnerabilityFindingRepository findingRepository;

    @GetMapping("/vulnerability/pdf")
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST','OPERATOR')")
    public ResponseEntity<byte[]> downloadVulnerabilityPdf(
        @RequestParam(required = false) String severity,
        @RequestParam(required = false) String status,
        @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate from,
        @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate to
    ) {
        byte[] pdf = reportService.generateVulnerabilityPdf(severity, status, from, to);

        String filename = "vulnerability_report_" + LocalDate.now() + ".pdf";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_PDF);
        headers.setContentDisposition(ContentDisposition.attachment().filename(filename).build());

        return ResponseEntity.ok()
            .headers(headers)
            .body(pdf);
    }

        @org.springframework.transaction.annotation.Transactional(readOnly=true,isolation=org.springframework.transaction.annotation.Isolation.REPEATABLE_READ)
        @GetMapping("/sync")
        @PreAuthorize("hasAnyRole('ADMIN','ANALYST','OPERATOR')")
        public ResponseEntity<Map<String, Object>> syncReportData(
            @RequestParam(defaultValue = "30") int days,
            @RequestParam(defaultValue = "1000") int limit
        ) {
        int safeDays = Math.min(Math.max(days, 1), 365);
        int safeLimit = Math.min(Math.max(limit, 100), 5000);
        ZonedDateTime until = ZonedDateTime.now();
        ZonedDateTime since = until.minusDays(safeDays);
        Pageable pageable = PageRequest.of(0, safeLimit);

        var alertPage=networkAlertsRepository.findByTimestampBetweenOrderByTimestampDesc(since,until,pageable);
        var incidentPage=incidentRepository.findByCreatedAtBetweenOrderByCreatedAtDesc(since,until,pageable);
        var malwarePage=malwareScanRepository.findByScanTimeBetweenOrderByScanTimeDesc(since,until,pageable);
        var eventPage=windowsEventLogRepository.findByEventTimeBetweenOrderByEventTimeDesc(since,until,pageable);
        var findingPage=findingRepository.findByCreatedAtBetweenOrderByCreatedAtDesc(since,until,pageable);
        List<CveRecordSummary> cveRecords = reportService.getTopCveRecords(since, 12);

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("alerts",alertPage.getTotalElements());
        summary.put("openIncidents",incidentRepository.countOpenInWindow(since,until));
        summary.put("incidents",incidentPage.getTotalElements());
        summary.put("infectedFiles",malwareScanRepository.countInfectedInWindow(since,until));
        summary.put("malwareScans",malwarePage.getTotalElements());
        summary.put("windowsEvents",eventPage.getTotalElements());
        summary.put("windowsSecurityEvents",windowsEventLogRepository.countSecurityInWindow(since,until));
        summary.put("vulnerabilityFindings",findingPage.getTotalElements());
        summary.put("criticalVulns",findingRepository.countCriticalInWindow(since,until));
        Map<String,Object> data = new LinkedHashMap<>();
        data.put("alerts",alertPage.getContent());data.put("incidents",incidentPage.getContent());
        data.put("malwareScans",malwarePage.getContent());data.put("winEvents",eventPage.getContent());
        data.put("vulnFindings",findingPage.getContent());
        Map<String,Object> coverage=new LinkedHashMap<>();
        coverage.put("alerts",Map.of("included",alertPage.getNumberOfElements(),"total",alertPage.getTotalElements()));
        coverage.put("incidents",Map.of("included",incidentPage.getNumberOfElements(),"total",incidentPage.getTotalElements()));
        coverage.put("malwareScans",Map.of("included",malwarePage.getNumberOfElements(),"total",malwarePage.getTotalElements()));
        coverage.put("winEvents",Map.of("included",eventPage.getNumberOfElements(),"total",eventPage.getTotalElements()));
        coverage.put("vulnFindings",Map.of("included",findingPage.getNumberOfElements(),"total",findingPage.getTotalElements()));
        List<ReportChecklistItem> checks = reportService.buildReportChecklist(summary, safeDays, cveRecords);

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("days", safeDays);
        payload.put("since", since);
        payload.put("until",until);
        payload.put("generatedAt",until);
        payload.put("coverage",coverage);
        payload.put("limit", safeLimit);
        payload.put("summary", summary);
        payload.put("data", data);
        payload.put("cveRecords", cveRecords);
        payload.put("checks", checks);
        return ResponseEntity.ok(payload);
        }
}
