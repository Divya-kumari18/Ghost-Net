package com.ghostnet.controller;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.ghostnet.service.IncidentService;
import com.ghostnet.service.MalwareDetectionService;
import com.ghostnet.service.WindowsEventService;
import com.ghostnet.windows.WindowsEventLogReader;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.RequiredArgsConstructor;

// ══════════════════════════════════════════════════════
//  Incident Management Controller
// ══════════════════════════════════════════════════════
@RestController
@RequestMapping("/incidents")
@RequiredArgsConstructor
class IncidentController {

    private final IncidentService incidentService;

    @GetMapping
    public ResponseEntity<?> getIncidents(
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String severity,
            @RequestParam(defaultValue = "0")  int page,
            @RequestParam(defaultValue = "20") int size) {
        return ResponseEntity.ok(incidentService.getIncidents(status, severity, page, size));
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getById(@PathVariable Long id) {
        return incidentService.getById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/{id}/timeline")
    public ResponseEntity<?> getTimeline(@PathVariable Long id) {
        return ResponseEntity.ok(incidentService.getTimeline(id));
    }

    @PostMapping
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST','OPERATOR')")
    public ResponseEntity<?> createIncident(
            @Valid @RequestBody CreateIncidentRequest req,
            @AuthenticationPrincipal UserDetails user) {
        try {
            var incident=incidentService.createAssignedIncident(
                    req.getTitle(), req.getDescription(),
                    req.getSeverity(), user.getUsername(), req.getAffectedAssets(),req.getAssignedTo());
            return ResponseEntity.ok(incident);
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.badRequest().body(Map.of("error", ex.getMessage()));
        }
    }

    @PatchMapping("/{id}/status")
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST','OPERATOR')")
    public ResponseEntity<?> updateStatus(
            @PathVariable Long id,
            @RequestBody Map<String, String> body,
            @AuthenticationPrincipal UserDetails user) {
        try {
            return ResponseEntity.ok(
                    incidentService.updateStatus(id, body.get("status"), user.getUsername()));
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.badRequest().body(Map.of("error", ex.getMessage()));
        }
    }

    @PostMapping("/{id}/notes")
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST','OPERATOR')")
    public ResponseEntity<?> addNote(
            @PathVariable Long id,
            @RequestBody Map<String, String> body,
            @AuthenticationPrincipal UserDetails user) {
        try {
            return ResponseEntity.ok(
                    incidentService.addNote(id, body.get("note"), user.getUsername()));
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.badRequest().body(Map.of("error", ex.getMessage()));
        }
    }

    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getStats() {
        return ResponseEntity.ok(incidentService.getIncidentStats());
    }

    @Data static class CreateIncidentRequest {
        @NotBlank String title;
        String description;
        @NotBlank String severity;
        String affectedAssets;
        String assignedTo;
    }
}

// ══════════════════════════════════════════════════════
//  Windows Event Log Controller
// ══════════════════════════════════════════════════════
@RestController
@RequestMapping("/events")
@RequiredArgsConstructor
class WindowsEventController {

    private final WindowsEventService windowsEventService;
    private final WindowsEventLogReader eventReader;

    @GetMapping
    public ResponseEntity<?> getEvents(
            @RequestParam(required = false) String channel,
            @RequestParam(required = false) String level,
            @RequestParam(defaultValue = "0")  int page,
            @RequestParam(defaultValue = "50") int size) {
        return ResponseEntity.ok(windowsEventService.getEvents(channel, level, page, size));
    }

    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getStats() {
        return ResponseEntity.ok(windowsEventService.getEventStats());
    }

    @GetMapping("/security")
    public ResponseEntity<?> getSecurityEvents(
            @RequestParam(defaultValue = "50") int limit) {
        return ResponseEntity.ok(windowsEventService.getRecentSecurityEvents(limit));
    }

    @GetMapping("/reader/status")
    public ResponseEntity<Map<String, Object>> readerStatus() {
        return ResponseEntity.ok(eventReader.getStatus());
    }

    @GetMapping("/catalog/status")
    public ResponseEntity<Map<String, Object>> catalogStatus() {
        return ResponseEntity.ok(windowsEventService.getCatalogStatus());
    }

    @GetMapping("/catalog/{eventId}")
    public ResponseEntity<Map<String, Object>> catalogEntry(@PathVariable Long eventId,
            @RequestParam(required=false) String source,@RequestParam(required=false) String channel) {
        return ResponseEntity.ok(windowsEventService.getEventCatalogEntry(eventId,source,channel));
    }
}

// ══════════════════════════════════════════════════════
//  Malware Detection Controller
// ══════════════════════════════════════════════════════
@RestController
@RequestMapping("/malware")
@RequiredArgsConstructor

class MalwareController {

    @org.springframework.beans.factory.annotation.Value("${ghostnet.storage.uploads:../uploads}")
    private String uploadRoot;
    private final MalwareDetectionService malwareService;

    @PostMapping("/scan")
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST','OPERATOR')")
    public ResponseEntity<?> scanFile(@RequestBody Map<String, String> body) {
        String filePath = body.get("filePath");
        if (filePath == null || filePath.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "filePath is required"));
        }
        try {
            return ResponseEntity.ok(malwareService.scanFile(filePath));
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.badRequest().body(Map.of("error", ex.getMessage()));
        } catch (Exception ex) {
            return ResponseEntity.internalServerError()
                    .body(Map.of("error", "Failed to scan file", "details", ex.getMessage()));
        }
    }

    @PostMapping("/upload")
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST','OPERATOR')")
    public ResponseEntity<?> uploadAndScan(@RequestParam("file") MultipartFile file) {
        if (file == null || file.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "File is required"));
        }
        
        // Validate file size (max 500MB)
        final long MAX_FILE_SIZE = 500L * 1024L * 1024L;
        if (file.getSize() > MAX_FILE_SIZE) {
            return ResponseEntity.badRequest()
                .body(Map.of("error", "File size exceeds maximum limit of 500MB"));
        }
        
        Path tempDir = null;
        Path tempFile = null;
        try {
            // Create temporary directory for uploads
            Path uploads=Path.of(uploadRoot).toAbsolutePath().normalize();
            Files.createDirectories(uploads);
            tempDir = Files.createTempDirectory(uploads,"malware-scan-");
            tempFile = tempDir.resolve(sanitizeFilename(file.getOriginalFilename()));
            
            // Save uploaded file to temp location
            file.transferTo(tempFile.toFile());
            
            // Scan the file
            return ResponseEntity.ok(malwareService.scanUploadedFile(tempFile.toAbsolutePath().toString()));
            
        } catch (IllegalArgumentException ex) {
            return ResponseEntity.badRequest().body(Map.of("error", ex.getMessage()));
        } catch (IOException ex) {
            return ResponseEntity.internalServerError()
                    .body(Map.of("error", "Failed to process uploaded file", "details", ex.getMessage()));
        } catch (Exception ex) {
            return ResponseEntity.internalServerError()
                    .body(Map.of("error", "Failed to scan file", "details", ex.getMessage()));
        } finally {
            // Clean up temporary files
            if (tempFile != null && Files.exists(tempFile)) {
                try {
                    Files.delete(tempFile);
                } catch (IOException e) {
                    // Log but don't fail - cleanup is best-effort
                }
            }
            if (tempDir != null && Files.exists(tempDir)) {
                try {
                    Files.delete(tempDir);
                } catch (IOException e) {
                    // Log but don't fail - cleanup is best-effort
                }
            }
        }
    }

    private static String sanitizeFilename(String originalName) {
        String fallback = "upload.bin";
        if (originalName == null || originalName.isBlank()) {
            return fallback;
        }

        String normalized = originalName.replace('\\', '/');
        int lastSlash = normalized.lastIndexOf('/');
        if (lastSlash >= 0 && lastSlash < normalized.length() - 1) {
            normalized = normalized.substring(lastSlash + 1);
        }

        normalized = normalized.replaceAll("[^A-Za-z0-9._-]", "_");
        if (normalized.isBlank()) {
            return fallback;
        }
        return normalized;
    }

    @GetMapping("/scans")
    public ResponseEntity<?> getScans(
            @RequestParam(required = false) String result,
            @RequestParam(defaultValue = "0")  int page,
            @RequestParam(defaultValue = "50") int size) {
        return ResponseEntity.ok(malwareService.getScans(result, page, size));
    }

    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getStats() {
        Map<String, Object> payload = new LinkedHashMap<>(malwareService.getMalwareStats());
        payload.put("filesystem", malwareService.getFileSystemRuntimeStats());
        return ResponseEntity.ok(payload);
    }

    @PostMapping("/scan/full")
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST')")
    public ResponseEntity<?> startFullFilesystemScan(@RequestBody(required = false) Map<String, String> body) {
        String rootPath = body == null ? null : body.get("rootPath");
        return ResponseEntity.ok(malwareService.startFullSystemScan(rootPath));
    }

    @GetMapping("/scan/full/{jobId}")
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST','OPERATOR')")
    public ResponseEntity<?> getFullFilesystemScanStatus(@PathVariable String jobId) {
        return ResponseEntity.ok(malwareService.getFileSystemScanStatus(jobId));
    }

    @PostMapping("/scan/full/{jobId}/stop")
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST')")
    public ResponseEntity<?> stopFullFilesystemScan(@PathVariable String jobId) {
        return ResponseEntity.ok(malwareService.stopFileSystemScan(jobId));
    }

    @GetMapping("/scan/full/jobs")
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST','OPERATOR')")
    public ResponseEntity<?> listFilesystemScanJobs() {
        return ResponseEntity.ok(Map.of("summary", malwareService.getFileSystemRuntimeStats()));
    }
}
