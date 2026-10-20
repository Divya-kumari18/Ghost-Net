package com.ghostnet.controller;
import java.util.List;
import java.util.Map;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.ghostnet.model.OperationalJob;
import com.ghostnet.model.SecurityEvent;
import com.ghostnet.repository.OperationalJobRepository;
import com.ghostnet.repository.SecurityEventRepository;
import com.ghostnet.service.FileIntegrityService;
import com.ghostnet.service.OperationalJobService;
import com.ghostnet.service.SecurityEventPipeline;
import com.ghostnet.service.TrafficMlWorker;

import lombok.RequiredArgsConstructor;
@RestController @RequestMapping("/operations") @RequiredArgsConstructor
public class OperationsController {
    private final SecurityEventPipeline pipeline;
    private final TrafficMlWorker ml;
    private final SecurityEventRepository events;
    private final FileIntegrityService fim;
    private final OperationalJobRepository jobs;
    private final OperationalJobService scheduler;
    @GetMapping("/status") public Map<String,Object> status() { return Map.of("pipeline",pipeline.status(),"fileIntegrity",fim.status(),"modelLastError",ml.getLastError()); }
    @GetMapping("/events") public Page<SecurityEvent> events(@RequestParam(defaultValue="0") int page) { return events.findAll(PageRequest.of(page,100,Sort.by("receivedAt").descending())); }
    @PostMapping("/fim/approve") @PreAuthorize("hasRole('ADMIN')") public Map<String,Object> approve(Authentication user) throws Exception { return fim.approve(user.getName()); }
    @GetMapping("/jobs") public List<OperationalJob> jobs() { return jobs.findAll(); }
    @PostMapping("/jobs") @PreAuthorize("hasRole('ADMIN')") public OperationalJob create(@RequestBody JobRequest request,Authentication user) {
        return scheduler.create(request.name(),request.type(),request.target(),request.intervalSeconds(),user.getName());
    }
    @DeleteMapping("/jobs/{id}") @PreAuthorize("hasRole('ADMIN')") public void delete(@PathVariable String id) { jobs.deleteById(id); }
    public record JobRequest(String name,String type,String target,long intervalSeconds) {}
}
