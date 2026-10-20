package com.ghostnet.controller;
import com.ghostnet.service.SettingsService;
import com.ghostnet.model.OperationalSettings;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.access.prepost.PreAuthorize;
import lombok.RequiredArgsConstructor;
@RestController @RequestMapping("/settings") @RequiredArgsConstructor
public class SettingsController {
    private final SettingsService settings;
    @GetMapping public OperationalSettings get() { return settings.get(); }
    @PutMapping @PreAuthorize("hasRole('ADMIN')") public OperationalSettings save(@RequestBody Request req,Authentication user) {
        return settings.save(req.criticalThreshold(),req.retentionHotDays(),req.retentionEnabled(),user.getName());
    }
    public record Request(int criticalThreshold,int retentionHotDays,boolean retentionEnabled) {}
}
