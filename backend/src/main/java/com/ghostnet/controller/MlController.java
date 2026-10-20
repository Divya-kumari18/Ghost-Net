package com.ghostnet.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.beans.factory.annotation.Value;
import java.net.*;
import java.net.http.*;
import java.time.Duration;
import org.springframework.http.ResponseEntity;
@RestController @RequestMapping("/ml")
public class MlController {
    @Value("${python.malware.base-url:http://127.0.0.1:5000}") private String base;
    @Value("${python.api-key:}") private String key;
    private final HttpClient client=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
    private ResponseEntity<String> forward(String path,String body) throws Exception {
        var builder=HttpRequest.newBuilder(URI.create(base+path)).timeout(Duration.ofSeconds(30)).header("X-API-Key",key).header("Content-Type","application/json");
        var response=client.send(body==null ? builder.GET().build() : builder.POST(HttpRequest.BodyPublishers.ofString(body)).build(),HttpResponse.BodyHandlers.ofString());
        return ResponseEntity.status(response.statusCode()).header("Content-Type","application/json").body(response.body());
    }
    @GetMapping("/health") public ResponseEntity<String> health() throws Exception { return forward("/api/health",null); }
    @PostMapping("/anomaly/detect") @PreAuthorize("hasAnyRole('ADMIN','ANALYST')") public ResponseEntity<String> detect(@RequestBody String body) throws Exception { return forward("/api/anomaly/detect",body); }
    @PostMapping("/anomaly/batch") @PreAuthorize("hasAnyRole('ADMIN','ANALYST')") public ResponseEntity<String> batch(@RequestBody String body) throws Exception { return forward("/api/anomaly/batch",body); }
    @PostMapping("/model/retrain") @PreAuthorize("hasRole('ADMIN')") public ResponseEntity<String> train(@RequestBody String body) throws Exception { return forward("/api/model/retrain",body); }
}
