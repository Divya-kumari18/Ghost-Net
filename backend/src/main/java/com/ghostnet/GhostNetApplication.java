package com.ghostnet;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.context.event.EventListener;
import org.springframework.core.env.Environment;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@SpringBootApplication
@EnableAsync
@EnableScheduling
@EnableCaching
public class GhostNetApplication {

    private final Environment environment;

    public GhostNetApplication(Environment environment) {
        this.environment = environment;
    }

    public static void main(String[] args) {
        printBanner();
        SpringApplication.run(GhostNetApplication.class, args);
    }

    @EventListener(ApplicationReadyEvent.class)
    public void logStartupDetails() {
        String port = environment.getProperty("local.server.port", environment.getProperty("server.port", "8081"));
        String contextPath = environment.getProperty("server.servlet.context-path", "");
        log.info("=================================================");
        log.info("  GhostNet Security Platform STARTED");
        log.info("  API: http://localhost:{}{}", port, contextPath);
        log.info("  Operations: http://localhost:{}{}/operations/status", port, contextPath);
        log.info("=================================================");
    }

    private static void printBanner() {
        System.out.println("""
        Multi-Layered Defence Architecture for Maximum Network Integrity and Resilience
        GhostNet: Uncovering Invisible Threats in Modern Networks
        By: Divya Kumari | Arnitha P | Aishwarya Girani | Arun Prasad
        JSSATE / VTU | Project Work Phase - 1 (BIS685)
        """);
    }
}
