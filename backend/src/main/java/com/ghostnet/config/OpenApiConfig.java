package com.ghostnet.config;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI ghostNetOpenAPI() {
        return new OpenAPI()
            .info(new Info()
                .title("GhostNet: Uncovering Invisible Threats in Modern Networks API")
                .description("""
                    Multi-Layered Defence Architecture for Maximum Network Integrity and Resilience.
                    
                    This API provides endpoints for:
                    - **Module 1** – Authentication & User Management
                    - **Module 3** – Real-time Network Analysis & IDS
                    - **Module 5** – Malware Detection & File Integrity
                    - **Module 6** – Centralized Incident Management
                    - **Module 8** – Dashboard Stats & WebSocket Events
                    
                    **WebSocket Topics** (STOMP):
                    - `/topic/alerts`    – Real-time IDS & Windows Event alerts
                    - `/topic/traffic`   – Live packet metadata stream
                    - `/topic/events`    – Windows Event Log entries
                    - `/topic/incidents` – Incident creation/update events
                    - `/topic/dashboard` – Aggregated stats (every 10s)
                    """)
                .version("1.0.0")
                .contact(new Contact()
                    .name("GhostNet Project Team")
                    .email("ghostnet@jssate.ac.in"))
                .license(new License()
                    .name("JSSATE / VTU Project Work Phase - 1 (BIS685)")))
            .servers(List.of(
                new Server().url("http://localhost:8081/api").description("Local Development")))
            .addSecurityItem(new SecurityRequirement().addList("bearerAuth"))
            .components(new Components()
                .addSecuritySchemes("bearerAuth",
                    new SecurityScheme()
                        .type(SecurityScheme.Type.HTTP)
                        .scheme("bearer")
                        .bearerFormat("JWT")
                        .description("Enter JWT token from /auth/login")));
    }
}
