package com.ghostnet.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;

@Configuration
@EnableWebSocketMessageBroker
public class WebSocketConfig implements WebSocketMessageBrokerConfigurer {
    private final com.ghostnet.security.JwtService jwt;
    private final com.ghostnet.security.GhostNetUserDetailsService users;
    private final java.util.Map<String,String> sessionTokens;

    public WebSocketConfig(com.ghostnet.security.JwtService jwt,
            com.ghostnet.security.GhostNetUserDetailsService users) {
        this.jwt = jwt;
        this.users = users;
        this.sessionTokens = new java.util.concurrent.ConcurrentHashMap<>();
    }

    @org.springframework.beans.factory.annotation.Value("${ghostnet.cors.allowed-origins}")
    private String origins;
    @Override
    public void configureClientInboundChannel(org.springframework.messaging.simp.config.ChannelRegistration registration) {
        registration.interceptors(new org.springframework.messaging.support.ChannelInterceptor() {
            @Override public org.springframework.messaging.Message<?> preSend(org.springframework.messaging.Message<?> message, org.springframework.messaging.MessageChannel channel) {
                var header = org.springframework.messaging.support.MessageHeaderAccessor.getAccessor(message, org.springframework.messaging.simp.stomp.StompHeaderAccessor.class);
                if (header == null || header.getCommand() == null) return message;
                var command = header.getCommand();
                if (command == org.springframework.messaging.simp.stomp.StompCommand.CONNECT) {
                    String auth = header.getFirstNativeHeader("Authorization");
                    if (auth == null || !auth.startsWith("Bearer ")) throw new org.springframework.security.access.AccessDeniedException("Authentication required");
                    String token = auth.substring(7);
                    var user = users.loadUserByUsername(jwt.extractUsername(token));
                    if (!jwt.isTokenValid(token, user)) throw new org.springframework.security.access.AccessDeniedException("Invalid session");
                    header.setUser(new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(user, null, user.getAuthorities()));
                    sessionTokens.put(header.getSessionId(),token);
                    if(header.getSessionAttributes()!=null) header.getSessionAttributes().put("jwt", token);
                } else if (command == org.springframework.messaging.simp.stomp.StompCommand.SUBSCRIBE || command == org.springframework.messaging.simp.stomp.StompCommand.SEND) {
                    String token = sessionTokens.get(header.getSessionId());
                    if (token == null || !jwt.isTokenValid(token, users.loadUserByUsername(jwt.extractUsername(token))))
                        throw new org.springframework.security.access.AccessDeniedException("Session expired");
                    if (command == org.springframework.messaging.simp.stomp.StompCommand.SEND || header.getDestination() == null || !java.util.Set.of("/topic/alerts", "/topic/traffic", "/topic/events", "/topic/incidents", "/topic/malware", "/topic/dashboard", "/topic/honeypot").contains(header.getDestination()))
                        throw new org.springframework.security.access.AccessDeniedException("Destination denied");
                }
                return message;
            }
        });
    }


    @Override
    public void configureClientOutboundChannel(org.springframework.messaging.simp.config.ChannelRegistration registration) {
        registration.interceptors(new org.springframework.messaging.support.ChannelInterceptor() {
            @Override public org.springframework.messaging.Message<?> preSend(org.springframework.messaging.Message<?> message, org.springframework.messaging.MessageChannel channel) {
                var header=org.springframework.messaging.simp.stomp.StompHeaderAccessor.wrap(message);
                if(header.getCommand()!=org.springframework.messaging.simp.stomp.StompCommand.MESSAGE) return message;
                String token=sessionTokens.get(header.getSessionId());
                try { if(token==null || !jwt.isTokenValid(token,users.loadUserByUsername(jwt.extractUsername(token)))) return null; }
                catch(RuntimeException ex) { return null; }
                return message;
            }
        });
    }
    @org.springframework.context.event.EventListener
    public void disconnected(org.springframework.web.socket.messaging.SessionDisconnectEvent event) { sessionTokens.remove(event.getSessionId()); }
    @Override
    public void configureMessageBroker(MessageBrokerRegistry registry) {
        // Enable a simple in-memory broker for broadcasting
        registry.enableSimpleBroker(
            "/topic/alerts",
            "/topic/traffic",
            "/topic/events",
            "/topic/incidents",
            "/topic/malware",
            "/topic/dashboard",
            "/topic/honeypot"
        );
        registry.setApplicationDestinationPrefixes("/app");
    }

    @Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        registry.addEndpoint("/ws")
                .setAllowedOrigins(origins.split(","))
                .withSockJS();
    }
}
