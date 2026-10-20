package com.ghostnet.security;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class JwtService {
    @org.springframework.beans.factory.annotation.Autowired
    private com.ghostnet.repository.UserSessionRepository sessions;
    public long accessLifetimeSeconds() { return jwtExpiration / 1000; }
    public long refreshLifetimeSeconds() { return refreshExpiration / 1000; }
    public String generateRefreshToken(UserDetails user, String sessionId) {
        return buildToken(Map.of("sid", sessionId, "purpose", "refresh"), user, refreshExpiration);
    }
    public boolean isRefreshTokenValid(String token, UserDetails user) {
        return valid(token, user, "refresh");
    }
    private boolean valid(String token, UserDetails user, String purpose) {
        try {
            Claims claims = extractAllClaims(token);
            String sid = claims.get("sid", String.class);
            return user.isEnabled() && user.isAccountNonLocked()
                && user.getUsername().equals(claims.getSubject())
                && purpose.equals(claims.get("purpose", String.class)) && sid != null
                && sessions.findWithUser(sid).filter(session -> session.isActive()
                    && session.getExpiresAt().toInstant().isAfter(Instant.now())
                    && session.getUser().getUsername().equals(user.getUsername())).isPresent();
        } catch (RuntimeException ex) { return false; }
    }


    @Value("${ghostnet.jwt.secret}")
    private String rawSecret;

    @Value("${ghostnet.jwt.expiration}")
    private long jwtExpiration;

    @Value("${ghostnet.jwt.refresh-expiration}")
    private long refreshExpiration;

    private SecretKey signingKey;   // computed once after injection

    @PostConstruct
    private void initSigningKey() {
        byte[] keyBytes = rawSecret.getBytes(StandardCharsets.UTF_8);
        if (keyBytes.length < 32) {
            throw new IllegalStateException(
                "ghostnet.jwt.secret must be at least 32 bytes for HMAC-SHA256 " +
                "(got " + keyBytes.length + " bytes)");
        }
        this.signingKey = Keys.hmacShaKeyFor(keyBytes);
    }

    // ─── Public API ──────────────────────────────────────────────────

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> resolver) {
        return resolver.apply(extractAllClaims(token));
    }

    /** Generates an access token with caller-supplied extra claims. */
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        var claims = new java.util.HashMap<String, Object>(extraClaims);
        claims.put("purpose", "access");
        return buildToken(claims, userDetails, jwtExpiration);
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        return valid(token, userDetails, "access");
    }

    // ─── Internals ───────────────────────────────────────────────────

    private String buildToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails,
            long expirationMs) {

        var now    = Instant.now();
        var expiry = now.plusMillis(expirationMs);

        return Jwts.builder()
                .claims(extraClaims)
                .subject(userDetails.getUsername())
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiry))
                .claim("roles", userDetails.getAuthorities())
                .signWith(signingKey)
                .compact();
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}