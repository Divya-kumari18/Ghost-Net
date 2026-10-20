package com.ghostnet.service;

import java.time.ZonedDateTime;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.UUID;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.ghostnet.model.User;
import com.ghostnet.model.UserSession;
import com.ghostnet.repository.UserRepository;
import com.ghostnet.repository.UserSessionRepository;
import com.ghostnet.security.JwtService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepo;
    private final UserSessionRepository sessionRepo;
    private final JwtService jwtService;
    private final AuthenticationManager authManager;
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    private static final String DEFAULT_ROLE = "viewer";

    @Transactional
    public Map<String, Object> login(String username, String password, String ipAddress, String userAgent) {
        try {
            authManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
        } catch (BadCredentialsException e) {
            log.warn("Failed login attempt for user '{}' from IP {}", username, ipAddress);
            throw new BadCredentialsException("Invalid username or password");
        } catch (DisabledException e) {
            throw new DisabledException("Account is disabled");
        }

        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        User user = userRepo.findByUsernameOrEmail(username, username)
                .orElseThrow(() -> new NoSuchElementException("User not found"));



        // Store session
        UserSession session = UserSession.builder()
                .sessionId(UUID.randomUUID().toString())
                .user(user)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .expiresAt(ZonedDateTime.now().plusSeconds(jwtService.refreshLifetimeSeconds()))
                .active(true)
                .build();
        sessionRepo.save(session);
        String accessToken = jwtService.generateToken(Map.of("sid", session.getSessionId()), userDetails);
        String refreshToken = jwtService.generateRefreshToken(userDetails, session.getSessionId());

        log.info("User '{}' logged in from IP {}", username, ipAddress);

        return Map.of(
            "accessToken",  accessToken,
            "refreshToken", refreshToken,
            "tokenType",    "Bearer",
            "expiresIn",    jwtService.accessLifetimeSeconds(),
            "user", Map.of(
                "userId",   user.getUserId(),
                "username", user.getUsername(),
                "email",    user.getEmail(),
                "role",     user.getRole()
            )
        );
    }

    @Transactional
    public User register(String username, String email, String password) {
        if (userRepo.existsByUsername(username)) {
            throw new IllegalArgumentException("Username already taken: " + username);
        }
        if (userRepo.existsByEmail(email)) {
            throw new IllegalArgumentException("Email already registered: " + email);
        }

        String salt = BCrypt.gensalt(12);
        User user = User.builder()
                .username(username)
                .email(email)
                .passwordHash(passwordEncoder.encode(password))
                .salt(salt.substring(0, 29))
                // self-service signups are always lowest-privilege
                .role(DEFAULT_ROLE)
                .active(true)
                .build();

        User saved = userRepo.save(user);
        log.info("New user registered: {} (role: {})", username, DEFAULT_ROLE);
        return saved;
    }

    @Transactional
    public Map<String, Object> refreshToken(String refreshToken) {
        try {
            String username = jwtService.extractUsername(refreshToken);
            UserDetails details = userDetailsService.loadUserByUsername(username);
            String oldId = jwtService.extractClaim(refreshToken, c -> c.get("sid", String.class));
            UserSession old = sessionRepo.findForUpdate(oldId).orElseThrow(() -> new BadCredentialsException("Session expired"));
            if (!old.isActive() || !jwtService.isRefreshTokenValid(refreshToken, details)) throw new BadCredentialsException("Session expired");
            old.setActive(false);
            UserSession next = UserSession.builder().sessionId(UUID.randomUUID().toString()).user(old.getUser())
                .ipAddress(old.getIpAddress()).userAgent(old.getUserAgent())
                .expiresAt(ZonedDateTime.now().plusSeconds(jwtService.refreshLifetimeSeconds())).active(true).build();
            sessionRepo.saveAndFlush(next);
            return Map.of("accessToken", jwtService.generateToken(Map.of("sid", next.getSessionId()), details),
                "refreshToken", jwtService.generateRefreshToken(details, next.getSessionId()),
                "expiresIn", jwtService.accessLifetimeSeconds(), "tokenType", "Bearer");
        } catch (io.jsonwebtoken.JwtException | IllegalArgumentException ex) {
            throw new BadCredentialsException("Invalid refresh token");
        }
    }

    @Transactional
    public void logout(String username) {
        sessionRepo.deleteByUser_UsernameAndActiveTrue(username);
        log.info("User '{}' logged out.", username);
    }

    @Transactional(readOnly = true)
    public User getCurrentUser(String username) {
        return userRepo.findByUsernameOrEmail(username, username)
                .orElseThrow(() -> new NoSuchElementException("User not found: " + username));
    }
}
