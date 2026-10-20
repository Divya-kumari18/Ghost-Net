package com.ghostnet.config;

import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.ghostnet.model.User;
import com.ghostnet.repository.UserRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class DefaultUserBootstrap {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @org.springframework.beans.factory.annotation.Value("${ghostnet.bootstrap.enabled:false}")
    private boolean enabled;
    @org.springframework.beans.factory.annotation.Value("${ghostnet.bootstrap.username:admin}")
    private String username;
    @org.springframework.beans.factory.annotation.Value("${ghostnet.bootstrap.password:}")
    private String password;
    @Bean
    public ApplicationRunner ensureDefaultAdminUser() {
        return args -> {
            if (!enabled) return;
            if (password == null || password.length() < 12) throw new IllegalStateException("Set a bootstrap password of at least 12 characters");
            if (userRepository.findByUsername(username).isPresent()) return;
            String email = username + "@ghostnet.local";
            User user = User.builder()
                .username(username)
                .email(email)
                .passwordHash(passwordEncoder.encode(password))
                .salt("")
                .role("admin")
                .active(true)
                .build();

            userRepository.save(user);
            log.info("Created initial administrator: {}", username);
        };
    }
}
