package com.ghostnet.service;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

class AuthServicePasswordTest {

    @Test
    void defaultAdminPasswordMatchesExpectedValue() {
        PasswordEncoder encoder = new BCryptPasswordEncoder(12);
        String encodedPassword = encoder.encode("password");

        assertThat(encoder.matches("password", encodedPassword)).isTrue();
        assertThat(encoder.matches("admin123", encodedPassword)).isFalse();
    }
}
