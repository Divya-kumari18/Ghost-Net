package com.ghostnet.security;

import java.util.Set;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.ghostnet.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class GhostNetUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    // ─── UserDetailsService ──────────────────────────────────────────

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository
                .findByUsernameOrEmail(username, username)
                .map(this::toUserDetails)
                .orElseThrow(() -> new UsernameNotFoundException(
                        "User not found: " + username));
    }

    // ─── Helpers ─────────────────────────────────────────────────────

    private UserDetails toUserDetails(com.ghostnet.model.User user) {
        var role      = "ROLE_" + user.getRole().toUpperCase();
        var authority = new SimpleGrantedAuthority(role);

        return User.builder()
                .username(user.getUsername())
                .password(user.getPasswordHash())
                .authorities(Set.of(authority))
                .accountExpired(false)
                .accountLocked(!user.isActive())
                .credentialsExpired(false)
                .disabled(!user.isActive())
                .build();
    }
}