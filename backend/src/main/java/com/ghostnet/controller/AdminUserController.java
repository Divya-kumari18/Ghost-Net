package com.ghostnet.controller;

import com.ghostnet.model.User;
import com.ghostnet.repository.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import lombok.RequiredArgsConstructor;
import java.util.*;

@RestController @RequestMapping("/admin/users") @RequiredArgsConstructor
public class AdminUserController {
    private final UserRepository users;
    private final UserSessionRepository sessions;
    private final PasswordEncoder passwords;
    private static final Set<String> ROLES=Set.of("admin","analyst","operator","auditor","viewer");
    @GetMapping public List<User> list() { return users.findAll(); }
    @PostMapping @Transactional public User create(@Valid @RequestBody NewUser req) {
        if (!ROLES.contains(req.role())) throw new IllegalArgumentException("Invalid role");
        if (users.existsByUsername(req.username()) || users.existsByEmail(req.email())) throw new IllegalArgumentException("Username or email already exists");
        return users.save(User.builder().username(req.username()).email(req.email()).role(req.role()).active(true)
            .passwordHash(passwords.encode(req.password())).salt("").build());
    }
    @PatchMapping("/{id}") @Transactional public User update(@PathVariable Long id, @Valid @RequestBody UpdateUser req, Authentication auth) {
        var user=users.findById(id).orElseThrow();
        if (!ROLES.contains(req.role())) throw new IllegalArgumentException("Invalid role");
        if (user.getUsername().equals(auth.getName()) && (!req.active() || !"admin".equals(req.role())))
            throw new IllegalArgumentException("An administrator cannot disable or demote their own account");
        user.setRole(req.role()); user.setActive(req.active());
        sessions.deleteByUser_UsernameAndActiveTrue(user.getUsername());
        return users.save(user);
    }
    public record NewUser(@NotBlank @Size(min=3,max=50) String username,@NotBlank @Email String email,
        @NotBlank @Size(min=12,max=72) String password,@NotBlank String role) {}
    public record UpdateUser(@NotBlank String role, boolean active) {}
}
