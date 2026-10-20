package com.ghostnet.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.ghostnet.model.Honeypot;

@Repository
public interface HoneypotRepository extends JpaRepository<Honeypot, Long> {
    long countByActiveTrue();
    Optional<Honeypot> findByHoneypotName(String honeypotName);
}
