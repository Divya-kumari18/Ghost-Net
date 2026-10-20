package com.ghostnet.repository;

import com.ghostnet.model.UserSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UserSessionRepository extends JpaRepository<UserSession, String> {
    @org.springframework.data.jpa.repository.Lock(jakarta.persistence.LockModeType.PESSIMISTIC_WRITE)
    @org.springframework.data.jpa.repository.Query("select s from UserSession s join fetch s.user where s.sessionId = :id")
    java.util.Optional<UserSession> findForUpdate(@org.springframework.data.repository.query.Param("id") String id);
    @org.springframework.data.jpa.repository.Query("select s from UserSession s join fetch s.user where s.sessionId = :id")
    java.util.Optional<UserSession> findWithUser(@org.springframework.data.repository.query.Param("id") String id);
    List<UserSession> findByUser_UsernameAndActiveTrue(String username);
    void deleteByUser_UsernameAndActiveTrue(String username);
}
