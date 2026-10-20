package com.ghostnet.repository;

import com.ghostnet.model.SecurityEvent;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;
import org.springframework.data.domain.Pageable;
import java.time.ZonedDateTime;
import java.util.List;

public interface SecurityEventRepository extends JpaRepository<SecurityEvent,String> {
    List<SecurityEvent> findByProcessedFalseOrderByReceivedAtAsc(Pageable page);
    List<SecurityEvent> findByPublishedFalseOrderByReceivedAtAsc(Pageable page);
    List<SecurityEvent> findByAssetAndOccurredAtAfter(String asset, ZonedDateTime since);
    List<SecurityEvent> findBySourceAndAnalyzedFalseOrderByReceivedAtAsc(String source, Pageable page);
    long countBySourceAndAnalyzedFalse(String source);
    long countByProcessedFalse();
    long countByPublishedFalse();
    @Lock(jakarta.persistence.LockModeType.PESSIMISTIC_WRITE)
    @Query("select e from SecurityEvent e where e.eventId = :id")
    java.util.Optional<SecurityEvent> lock(@Param("id") String id);
}
