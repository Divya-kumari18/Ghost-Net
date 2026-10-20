package com.ghostnet.repository;

import com.ghostnet.model.IncidentTimeline;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface IncidentTimelineRepository extends JpaRepository<IncidentTimeline, Long> {
    List<IncidentTimeline> findByIncident_IncidentIdOrderByTimestampAsc(Long incidentId);
}
