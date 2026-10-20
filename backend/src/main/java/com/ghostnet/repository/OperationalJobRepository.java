package com.ghostnet.repository;
import com.ghostnet.model.OperationalJob;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;
import java.time.ZonedDateTime;
import java.util.List;
public interface OperationalJobRepository extends JpaRepository<OperationalJob,String> {
    List<OperationalJob> findByEnabledTrueAndNextRunBefore(ZonedDateTime now);
    @Lock(jakarta.persistence.LockModeType.PESSIMISTIC_WRITE)
    @Query("select j from OperationalJob j where j.jobId=:id") java.util.Optional<OperationalJob> lock(@Param("id") String id);
}
