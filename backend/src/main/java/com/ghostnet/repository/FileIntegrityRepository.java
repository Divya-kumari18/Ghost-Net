package com.ghostnet.repository;
import com.ghostnet.model.FileIntegrityBaseline;
import org.springframework.data.jpa.repository.JpaRepository;
public interface FileIntegrityRepository extends JpaRepository<FileIntegrityBaseline,String> {}
