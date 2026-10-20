package com.ghostnet.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.ghostnet.model.IdsRule;

@Repository
public interface IdsRuleRepository extends JpaRepository<IdsRule, Long> {
    List<IdsRule> findByActiveTrue();
    List<IdsRule> findBySeverityGreaterThanEqualAndActiveTrue(int minSeverity);
    List<IdsRule> findByRuleName(String ruleName);
    @org.springframework.data.jpa.repository.Modifying
    @org.springframework.data.jpa.repository.Query("update IdsRule r set r.matchCount=r.matchCount+:count where r.ruleId=:id")
    void incrementMatches(@org.springframework.data.repository.query.Param("id") Long id,@org.springframework.data.repository.query.Param("count") long count);
}
