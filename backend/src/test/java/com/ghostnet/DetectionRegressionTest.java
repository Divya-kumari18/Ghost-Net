package com.ghostnet;

import com.ghostnet.capture.IdsRuleEngine;
import com.ghostnet.model.*;
import com.ghostnet.repository.*;
import com.ghostnet.security.JwtService;
import com.ghostnet.service.NmapXmlParser;
import org.junit.jupiter.api.*;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.security.core.userdetails.UserDetails;
import java.time.ZonedDateTime;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class DetectionRegressionTest {
    @Test void databaseRetryPreservesComputedStatefulDetections() {
        var trafficRepo=mock(NetworkTrafficRepository.class);var alerts=mock(NetworkAlertsRepository.class);
        var rules=mock(IdsRuleRepository.class);var engine=mock(IdsRuleEngine.class);
        var broadcaster=mock(com.ghostnet.websocket.AlertBroadcaster.class);
        var pipeline=mock(com.ghostnet.service.SecurityEventPipeline.class);
        var tx=mock(org.springframework.transaction.support.TransactionTemplate.class);
        var service=new com.ghostnet.service.NetworkAnalysisService(trafficRepo,alerts,rules,engine,broadcaster,pipeline,tx);
        var traffic=NetworkTraffic.builder().sourceIp("10.0.0.1").destinationIp("10.0.0.2").protocol("TCP").build();
        var alert=NetworkAlert.builder().rule(IdsRule.builder().ruleId(42L).build()).severity("HIGH").build();
        when(engine.match(traffic)).thenReturn(List.of(alert));
        doThrow(new IllegalStateException("simulated database failure")).doAnswer(invocation->{
            java.util.function.Consumer<org.springframework.transaction.TransactionStatus> action=invocation.getArgument(0);
            action.accept(mock(org.springframework.transaction.TransactionStatus.class));return null;
        }).when(tx).executeWithoutResult(any());
        service.processTraffic(traffic);service.drainQueue();
        verifyNoInteractions(broadcaster);
        service.drainQueue();
        verify(engine,times(1)).match(traffic);verify(broadcaster,times(1)).broadcastAlert(alert);
        verify(rules).incrementMatches(42L,1L);
    }
    @Test void cveImportAcceptsUnnamedIndexAndShortRows() throws Exception {
        var service=new com.ghostnet.service.CveImportService(mock(org.springframework.jdbc.core.JdbcTemplate.class),
            mock(CveDatabaseRepository.class),mock(IngestionCursorRepository.class),mock(org.springframework.transaction.support.TransactionTemplate.class));
        var file=java.nio.file.Path.of(getClass().getResource("/cve-regression.csv").toURI());
        assertEquals(2,service.importFromCsv(file));
    }
    @Test void distinctPortThresholdRequiresSeparateSynConnectionsWithinWindow() {
        var repo=mock(IdsRuleRepository.class);
        var rule=IdsRule.builder().ruleId(42L).ruleName("scan").ruleType("custom").severity(3)
            .thresholdCount(3).windowSeconds(10).distinctPorts(true).active(true).build();
        when(repo.findByActiveTrue()).thenReturn(List.of(rule));
        var engine=new IdsRuleEngine(repo);engine.reloadRules();
        var traffic=NetworkTraffic.builder().sourceIp("10.0.0.1").destinationIp("10.0.0.2").protocol("TCP")
            .flags("SYN").destinationPort(80).timestamp(ZonedDateTime.now()).build();
        assertTrue(engine.match(traffic).isEmpty());assertTrue(engine.match(traffic).isEmpty());
        traffic.setDestinationPort(81);assertTrue(engine.match(traffic).isEmpty());
        traffic.setFlags("SYN ACK");traffic.setDestinationPort(82);assertTrue(engine.match(traffic).isEmpty());
        traffic.setFlags("SYN");assertEquals(1,engine.match(traffic).size());
        traffic.setTimestamp(traffic.getTimestamp().plusSeconds(20));assertTrue(engine.match(traffic).isEmpty());
    }
    @Test void yaraStylePayloadUsesRegexAndRequiresPayload() {
        var repo=mock(IdsRuleRepository.class);
        var rule=IdsRule.builder().ruleName("download").ruleType("custom").severity(3).sourceIpPattern(".*")
            .protocolPattern("UDP|TCP").portPattern("80,443,8000-8080").payloadPattern("(?i)download(string)?").active(true).build();
        when(repo.findByActiveTrue()).thenReturn(List.of(rule));
        var engine=new IdsRuleEngine(repo);engine.reloadRules();
        var traffic=NetworkTraffic.builder().sourceIp("10.1.2.3").destinationIp("10.2.3.4").protocol("TCP").destinationPort(8001).build();
        assertTrue(engine.match(traffic).isEmpty());
        traffic.setDetectionPayload("\0DownloadString\r\n");assertEquals(1,engine.match(traffic).size());
        traffic.setDestinationPort(22);assertTrue(engine.match(traffic).isEmpty());
    }
    @Test void invalidRuleNeverWidensDetection() {
        var rule=IdsRule.builder().severity(3).ruleType("custom").payloadPattern("[").build();
        assertThrows(IllegalArgumentException.class,()->IdsRuleEngine.validateRule(rule));
        rule.setPayloadPattern(null);rule.setPortPattern("80-20");assertThrows(IllegalArgumentException.class,()->IdsRuleEngine.validateRule(rule));
        rule.setPortPattern("any");rule.setRuleType("snort");assertThrows(IllegalArgumentException.class,()->IdsRuleEngine.validateRule(rule));
    }
    @Test void nmapAssociatesMultipleCvesWithCorrectHostAndPort() {
        String xml="""
            <?xml version="1.0"?><!DOCTYPE nmaprun SYSTEM "file:///missing.dtd"><nmaprun>
            <host><address addr="10.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/>
            <script id="vuln" output="VULNERABLE CVE-2024-1111 and CVE-2024-2222"/></port></ports></host>
            <host><address addrtype="ipv4" addr="10.0.0.2"/><ports><port protocol="tcp" portid="22"><state state="closed"/>
            <script id="vuln" output="NOT VULNERABLE CVE-2024-3333"/></port></ports></host></nmaprun>
            """;
        var scan=VulnerabilityScan.builder().targets("10.0.0.0/24").build();
        var findings=NmapXmlParser.parse(xml,scan,false);
        assertEquals(2,findings.size());assertTrue(findings.stream().allMatch(f->"10.0.0.1".equals(f.getHostIp())));
        assertEquals(Set.of("CVE-2024-1111","CVE-2024-2222"),new HashSet<>(findings.stream().map(VulnerabilityFinding::getCveId).toList()));
        assertTrue(findings.getFirst().getVulnerabilityName().contains("tcp/80"));
        var ports=NmapXmlParser.parse(xml,scan,true);assertEquals(1,ports.size());assertEquals("info",ports.getFirst().getSeverity());
    }
    @Test void malformedNmapCannotProduceFindings() { assertThrows(IllegalArgumentException.class,()->NmapXmlParser.parse("not xml",new VulnerabilityScan(),false)); }
    @Test void jwtPurposeRevocationAndDisabledUsersAreEnforced() {
        var jwt=new JwtService();var sessions=mock(UserSessionRepository.class);
        ReflectionTestUtils.setField(jwt,"rawSecret","this-is-a-test-secret-at-least-32-bytes");
        ReflectionTestUtils.setField(jwt,"jwtExpiration",60000L);ReflectionTestUtils.setField(jwt,"refreshExpiration",120000L);
        ReflectionTestUtils.setField(jwt,"sessions",sessions);ReflectionTestUtils.invokeMethod(jwt,"initSigningKey");
        UserDetails details=org.springframework.security.core.userdetails.User.withUsername("analyst").password("unused").roles("ANALYST").build();
        var session=UserSession.builder().sessionId("sid").user(User.builder().username("analyst").build()).active(true).expiresAt(ZonedDateTime.now().plusHours(1)).build();
        when(sessions.findWithUser("sid")).thenReturn(Optional.of(session));
        var access=jwt.generateToken(Map.of("sid","sid"),details);var refresh=jwt.generateRefreshToken(details,"sid");
        assertTrue(jwt.isTokenValid(access,details));assertFalse(jwt.isTokenValid(refresh,details));
        assertTrue(jwt.isRefreshTokenValid(refresh,details));assertFalse(jwt.isRefreshTokenValid(access,details));
        session.setActive(false);assertFalse(jwt.isTokenValid(access,details));assertFalse(jwt.isRefreshTokenValid(refresh,details));
        session.setActive(true);session.setExpiresAt(ZonedDateTime.now().minusSeconds(1));assertFalse(jwt.isTokenValid(access,details));
        assertFalse(jwt.isTokenValid("invalid",details));
    }
}
