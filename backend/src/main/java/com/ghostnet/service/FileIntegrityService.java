package com.ghostnet.service;
import com.ghostnet.model.FileIntegrityBaseline;
import com.ghostnet.repository.FileIntegrityRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.transaction.support.TransactionTemplate;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.ZonedDateTime;
import java.util.*;

/** Persistent approved baseline, with separate observed state so repeated polls do not flood alerts. */
@Service @RequiredArgsConstructor
public class FileIntegrityService {
    private final FileIntegrityRepository baselines;
    private final SecurityEventPipeline pipeline;
    private final TransactionTemplate tx;
    private final com.ghostnet.repository.IngestionCursorRepository cursors;
    @Value("${ghostnet.fim.roots:}") private String configuredRoots;
    @Value("${ghostnet.fim.max-files:100000}") private int maxFiles;
    private volatile String lastError="";
    private volatile ZonedDateTime lastScan;
    private List<Path> roots() { return Arrays.stream(configuredRoots.split(";")).filter(s->!s.isBlank()).map(s->Path.of(s.trim()).toAbsolutePath().normalize()).toList(); }
    public static String hash(Path path) throws Exception {
        var digest=MessageDigest.getInstance("SHA-256");
        try(var stream=Files.newInputStream(path)) { byte[] buffer=new byte[65536];int n;while((n=stream.read(buffer))!=-1) digest.update(buffer,0,n); }
        return HexFormat.of().formatHex(digest.digest());
    }
    private String id(String path) throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(path.getBytes(java.nio.charset.StandardCharsets.UTF_8))); }
    private Map<String,String> snapshot() throws Exception {
        Map<String,String> state=new TreeMap<>();
        for(var root:roots()) {
            if(!Files.isDirectory(root,LinkOption.NOFOLLOW_LINKS)) throw new IllegalStateException("Monitored root unavailable: "+root);
            try(var walk=Files.walk(root)) {
                var iterator=walk.filter(p->Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS)).iterator();
                while(iterator.hasNext()) {
                    var path=iterator.next();
                    if(state.size()>=maxFiles) throw new IllegalStateException("FIM file limit exceeded; previous baseline retained");
                    state.put(path.toAbsolutePath().normalize().toString(),hash(path));
                }
            }
        }
        return state;
    }
    public synchronized Map<String,Object> approve(String username) throws Exception {
        if(roots().isEmpty()) throw new IllegalArgumentException("Configure GHOSTNET_FIM_ROOTS before approving a baseline");
        var snapshot=snapshot();
        List<FileIntegrityBaseline> fresh=new ArrayList<>();
        for(var item:snapshot.entrySet()) fresh.add(FileIntegrityBaseline.builder().baselineId(id(item.getKey())).path(item.getKey())
            .approvedHash(item.getValue()).observedHash(item.getValue()).approvedBy(username).approvedAt(ZonedDateTime.now()).checkedAt(ZonedDateTime.now()).build());
        tx.executeWithoutResult(status->{
            baselines.deleteAllInBatch();baselines.saveAll(fresh);
            cursors.save(new com.ghostnet.model.IngestionCursor("fim:approval",System.currentTimeMillis(),roots().toString()));
        });
        return status();
    }
    @Scheduled(fixedDelayString="${ghostnet.fim.interval-ms:30000}")
    public synchronized void reconcile() {
        if(roots().isEmpty()) return;
        if(!cursors.findById("fim:approval").map(c->roots().toString().equals(c.getIdentity())).orElse(false)) {
            lastError="Approve a baseline for the configured roots";return;
        }
        try {
            var current=snapshot();
            tx.executeWithoutResult(status->{
                var known=new HashMap<String,FileIntegrityBaseline>();baselines.findAll().forEach(b->known.put(b.getPath(),b));
                var paths=new TreeSet<>(known.keySet());paths.addAll(current.keySet());
                for(var path:paths) {
                    var prior=known.get(path);String observed=current.get(path);
                    if(prior==null) {
                        try { prior=FileIntegrityBaseline.builder().baselineId(id(path)).path(path).build(); }
                        catch(Exception ex) { throw new IllegalStateException(ex); }
                    }
                    if(!Objects.equals(prior.getObservedHash(),observed)) {
                        String change=observed==null?"deleted":prior.getObservedHash()==null?"created":"modified";
                        pipeline.record("fim:"+UUID.randomUUID(),"fim","127.0.0.1",null,"high",
                            change+" "+path+" approved="+prior.getApprovedHash()+" observed="+observed,ZonedDateTime.now());
                    }
                    prior.setObservedHash(observed);prior.setCheckedAt(ZonedDateTime.now());baselines.save(prior);
                }
            });lastScan=ZonedDateTime.now();lastError="";
        } catch(Exception ex) { lastError=ex.getMessage(); }
    }
    public Map<String,Object> status() {
        Map<String,Object> result=new LinkedHashMap<>();result.put("roots",roots().stream().map(Path::toString).toList());
        result.put("baselineFiles",baselines.count());result.put("lastScan",lastScan);result.put("error",lastError);
        result.put("enabled",!roots().isEmpty());return result;
    }
}
