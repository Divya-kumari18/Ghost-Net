package com.ghostnet.service;

import com.ghostnet.model.IntegrationSetting;
import com.ghostnet.repository.IntegrationSettingRepository;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import javax.crypto.Cipher;
import javax.crypto.spec.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;

@Service
public class IntegrationSettingsService {
    private final IntegrationSettingRepository repo;
    private final Environment env;
    private final SecretKeySpec encryptionKey;
    public record Config(boolean enabled,String baseUrl,String apiKey) {}
    public record Update(boolean enabled,String baseUrl,String apiKey,boolean clearApiKey) {}
    public IntegrationSettingsService(IntegrationSettingRepository repo,Environment env) {
        this.repo=repo; this.env=env;
        try {
            String secret=env.getProperty("ghostnet.integrations.encryption-key",env.getRequiredProperty("ghostnet.jwt.secret"));
            encryptionKey=new SecretKeySpec(MessageDigest.getInstance("SHA-256").digest(("GhostNet integration credentials\n"+secret).getBytes(StandardCharsets.UTF_8)),"AES");
        } catch(Exception ex) {throw new IllegalStateException("Integration credential encryption unavailable",ex);}
    }
    public static void validateService(String service) {
        if (!Set.of("zap","virustotal").contains(service)) throw new IllegalArgumentException("Unknown integration");
    }
    @Transactional(readOnly=true)
    public Config get(String service) {
        validateService(service);
        var row=repo.findById(service);
        if(row.isPresent()) {var s=row.get();return new Config(s.isEnabled(),s.getBaseUrl(),decrypt(s.getEncryptedKey()));}
        String prefix="ghostnet."+service+".";
        return new Config(env.getProperty(prefix+"enabled",Boolean.class,false),env.getProperty(prefix+"base-url",service.equals("zap")?"http://127.0.0.1:8090":"https://www.virustotal.com/api/v3"),env.getProperty(prefix+"api-key",""));
    }
    public Map<String,Object> metadata(String service) {
        var c=get(service);
        return Map.of("enabled",c.enabled(),"baseUrl",c.baseUrl(),"configured",!c.apiKey().isBlank(),"message",!c.enabled()?"Disabled":c.apiKey().isBlank()?"API key missing":"Configured · connection not checked");
    }
    @Transactional
    public Map<String,Object> save(String service,Update update) {
        validateService(service);
        URI uri;
        try {uri=URI.create(update.baseUrl().trim());}catch(Exception ex){throw new IllegalArgumentException("Enter a valid service URL");}
        if(uri.getHost()==null || uri.getUserInfo()!=null || uri.getQuery()!=null || uri.getFragment()!=null || !("https".equals(uri.getScheme()) || (service.equals("zap") && "http".equals(uri.getScheme())))) throw new IllegalArgumentException("Use an HTTPS service URL (ZAP also supports HTTP), without credentials or query parameters");
        var current=get(service);
        String key=update.clearApiKey()?"":update.apiKey()==null || update.apiKey().isBlank()?current.apiKey():update.apiKey().trim();
        if(key.length()>4096 || key.chars().anyMatch(Character::isISOControl)) throw new IllegalArgumentException("Invalid API key");
        var row=new IntegrationSetting(); row.setService(service);row.setEnabled(update.enabled());row.setBaseUrl(uri.toString().replaceAll("/+$",""));row.setEncryptedKey(encrypt(key));repo.saveAndFlush(row);
        return metadata(service);
    }
    private String encrypt(String value) {
        if(value.isEmpty())return "";
        try {byte[] nonce=new byte[12];new SecureRandom().nextBytes(nonce);var cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.ENCRYPT_MODE,encryptionKey,new GCMParameterSpec(128,nonce));byte[] body=cipher.doFinal(value.getBytes(StandardCharsets.UTF_8));byte[] result=Arrays.copyOf(nonce,nonce.length+body.length);System.arraycopy(body,0,result,nonce.length,body.length);return Base64.getEncoder().encodeToString(result);}catch(Exception ex){throw new IllegalStateException("Unable to save integration credentials");}
    }
    private String decrypt(String value) {
        if(value==null || value.isEmpty())return "";
        try {byte[] body=Base64.getDecoder().decode(value);var cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.DECRYPT_MODE,encryptionKey,new GCMParameterSpec(128,Arrays.copyOf(body,12)));return new String(cipher.doFinal(body,12,body.length-12),StandardCharsets.UTF_8);}catch(Exception ex){throw new IllegalStateException("Unable to read integration credentials; restore the server encryption key");}
    }
}
