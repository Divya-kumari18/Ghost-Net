package com.ghostnet.service;

import com.ghostnet.model.IntegrationSetting;
import com.ghostnet.repository.IntegrationSettingRepository;
import org.junit.jupiter.api.*;
import org.springframework.mock.env.MockEnvironment;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class IntegrationSettingsServiceTest {
    IntegrationSettingRepository repo;
    IntegrationSettingsService service;
    AtomicReference<IntegrationSetting> stored;
    @BeforeEach void setup() {
        repo=mock(IntegrationSettingRepository.class);stored=new AtomicReference<>();
        when(repo.findById(anyString())).thenAnswer(call->Optional.ofNullable(stored.get()));
        when(repo.saveAndFlush(any())).thenAnswer(call->{stored.set(call.getArgument(0));return stored.get();});
        service=new IntegrationSettingsService(repo,new MockEnvironment().withProperty("ghostnet.jwt.secret","test-server-secret").withProperty("ghostnet.zap.api-key","environment-key"));
    }
    @Test void credentialsAreEncryptedAndNeverReturnedInMetadata() {
        var result=service.save("zap",new IntegrationSettingsService.Update(true,"http://127.0.0.1:8090/","secret-test-key",false));
        assertFalse(stored.get().getEncryptedKey().contains("secret-test-key"));
        assertEquals("secret-test-key",service.get("zap").apiKey());
        assertFalse(result.containsKey("apiKey"));assertFalse(result.containsKey("encryptedKey"));
        assertEquals("http://127.0.0.1:8090",result.get("baseUrl"));
    }
    @Test void blankKeyPreservesExistingAndExplicitClearRemovesIt() {
        service.save("zap",new IntegrationSettingsService.Update(false,"http://localhost:8090","",false));
        assertEquals("environment-key",service.get("zap").apiKey());
        service.save("zap",new IntegrationSettingsService.Update(false,"http://localhost:8090",null,true));
        assertEquals("",service.get("zap").apiKey());
    }
    @Test void rejectsUnknownServiceAndUnsafeEndpointForms() {
        assertThrows(IllegalArgumentException.class,()->service.save("other",new IntegrationSettingsService.Update(true,"https://example.test","x",false)));
        for(String url:List.of("http://example.test","file:///etc/passwd","https://user:pass@example.test","https://example.test?key=secret"))assertThrows(IllegalArgumentException.class,()->service.save("virustotal",new IntegrationSettingsService.Update(true,url,"x",false)));
    }
}
