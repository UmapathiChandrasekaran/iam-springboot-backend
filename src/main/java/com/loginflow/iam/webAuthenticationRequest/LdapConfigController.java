package com.loginflow.iam.webAuthenticationRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.loginflow.iam.auth.aaa.ldap.LdapConfiguration;
import com.loginflow.iam.auth.aaa.ldap.LdapConfigurationRepository;

@RestController
@RequestMapping("/api/ldap-config")
public class LdapConfigController {
	
	@Autowired
    private LdapConfigurationRepository repository;

    // Fetch the current configuration for the UI
    @GetMapping
    public ResponseEntity<LdapConfiguration> getConfiguration() {
        LdapConfiguration config = repository.findById(1L).orElse(null);
        
        // If booting for the first time, create a default row to prevent UI crashes
        if (config == null) {
            config = new LdapConfiguration();
            config.setId(1L);
            config.setLdapEnabled(false);
            config.setLdapsSecureProtocol(false);
            repository.save(config);
        }
        
        return ResponseEntity.ok(config);
    }

    // Save configurations sent from the Angular UI
    @PutMapping
    public ResponseEntity<LdapConfiguration> updateConfiguration(@RequestBody LdapConfiguration updatedConfig) {
        // Hardcode ID to 1L to enforce the Singleton pattern (only 1 row allowed)
        updatedConfig.setId(1L);
        LdapConfiguration savedConfig = repository.save(updatedConfig);
        return ResponseEntity.ok(savedConfig);
    }

}
