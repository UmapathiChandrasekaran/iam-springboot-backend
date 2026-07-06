package com.loginflow.iam.auth.aaa.oidc;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/config/oidc") // Admin Config Path
@CrossOrigin(origins = "http://localhost:4200", exposedHeaders = "X-IAM-SESSION-ID")
public class OidcConfigController {

    @Autowired
    private OidcConfigurationRepository configRepository;

    @GetMapping
    public OidcConfiguration getOidcConfig() {
        return configRepository.findById(1L).orElseGet(() -> {
            OidcConfiguration defaultConfig = new OidcConfiguration();
            defaultConfig.setOidcEnabled(false);
            return configRepository.save(defaultConfig);
        });
    }

    @PutMapping
    public OidcConfiguration updateOidcConfig(@RequestBody OidcConfiguration config) {
        config.setId(1L); // Force singleton overwrite
        return configRepository.save(config);
    }
}