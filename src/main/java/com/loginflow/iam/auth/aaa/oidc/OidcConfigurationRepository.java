package com.loginflow.iam.auth.aaa.oidc;

import org.springframework.data.jpa.repository.JpaRepository;

public interface OidcConfigurationRepository extends JpaRepository<OidcConfiguration, Long> {
}