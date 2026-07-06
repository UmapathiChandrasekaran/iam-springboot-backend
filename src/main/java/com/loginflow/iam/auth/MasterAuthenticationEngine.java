package com.loginflow.iam.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Service;

import com.loginflow.iam.auth.aaa.ldap.LdapConfiguration;
import com.loginflow.iam.auth.aaa.ldap.LdapConfigurationRepository;

@Service
@Primary
public class MasterAuthenticationEngine implements Authenticator {

	@Autowired
	private LdapAuthenticator ldapEngine;

	@Autowired
	private OidcAuthenticatorEngine oidcEngine;

	@Autowired
	private LocalAuthenticatorEngine localEngine;

	@Autowired
	private LdapConfigurationRepository configRepo;

	@Override
	public boolean authenticate(String username, String inboundSecret) {

		//oidcEngine
		if (inboundSecret != null && inboundSecret.length() > 50) {
			System.out.println("[MASTER AUTH] JWT Token detected. Routing to OIDC Engine...");
			return oidcEngine.authenticate(username, inboundSecret);
		}
		LdapConfiguration config = configRepo.findById(1L).orElse(null);

		//ldapEngine
		if (config != null && config.isLdapEnabled()) {
			try {
				System.out.println("[MASTER AUTH] Routing credentials to LDAP Engine...");
				boolean isVerified = ldapEngine.authenticate(username, inboundSecret);

				return isVerified;

			} catch (RuntimeException e) {
				if ("LDAP_TIMEOUT".equals(e.getMessage())) {
					System.out
							.println("[MASTER AUTH] ALERT: LDAP Server unreachable! Executing Failover to Local DB...");
					return localEngine.authenticate(username, inboundSecret);
				}
				return false;
			}
		}

		System.out.println("[MASTER AUTH] LDAP disabled. Routing credentials to Local DB Engine...");
		//localEngine
		return localEngine.authenticate(username, inboundSecret);
	}

	@Override
	public String getEngineName() {
		return "MASTER_IDENTITY_BROKER";
	}
}
