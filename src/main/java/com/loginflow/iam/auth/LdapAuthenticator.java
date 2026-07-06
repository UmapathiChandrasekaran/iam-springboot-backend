package com.loginflow.iam.auth;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.ldap.CommunicationException;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.stereotype.Service;

import com.loginflow.iam.auth.aaa.ldap.LdapConfiguration;
import com.loginflow.iam.auth.aaa.ldap.LdapConfigurationRepository;

@Service
public class LdapAuthenticator implements Authenticator {

	@Autowired
	private LdapConfigurationRepository configRepo;

	@Override
	public boolean authenticate(String username, String inboundSecret) {
		LdapConfiguration config = configRepo.findById(1L).orElse(null);
		if (config == null || !config.isLdapEnabled())
			return false;

		try {
			LdapContextSource contextSource = new LdapContextSource();
			contextSource.setUrl(config.getLdapServerUrl());
			contextSource.setBase(config.getLdapBaseDn());
			contextSource.setUserDn(config.getLdapManagerDn());
			contextSource.setPassword(config.getLdapManagerPassword());

			Map<String, Object> envProps = new HashMap<>();
			envProps.put("com.sun.jndi.ldap.connect.timeout", "3000");
			envProps.put("com.sun.jndi.ldap.read.timeout", "3000");
			contextSource.setBaseEnvironmentProperties(envProps);
			contextSource.afterPropertiesSet();

			LdapTemplate ldapTemplate = new LdapTemplate(contextSource);

			String userSearchFilter = "(uid=" + username + ")";

			ldapTemplate.authenticate("", userSearchFilter, inboundSecret);
			System.out.println("[LDAP ENGINE] SUCCESS: User " + username + " verified via Remote Directory.");
			return true;

		} catch (CommunicationException e) {
			System.out.println("[LDAP ENGINE] CRITICAL: Active Directory connection timed out.");
			throw new RuntimeException("LDAP_TIMEOUT");
		} catch (Exception e) {
			// Server answered, but it was a wrong password or bad DN
			System.out.println("[LDAP ENGINE] REJECTED: Invalid Directory Credentials.");
			return false;
		}
	}

	@Override
	public String getEngineName() {
		return "LDAP_DIRECTORY_SERVICE";
	}
}