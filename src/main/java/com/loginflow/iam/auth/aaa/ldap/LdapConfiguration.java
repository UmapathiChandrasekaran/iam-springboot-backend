package com.loginflow.iam.auth.aaa.ldap;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "ldap_configurations")
public class LdapConfiguration {

	@Id
    private Long id = 1L; // Singleton pattern - only one config row needed

    // LDAP / LDAPS Operational Fields
    private boolean ldapEnabled;
    private boolean ldapsSecureProtocol; // Toggle for LDAPS (SSL/TLS)
    private String ldapServerUrl;        // e.g., ldaps://192.168.1.50:636
    private String ldapBaseDn;           // e.g., dc=corporate,dc=internal
    private String ldapManagerDn;        // e.g., cn=admin,dc=corporate,dc=internal
    private String ldapManagerPassword;  // Bind credentials
    
	public Long getId() {
		return id;
	}
	public void setId(Long id) {
		this.id = id;
	}
	public boolean isLdapEnabled() {
		return ldapEnabled;
	}
	public void setLdapEnabled(boolean ldapEnabled) {
		this.ldapEnabled = ldapEnabled;
	}
	public boolean isLdapsSecureProtocol() {
		return ldapsSecureProtocol;
	}
	public void setLdapsSecureProtocol(boolean ldapsSecureProtocol) {
		this.ldapsSecureProtocol = ldapsSecureProtocol;
	}
	public String getLdapServerUrl() {
		return ldapServerUrl;
	}
	public void setLdapServerUrl(String ldapServerUrl) {
		this.ldapServerUrl = ldapServerUrl;
	}
	public String getLdapBaseDn() {
		return ldapBaseDn;
	}
	public void setLdapBaseDn(String ldapBaseDn) {
		this.ldapBaseDn = ldapBaseDn;
	}
	public String getLdapManagerDn() {
		return ldapManagerDn;
	}
	public void setLdapManagerDn(String ldapManagerDn) {
		this.ldapManagerDn = ldapManagerDn;
	}
	public String getLdapManagerPassword() {
		return ldapManagerPassword;
	}
	public void setLdapManagerPassword(String ldapManagerPassword) {
		this.ldapManagerPassword = ldapManagerPassword;
	}

}
