package com.loginflow.iam.auth.aaa.oidc;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "oidc_configurations")
public class OidcConfiguration {

	@Id
	private Long id = 1L; // Singleton pattern

	private boolean oidcEnabled;
	private String oidcClientId;
	private String oidcClientSecret;
	private String oidcIssuerUrl;

	// --- Getters and Setters ---
	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public boolean isOidcEnabled() {
		return oidcEnabled;
	}

	public void setOidcEnabled(boolean oidcEnabled) {
		this.oidcEnabled = oidcEnabled;
	}

	public String getOidcClientId() {
		return oidcClientId;
	}

	public void setOidcClientId(String oidcClientId) {
		this.oidcClientId = oidcClientId;
	}

	public String getOidcClientSecret() {
		return oidcClientSecret;
	}

	public void setOidcClientSecret(String oidcClientSecret) {
		this.oidcClientSecret = oidcClientSecret;
	}

	public String getOidcIssuerUrl() {
		return oidcIssuerUrl;
	}

	public void setOidcIssuerUrl(String oidcIssuerUrl) {
		this.oidcIssuerUrl = oidcIssuerUrl;
	}
}
