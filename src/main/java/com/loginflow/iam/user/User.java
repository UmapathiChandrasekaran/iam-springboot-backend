package com.loginflow.iam.user;

import java.time.LocalDateTime;

import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;

@Entity
@Table(name = "users")
public class User {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(unique = true, nullable = true)
	private String username;

	@Column(nullable = true)
	@JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
	private String password;

	@Column(nullable = true)
	private String userType;

	@Column(nullable = true)
	private Boolean isBlocked;

	@Column(name = "created_at", nullable = false, updatable = false)
	@JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
	private LocalDateTime createdAt;

	@Column(name = "totp_secret", nullable = true)
	private String totpSecret;

	@Column(name = "is_totp_enabled", nullable = false, columnDefinition = "BOOLEAN DEFAULT FALSE")
	private Boolean isTotpEnabled = false;

	@Column(name = "is_external_user")
	private Boolean externalUser = false;

	@PrePersist
	protected void onCreate() {
		this.createdAt = LocalDateTime.now();
	}

	public User() {
	}

	public User(Long id, String username, String password, String userType, Boolean isBlocked,
			LocalDateTime createdAt) {
		super();
		this.id = id;
		this.username = username;
		this.password = password;
		this.userType = userType;
		this.isBlocked = isBlocked;
		this.createdAt = createdAt;
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		if (username != null) {
			this.username = username.toLowerCase().trim();
		} else {
			this.username = null;
		}
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getUserType() {
		return userType;
	}

	public void setUserType(String userType) {
		this.userType = userType;
	}

	public Boolean isBlocked() {
		return isBlocked;
	}

	public void setBlocked(Boolean isBlocked) {
		this.isBlocked = isBlocked;
	}

	public LocalDateTime getCreatedAt() {
		return createdAt;
	}

	public void setCreatedAt(LocalDateTime createdAt) {
		this.createdAt = createdAt;
	}

	public String getTotpSecret() {
		return totpSecret;
	}

	public void setTotpSecret(String totpSecret) {
		this.totpSecret = totpSecret;
	}

	public Boolean isTotpEnabled() {
		return isTotpEnabled;
	}

	public void setTotpEnabled(Boolean totpEnabled) {
		this.isTotpEnabled = totpEnabled;
	}

	public Boolean isExternalUser() {
		return externalUser;
	}

	public void setExternalUser(Boolean externalUser) {
		this.externalUser = externalUser;
	}

}
