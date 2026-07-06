package com.loginflow.iam.webAuthenticationRequest;

/**
 * Data Transfer Object capturing incoming login credentials from Postman.
 */

public class LoginRequest {
	private String username;
	private String password;

	// Default constructor required by Jackson JSON parser
	public LoginRequest() {
	}

	public LoginRequest(String username, String password) {
		this.username = username;
		this.password = password;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}
}
