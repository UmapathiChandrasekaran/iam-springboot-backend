package com.loginflow.iam.auth;

public interface Authenticator {
	
	boolean authenticate(String username, String inboundSecret);
	
	String getEngineName();
}
