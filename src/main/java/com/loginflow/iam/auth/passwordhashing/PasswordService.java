package com.loginflow.iam.auth.passwordhashing;

public interface PasswordService 
{
	
	String hash(String rawPassword);

	boolean verify(String rawPassword, String hashedPassword);
}
