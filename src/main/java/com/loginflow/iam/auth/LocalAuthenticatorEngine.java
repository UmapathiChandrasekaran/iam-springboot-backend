package com.loginflow.iam.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import com.loginflow.iam.auth.passwordhashing.PasswordService;
import com.loginflow.iam.user.User;
import com.loginflow.iam.user.UserRepository;

@Service("localAuthenticatorEngine")
public class LocalAuthenticatorEngine implements Authenticator {
	@Autowired
	private PasswordService passwordService; // Uses the interface
	@Autowired
	private UserRepository userRepository;

	@Override
	public boolean authenticate(String username, String inboundSecret) { 
		// 1. Fetch user locally
		User user = userRepository.findByUsername(username).orElse(null);

		// 2. Block if they don't exist locally, or if inputs are blank
		if (user == null || inboundSecret == null || inboundSecret.isBlank()) {
			System.out.println("DEBUG: Local Auth blocked: User not found or empty inputs.");
			return false;
		}

		// 3. Perform the verification
		boolean isMatch = passwordService.verify(inboundSecret, user.getPassword());
		System.out.println("DEBUG: Local Auth match result: " + isMatch);
		return isMatch;
	}

	@Override
	public String getEngineName() {
		return "Local_Authenticator";
	}
}
