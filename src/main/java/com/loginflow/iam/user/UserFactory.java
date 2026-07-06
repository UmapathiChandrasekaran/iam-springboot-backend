package com.loginflow.iam.user;

import java.time.LocalDateTime;

public class UserFactory {
	public static User createUser(String username, String rawPassword, String type) {
		User user = new User();
		user.setUsername(username);
		user.setPassword(rawPassword); 
		user.setCreatedAt(LocalDateTime.now());
		user.setBlocked(false); // Accounts start active by default

		if ("ADMIN".equalsIgnoreCase(type)) {
			user.setUserType("ADMIN");
		} else if ("STANDARD".equalsIgnoreCase(type)) {
			user.setUserType("STANDARD");
		} else {
			throw new IllegalArgumentException("Unknown Enterprise User Type: " + type);
		}
		return user;
	}
}
