package com.loginflow.iam.config;

import org.springframework.context.annotation.Configuration;
import com.loginflow.iam.user.User;
import com.loginflow.iam.user.UserRepository;
import com.loginflow.iam.auth.passwordhashing.PasswordService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;

@Configuration
public class DataInitializer {

	@Bean
	CommandLineRunner initDatabase(UserRepository userRepository, PasswordService passwordService) {
		return args -> {
			// Check if Admin exists
			if (userRepository.findByUsernameIgnoreCase("admin").isEmpty()) {
				User admin = new User();
				admin.setUsername("admin");
				// Hashing the password using your secure PasswordService adapter
				admin.setPassword(passwordService.hash("admin123"));
				admin.setUserType("ADMIN");
				admin.setBlocked(false);

				userRepository.save(admin);
				System.out.println("[IAM INIT] Root Admin account initialized successfully.");
			}
		};
	}
}