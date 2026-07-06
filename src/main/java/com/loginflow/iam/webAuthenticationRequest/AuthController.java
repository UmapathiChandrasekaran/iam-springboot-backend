package com.loginflow.iam.webAuthenticationRequest;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.loginflow.iam.user.User;
import com.loginflow.iam.user.UserRepository;
import com.loginflow.iam.user.UserService;
import com.loginflow.iam.auth.Authenticator;
import com.loginflow.iam.auth.TotpEngine;
import com.loginflow.iam.auth.passwordhashing.PasswordService;

import jakarta.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/api")
public class AuthController {

	private final UserService userService;
	private final UserRepository userRepository;
	private final Authenticator masterAuthEngine;
	private final TotpEngine totpEngine;

	@Autowired
	public AuthController(UserService userService, UserRepository userRepository, Authenticator masterAuthEngine,
			TotpEngine totpEngine) {
		this.userService = userService;
		this.userRepository = userRepository;
		this.masterAuthEngine = masterAuthEngine;
		this.totpEngine = totpEngine;
	}

	/**
	 * STAGE 1: Standard Credential Gatekeeper
	 */
	@PostMapping("/login")
	public ResponseEntity<?> login(@RequestBody LoginRequest loginPayload, HttpServletRequest request) {
		String username = loginPayload.getUsername();
		String password = loginPayload.getPassword();

		if (!masterAuthEngine.authenticate(username, password)) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials provided.");
		}

		User user = userRepository.findByUsername(username).orElse(null);

		if (user == null) {
			System.out.println("[JIT PROVISIONING] External LDAP User detected. Creating local profile for: " + username);
			user = new User();
			user.setUsername(username);
			user.setPassword("LDAP_MANAGED_ACCOUNT"); // Dummy password (LDAP handles real auth)
			user.setUserType("USER"); // Default role
			user.setBlocked(false);
			user.setTotpEnabled(false);
			user.setExternalUser(true);
			userRepository.save(user);
		}

		if (user.isBlocked() != null && user.isBlocked()) {
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body("ACCOUNT_SUSPENDED_CONTACT_ADMIN");
		}

		if (user.isTotpEnabled() != null && user.isTotpEnabled()) {
			Map<String, Object> mfaChallenge = new HashMap<>();
			mfaChallenge.put("mfaRequired", true);
			mfaChallenge.put("username", user.getUsername());
			return ResponseEntity.ok(mfaChallenge);
		}

		String clientIp = request.getRemoteAddr();
		
		// *NOTE: If your userService.login() attempts to re-verify the password against the DB, 
		// you will need to update it to just generate the token, because LDAP users have "LDAP_MANAGED_ACCOUNT" as their DB password!
		String sessionToken = userService.login(username, password, clientIp);

		HttpHeaders responseHeaders = new HttpHeaders();
		responseHeaders.set("X-IAM-SESSION-ID", sessionToken);

		Map<String, Object> standardSuccess = new HashMap<>();
		standardSuccess.put("mfaRequired", false);
		standardSuccess.put("userType", user.getUserType());

		return new ResponseEntity<>(standardSuccess, responseHeaders, HttpStatus.OK);
	}

	// INSIDE AuthController.java

		/**
		 * STAGE 2 LOGIN: Time-Based Verification Gate (Enforces Token Creation)
		 */
		@PostMapping("/login/mfa-verify")
		public ResponseEntity<?> verifyLoginOtpChallenge(@RequestBody Map<String, String> payload, HttpServletRequest request) {
			String username = payload.get("username");
			String codeStr = payload.get("code");

			if (username == null || codeStr == null) {
				return ResponseEntity.badRequest().body("MISSING_CHALLENGE_PARAMETERS");
			}

			User user = userRepository.findByUsername(username)
					.orElseThrow(() -> new RuntimeException("Identity context profile has expired."));

			try {
				int code = Integer.parseInt(codeStr);

				// Cryptographically test the login pin against the saved secret
				if (totpEngine.verifyCode(user.getTotpSecret(), code)) {
					
					String clientIp = request.getRemoteAddr();
					String finalSecureToken = userService.createMfaSession(user.getUsername(), clientIp);

					HttpHeaders responseHeaders = new HttpHeaders();
					responseHeaders.set("X-IAM-SESSION-ID", finalSecureToken);

					Map<String, Object> mfaSuccess = new HashMap<>();
					mfaSuccess.put("userType", user.getUserType());

					return new ResponseEntity<>(mfaSuccess, responseHeaders, HttpStatus.OK);
				} else {
					return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("INVALID_MFA_TOKEN_CODE");
				}
			} catch (NumberFormatException e) {
				return ResponseEntity.badRequest().body("MFA_CODE_MUST_BE_NUMERIC");
			}
		}

	@PostMapping("/logout")
	public ResponseEntity<String> logout(@RequestHeader(value = "X-IAM-SESSION-ID", required = false) String token) {
		if (token != null && !token.trim().isEmpty()) {
			userService.logout(token);
		}
		return ResponseEntity.ok("Logged out successfully.");
	}
}