package com.loginflow.iam.auth;

import java.util.Collections;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import com.loginflow.iam.auth.Authenticator;
import com.loginflow.iam.user.User;
import com.loginflow.iam.user.UserRepository;

import com.loginflow.iam.auth.aaa.oidc.OidcConfiguration;
import com.loginflow.iam.auth.aaa.oidc.OidcConfigurationRepository;

@Service
public class OidcAuthenticatorEngine implements Authenticator {

	@Autowired
	private OidcConfigurationRepository configRepo;

	@Autowired
	private UserRepository userRepository;

	@Override
	public boolean authenticate(String username, String inboundSecret) {
		OidcConfiguration config = configRepo.findById(1L).orElse(null);

		// 1. Block if OIDC is disabled by the Administrator
		if (config == null || !config.isOidcEnabled()) {
			System.out.println("[OIDC ENGINE] REJECTED: OIDC Federation is disabled.");
			return false;
		}

		try {
			System.out.println("[OIDC ENGINE] Intercepted Federated Token. Verifying Signature...");

			// 2. Build the Google Cryptographic Verifier
			// It automatically fetches Google's public keys to verify the token signature
			GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(new NetHttpTransport(),
					new GsonFactory())
					// Verify the 'aud' claim matches YOUR Client ID from the DB
					.setAudience(Collections.singletonList(config.getOidcClientId()))
					// Verify the 'iss' claim matches the Google Issuer from the DB
					.setIssuer(config.getOidcIssuerUrl()).build();

			// 3. Perform the Mathematical Verification
			// inboundSecret is the massive JWT string passed from the Angular frontend
			GoogleIdToken idToken = verifier.verify(inboundSecret);

			if (idToken != null) {
				GoogleIdToken.Payload payload = idToken.getPayload();

				// 4. Extract verified identity details
				String verifiedEmail = payload.getEmail();
				boolean emailVerified = Boolean.valueOf(payload.getEmailVerified());

				// Optional: Extract Name/Picture if needed later
				// String name = (String) payload.get("name");
				// String pictureUrl = (String) payload.get("picture");

				if (!emailVerified) {
					System.out.println("[OIDC ENGINE] REJECTED: Google reports email is not verified.");
					return false;
				}

				System.out.println(
						"[OIDC ENGINE] SUCCESS: Google Cryptographic Signature Validated for: " + verifiedEmail);

				// 5. Just-In-Time (JIT) Account Provisioning
				// If the user's Google email isn't in our PostgreSQL DB yet, create an account
				// automatically.
				provisionUserIfNeeded(verifiedEmail);

				// 6. Enforce Username matching.
				// We enforce that the username entered in the frontend MUST match the verified
				// Google email.
				if (!username.equalsIgnoreCase(verifiedEmail)) {
					System.out.println(
							"[OIDC ENGINE] REJECTED: Frontend username does not match the token's embedded email.");
					return false;
				}

				return true;
			} else {
				System.out.println("[OIDC ENGINE] REJECTED: Invalid ID token signature or expired token.");
				return false;
			}

		} catch (Exception e) {
			System.out.println(
					"[OIDC ENGINE] CRITICAL ERROR: Federated Identity verification failed -> " + e.getMessage());
			return false;
		}
	}

	@Override
	public String getEngineName() {
		return "OIDC_FEDERATED_BROKER";
	}

	private void provisionUserIfNeeded(String email) {
		Optional<User> existingUser;
		try {
			existingUser = userRepository.findByUsernameIgnoreCase(email);

			if (existingUser.isEmpty()) {
				System.out.println("[OIDC ENGINE] JIT PROVISIONING: Creating new local account for " + email);
				User newUser = new User();
				newUser.setUsername(email);
				newUser.setUserType("USER"); // Default to standard user
				newUser.setBlocked(false);
				newUser.setTotpEnabled(false);
				// We intentionally leave password blank/null because they login via Google
				userRepository.save(newUser);
			}
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
