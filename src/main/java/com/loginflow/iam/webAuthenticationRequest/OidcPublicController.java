package com.loginflow.iam.webAuthenticationRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import com.loginflow.iam.auth.aaa.oidc.OidcConfiguration;
import com.loginflow.iam.auth.aaa.oidc.OidcConfigurationRepository;
import com.loginflow.iam.config.jwt.JwtUtils;

import com.loginflow.iam.user.User;
import com.loginflow.iam.user.UserRepository;
import com.loginflow.iam.user.session.Session;
import com.loginflow.iam.user.session.SessionRepository;

import jakarta.servlet.http.HttpServletResponse;
import tools.jackson.databind.ObjectMapper;

import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/public/oidc")
public class OidcPublicController {

	@Value("${iam.frontend.url}")
	private String frontendUrl;

	@Autowired
	private OidcConfigurationRepository configRepository;

	@Autowired
	private JwtUtils jwtUtils;

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private SessionRepository sessionRepository;

	@GetMapping("/status")
	public ResponseEntity<?> checkOidcStatus() {
		OidcConfiguration config = configRepository.findById(1L).orElse(new OidcConfiguration());
		return ResponseEntity.ok(Map.of("enabled", config.isOidcEnabled()));
	}

	@GetMapping("/login-url")
	public ResponseEntity<?> getLoginUrl() {
		OidcConfiguration config = configRepository.findById(1L).orElseThrow();

		String baseUrl = config.getOidcIssuerUrl();
		if (!baseUrl.endsWith("/auth")) {
			baseUrl = baseUrl + "/o/oauth2/v2/auth";
		}

		String url = baseUrl + "?client_id=" + config.getOidcClientId()
				+ "&redirect_uri=http://localhost:8080/api/public/oidc/callback" + "&response_type=code"
				+ "&scope=openid profile email" + "&prompt=select_account";

		return ResponseEntity.ok(Map.of("url", url));
	}

	@GetMapping("/callback")
	public void oidcCallback(@RequestParam("code") String code, HttpServletResponse response) throws Exception {
		OidcConfiguration config = configRepository.findById(1L).orElseThrow();

		RestTemplate restTemplate = new RestTemplate();
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

		String requestBody = "code=" + code + "&client_id=" + config.getOidcClientId() + "&client_secret="
				+ config.getOidcClientSecret() + "&redirect_uri=http://localhost:8080/api/public/oidc/callback"
				+ "&grant_type=authorization_code";

		HttpEntity<String> request = new HttpEntity<>(requestBody, headers);

		try {
			ResponseEntity<Map> tokenResponse = restTemplate.postForEntity("https://oauth2.googleapis.com/token",
					request, Map.class);

			if (tokenResponse.getStatusCode().is2xxSuccessful()) {
				Map<String, Object> body = tokenResponse.getBody();

				// 1. EXTRACT THE REAL EMAIL FROM GOOGLE'S ID TOKEN
				String email = "GOOGLE_USER";
				if (body.containsKey("id_token")) {
					String idToken = (String) body.get("id_token");
					String[] parts = idToken.split("\\.");
					String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
					Map<String, Object> payloadMap = new ObjectMapper().readValue(payload, Map.class);
					if (payloadMap.containsKey("email")) {
						email = (String) payloadMap.get("email");
					}
				}

				final String finalEmail = email;

				// 2. SECURITY GATE: Check if user exists and is blocked FIRST
				Optional<User> existingUserOpt = userRepository.findByUsername(finalEmail);

				if (existingUserOpt.isPresent() && Boolean.TRUE.equals(existingUserOpt.get().isBlocked())) {
					System.out.println("[IAM ALERT] Blocked user attempted OIDC federation: " + finalEmail);
					// Bounce them immediately back to Angular with a specific error code
					response.sendRedirect(frontendUrl + "/login?error=ACCOUNT_BLOCKED");
					return; // HALT EXECUTION HERE
				}

				// 3. JUST-IN-TIME PROVISIONING (Create user if they don't exist)
				User oidcUser = existingUserOpt.orElseGet(() -> {
					User newUser = new User();
					newUser.setUsername(finalEmail);
					newUser.setBlocked(false);
					newUser.setPassword("OIDC_EXTERNAL_AUTH");
					newUser.setUserType("USER");
					newUser.setExternalUser(true);
					return userRepository.save(newUser);
				});

				// 4. Generate your internal JWT
				String internalJwt = jwtUtils.generateToken(oidcUser.getUsername(), "ROLE_" + oidcUser.getUserType());

				// 5. SAVE THE SESSION TO THE DATABASE!
				Session newSession = new Session();
				newSession.setSessionToken(internalJwt);
				newSession.setUser(oidcUser);
				newSession.setCreatedAt(LocalDateTime.now());
				newSession.setExpiresAt(LocalDateTime.now().plusHours(8));
				sessionRepository.save(newSession);

				// 6. Redirect back to Angular seamlessly
				response.sendRedirect(frontendUrl + "/login?token=" + internalJwt);
			} else {
				response.sendRedirect(frontendUrl + "/login?error=OIDC_FAILED");
			}
		} catch (Exception e) {
			e.printStackTrace();
			response.sendRedirect(frontendUrl + "/login?error=GOOGLE_REJECTED");
		}
	}
}