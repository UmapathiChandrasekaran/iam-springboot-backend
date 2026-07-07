package com.loginflow.iam.user;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import com.loginflow.iam.auth.Authenticator;
import com.loginflow.iam.auth.TotpEngine;
import com.loginflow.iam.auth.passwordhashing.PasswordService;
import com.loginflow.iam.config.jwt.JwtUtils;
import com.loginflow.iam.user.dto.MfaSetupResponse;
import com.loginflow.iam.user.dto.PasswordChangeRequest;
import com.loginflow.iam.user.session.Session;
import com.loginflow.iam.user.session.SessionRepository;

import jakarta.transaction.Transactional;

@Service
public class UserService {

	private final UserRepository userRepository;
	private final Authenticator authenticator;
	private final SessionRepository sessionRepository;
	private PasswordService passwordService;
	private TotpEngine totpEngine;
	private final JwtUtils jwtUtils;

	@Autowired
	public UserService(UserRepository userRepository, Authenticator authenticator, PasswordService passwordService,
			SessionRepository sessionRepository, TotpEngine totpEngine, JwtUtils jwtUtils) {
		this.userRepository = userRepository;
		this.authenticator = authenticator;
		this.sessionRepository = sessionRepository;
		this.passwordService = passwordService;
		this.totpEngine = totpEngine;
		this.jwtUtils = jwtUtils;
	}

	@Transactional
	public String login(String username, String password, String ipAddress) {
		User user = userRepository.findByUsernameIgnoreCase(username)
				.orElseThrow(() -> new RuntimeException("Authentication failed: Invalid credentials provided."));

		if (user.isBlocked() != null && user.isBlocked()) {
			throw new IllegalStateException("Account is suspended. Contact system administrator.");
		}

		boolean isMatch = authenticator.authenticate(username, password);
		if (!isMatch) {
			throw new RuntimeException("Authentication failed: Invalid credentials provided.");
		}

		// Generate the real dynamic session structure tracking metadata parameters
		String randomToken = jwtUtils.generateToken(user.getUsername(), user.getUserType());
		Session session = new Session();
		session.setSessionToken(randomToken);
		session.setUser(user);
		session.setIpAddress(ipAddress); // Sets IP Address directly onto the session mapping
		session.setCreatedAt(LocalDateTime.now());
		session.setExpiresAt(LocalDateTime.now().plusHours(2));
		session.setLastLoginAt(LocalDateTime.now()); // Populated inside the session context loop
		System.out.println("[USER SERVICE] Issued standard JWT for: " + username + " " + randomToken);
		sessionRepository.save(session);
		return randomToken;
	}

	@Transactional
	public void logout(String token) {
		if (token != null && !token.trim().isEmpty()) {
			sessionRepository.findBySessionToken(token).ifPresent(session -> {
				// 1. Mark the log out action timestamp for operational auditing
				session.setLastLogoutAt(LocalDateTime.now());
				sessionRepository.save(session);
			});
		}
	}

	@Transactional
	private String getCurrentContextUsername() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null || !authentication.isAuthenticated()) {
			throw new SecurityException("Access Denied: Unauthenticated system access attempt.");
		}
		return authentication.getName();
	}

	@Transactional
	private void validateAdminSessionRole() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null) {
			throw new SecurityException("Access Denied: Missing authentication token context.");
		}

		boolean isAdmin = authentication.getAuthorities().stream()
				.anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals("ROLE_ADMIN"));

		if (!isAdmin) {
			throw new SecurityException("Access Denied: This operation requires elevated 'ADMIN' privileges.");
		}
	}

	@Transactional
	public void blockUser(Long targetUserId) {
		// 1. Enforce that only valid ADMIN connections pass through
		validateAdminSessionRole();

		User targetUser = userRepository.findById(targetUserId)
				.orElseThrow(() -> new IllegalArgumentException("Target user identity not found."));

		// 2. Prevent Self-Block: Capture current caller context username
		String currentActorUsername = getCurrentContextUsername();
		if (targetUser.getUsername().equals(currentActorUsername)) {
			throw new SecurityException(
					"Access Denied: Operational security parameters prohibit users from blocking their own connection node.");
		}

		// 3. Hierarchical Admin Protection: Distinguish Root Admin from Normal Admins
		if ("ADMIN".equalsIgnoreCase(targetUser.getUserType())) {

			// Define your ultimate root account username here
			final String ROOT_ADMIN_USERNAME = "admin";

			// Rule A: The absolute Root Admin can NEVER be blocked by anyone.
			if (targetUser.getUsername().equalsIgnoreCase(ROOT_ADMIN_USERNAME)) {
				throw new SecurityException(
						"Access Denied: Core Root Administrative system privileges cannot be blocked or suspended.");
			}

			// Rule B: If the target is a normal Admin, only the Root Admin is authorized to
			// block them.
			// If the caller is anyone else, reject the request.
			if (!currentActorUsername.equalsIgnoreCase(ROOT_ADMIN_USERNAME)) {
				throw new SecurityException(
						"Access Denied: Insufficient clearance. Only the Root Administrator can suspend other Admin accounts.");
			}
		}

		// Everything passes clear, commit suspension flag modification data onto
		// storage records
		targetUser.setBlocked(true);
		userRepository.save(targetUser);
	}

	@Transactional
	public void unblockUser(Long targetUserId) {
		// 1. Enforce that only valid ADMIN connections pass through
		validateAdminSessionRole();

		User targetUser = userRepository.findById(targetUserId)
				.orElseThrow(() -> new IllegalArgumentException("Target user identity not found."));

		// 2. Prevent Self-Unblock: Capture current caller context username
		String currentActorUsername = getCurrentContextUsername();
		if (targetUser.getUsername().equals(currentActorUsername)) {
			throw new SecurityException(
					"Access Denied: Operational security parameters prohibit users from unblocking their own connection node.");
		}

		// Everything passes validation clear: toggle the suspension flag to false
		targetUser.setBlocked(false);
		userRepository.save(targetUser);
	}

	@Transactional
	public void editUser(User modifiedUserPayload) {
		if (modifiedUserPayload == null || modifiedUserPayload.getId() == null) {
			throw new IllegalArgumentException("Invalid user modifications: Missing target record identifier.");
		}

		User existingUser = userRepository.findById(modifiedUserPayload.getId()).orElseThrow(
				() -> new IllegalArgumentException("The user record you are trying to modify does not exist."));

		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null) {
			throw new SecurityException("Access Denied: Missing session validation context tokens.");
		}

		String currentActorUsername = authentication.getName();
		boolean actorIsAdmin = authentication.getAuthorities().stream()
				.anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals("ROLE_ADMIN"));
		boolean actorIsRoot = "admin".equalsIgnoreCase(currentActorUsername);

		// RULE 1: Root admin is untouched. No one can do anything to them, even
		// themselves.
		if ("admin".equalsIgnoreCase(existingUser.getUsername())) {
			throw new SecurityException(
					"Access Denied : The Root Admin is untouched. No modifications allowed.");
		}

		if (actorIsAdmin) {
			// RULE 3 & 4: Normal Admin Logic
			if (!actorIsRoot) {
				// RULE 3: An admin user cannot modify their own profile.
				if (existingUser.getUsername().equalsIgnoreCase(currentActorUsername)) {
					throw new SecurityException(
							"Access Denied: Normal admins cannot modify their own profile. Contact Root.");
				}
				// RULE 4 is implicitly allowed here: Normal admins CAN modify other normal
				// admins and normal users.
			}
			// RULE 2 is implicitly allowed here: Root admin bypasses the self-edit block
			// and has all permissions.
		} else {
			// RULE 5a: Normal users can modify themselves...
			if (!existingUser.getUsername().equalsIgnoreCase(currentActorUsername)) {
				throw new SecurityException(
						"Access Denied : Standard users can only modify their own profile.");
			}
		}

		// Apply the username changes
		existingUser.setUsername(modifiedUserPayload.getUsername());

		// RULE 5b: ...but normal users cannot modify their role.
		if (actorIsAdmin) {
			existingUser.setUserType(modifiedUserPayload.getUserType());
		} else {
			// Force the role to stay "USER" if a standard user tries to hack the payload
			existingUser.setUserType("USER");
		}

		userRepository.save(existingUser);
	}

	@Transactional
	public void deleteUser(Long targetUserId) {
		User targetUser = userRepository.findById(targetUserId).orElseThrow(() -> new IllegalArgumentException(
				"Target user identity not found. Cannot delete non-existent record."));
		String currentActorUsername = getCurrentContextUsername();

		// Admin Protection: Distinguish Root Admin from Normal Admins
		if ("ADMIN".equalsIgnoreCase(targetUser.getUserType())) {

			// Define your ultimate root account username here
			final String ROOT_ADMIN_USERNAME = "admin";

			// Rule A: The absolute Root Admin can NEVER be blocked by anyone.
			if (targetUser.getUsername().equalsIgnoreCase(ROOT_ADMIN_USERNAME)) {
				throw new SecurityException(
						"Access Denied: Core Root Administrative system privileges cannot be wiped.");
			}

			// Rule B: If the target is a normal Admin, only the Root Admin is authorized to
			// block them.
			// If the caller is anyone else, reject the request.
			if (!currentActorUsername.equalsIgnoreCase(ROOT_ADMIN_USERNAME)) {
				throw new SecurityException(
						"Access Denied: Insufficient clearance. Only the Root Administrator can wipe other Admin accounts.");
			}
		}

		// Identify the active execution actor context token profiles parameters
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null) {
			throw new SecurityException("Access Denied: Missing verification signature clearances tokens.");
		}

		boolean actorIsAdmin = authentication.getAuthorities().stream()
				.anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals("ROLE_ADMIN"));

		// 1. Wipe out active tracking sessions across connected client layout spaces
		// first
		sessionRepository.deleteByUserId(targetUserId);

		// 2. Discard the core identity credentials profile safely from the database
		// parent table
		userRepository.delete(targetUser);
	}

	@Transactional
	public User addUser(User newAccountPayload) {
		validateAdminSessionRole();
		if (newAccountPayload == null || newAccountPayload.getUsername() == null) {
			throw new IllegalArgumentException("Invalid registration data: Username is strictly required.");
		}

		boolean exists = userRepository.findByUsernameIgnoreCase(newAccountPayload.getUsername()).isPresent();
		if (exists) {
			throw new IllegalStateException("Registration failed: Username is already registered in the system.");
		}

		newAccountPayload.setCreatedAt(LocalDateTime.now());
		newAccountPayload.setBlocked(false);
		newAccountPayload.setPassword(passwordService.hash(newAccountPayload.getPassword()));
		return userRepository.save(newAccountPayload);
	}

	@Transactional
	public List<com.loginflow.iam.user.User> findAll() {
		return userRepository.findAll();
	}

	@Transactional
	public void changePassword(String username, PasswordChangeRequest request) {
		// 1. HARD RULE: Immutable Root Protection Gate
		if ("admin".equalsIgnoreCase(username)) {
			throw new SecurityException("ROOT_ADMIN_PROTECTED_TASK_DENIED");
		}

		User user = userRepository.findByUsernameIgnoreCase(username)
				.orElseThrow(() -> new RuntimeException("User not found"));

		if (Boolean.TRUE.equals(user.isExternalUser())) {
			throw new SecurityException("[IAM POLICY] Federated users cannot modify local credentials.");
		}

		// 2. Verify current password matches the stored cryptographic hash
		if (!passwordService.verify(request.getCurrentPassword(), user.getPassword())) {
			throw new SecurityException("Invalid current password");
		}

		// 3. Securely hash new password and commit to database registry
		user.setPassword(passwordService.hash(request.getNewPassword()));
		userRepository.save(user);
	}

	@Transactional
	public boolean verifyAndActivateMfa(String username, int code) {
		User user = userRepository.findByUsernameIgnoreCase(username)
				.orElseThrow(() -> new RuntimeException("Identity profile not found"));

		if (Boolean.TRUE.equals(user.isExternalUser())) {
			throw new SecurityException("[IAM POLICY] Federated users cannot modify local credentials.");
		}

		if (totpEngine.verifyCode(user.getTotpSecret(), code)) {
			user.setTotpEnabled(true);
			userRepository.save(user);
			return true;
		}
		return false;
	}

	@Transactional
	public MfaSetupResponse generateMfaSetup(String username) {

		// HARD CONSTRAINT: Immutable Root Protection Gate
		if ("admin".equalsIgnoreCase(username)) {
			throw new SecurityException("ROOT_ADMIN_MFA_PROHIBITED");
		}

		User user = userRepository.findByUsernameIgnoreCase(username)
				.orElseThrow(() -> new RuntimeException("Identity profile not found"));

		if (Boolean.TRUE.equals(user.isExternalUser())) {
			throw new SecurityException("[IAM POLICY] Federated users cannot modify local credentials.");
		}
		if (!user.isTotpEnabled()) {
			user.setTotpSecret(totpEngine.generateSecretKey());
			userRepository.save(user);
		}

		String configString = "Account: " + username + " | Key: " + user.getTotpSecret();
		String qrCodeImageStr = totpEngine.generateQrCodeBase64(username, user.getTotpSecret());

		return new MfaSetupResponse(user.getTotpSecret(), configString, qrCodeImageStr);
	}

	@Transactional
	public void administrativeMfaDisable(String targetUsername, String requester) {

		if ("admin".equalsIgnoreCase(targetUsername)) {
			throw new SecurityException("ROOT_ADMIN_MFA_IS_IMMUTABLE");
		}

		User user = userRepository.findByUsernameIgnoreCase(targetUsername)
				.orElseThrow(() -> new RuntimeException("Identity not found"));

		user.setTotpSecret(null);
		user.setTotpEnabled(false);
		userRepository.save(user);
	}

	@Transactional
	public void administrativeForcePassword(String targetUsername, String newPassword, String requester) {
		if (!"ADMIN".equalsIgnoreCase(
				userRepository.findByUsernameIgnoreCase(requester).map(User::getUserType).orElse(""))) {
			throw new SecurityException("UNAUTHORIZED_ADMIN_ACTION");
		}

		if (targetUsername.equalsIgnoreCase(requester)) {
			throw new SecurityException(
					"Access Denied: Proceed to self-service policy card below to modify your active access key");
		}

		if ("admin".equalsIgnoreCase(targetUsername)) {
			throw new SecurityException("ROOT_ADMIN_PASSWORD_IS_IMMUTABLE");
		}

		User user = userRepository.findByUsernameIgnoreCase(targetUsername)
				.orElseThrow(() -> new RuntimeException("Identity not found"));

		user.setPassword(passwordService.hash(newPassword));
		userRepository.save(user);
	}

	@Transactional
	public String createMfaSession(String username, String ipAddress) {
		User user = userRepository.findByUsernameIgnoreCase(username)
				.orElseThrow(() -> new RuntimeException("User not found"));

		// Generate the token and officially save it to PostgreSQL
		String randomToken = jwtUtils.generateToken(user.getUsername(), user.getUserType());
		Session session = new Session();
		session.setSessionToken(randomToken);
		session.setUser(user);
		session.setIpAddress(ipAddress);
		session.setCreatedAt(LocalDateTime.now());
		session.setExpiresAt(LocalDateTime.now().plusHours(2));
		session.setLastLoginAt(LocalDateTime.now());
		System.out.println("[USER SERVICE] Issued MFA-Verified JWT for: " + randomToken);

		sessionRepository.save(session);
		return randomToken;
	}

}