package com.loginflow.iam.webAuthenticationRequest;

import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.loginflow.iam.auth.TotpEngine;
import com.loginflow.iam.user.User;
import com.loginflow.iam.user.UserService;
import com.loginflow.iam.user.dto.MfaSetupResponse;
import com.loginflow.iam.user.dto.PasswordChangeRequest;

@RestController
@RequestMapping("/api/users")
public class UserController {

	private final UserService userService;
	private final TotpEngine totpEngine;

	@Autowired
	public UserController(UserService userService, TotpEngine totpEngine) {
		this.userService = userService;
		this.totpEngine = totpEngine;
	}

	@GetMapping("/me")
	public ResponseEntity<User> getCurrentUserSessionContext() {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		if (auth == null || !auth.isAuthenticated()) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
		}

		// Look up account records directly out of the database tier via service layer
		User currentUser = userService.findAll().stream().filter(user -> user.getUsername().equals(auth.getName()))
				.findFirst()
				.orElseThrow(() -> new RuntimeException("Authenticated session principal missing from database."));

		return ResponseEntity.ok(currentUser);
	}

	@PostMapping("/block/{id}")
	public ResponseEntity<?> blockUser(@PathVariable Long id) {
		try {
			userService.blockUser(id);
			return ResponseEntity.ok("Operation completed successfully.");
		} catch (SecurityException e) {
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(e.getLocalizedMessage());
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error executing block routine.");
		}
	}

	@PutMapping("/edit")
	public ResponseEntity<?> editUser(@RequestBody User modifiedUserPayload) {
		try {
			userService.editUser(modifiedUserPayload);
			return ResponseEntity.ok("User profile modifications saved successfully.");
		} catch (SecurityException e) {
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(e.getMessage());
		} catch (IllegalArgumentException e) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body("Error modifying user registration data.");
		}
	}

	@DeleteMapping("/delete/{id}")
	public ResponseEntity<?> deleteUser(@PathVariable Long id) {
		try {
			userService.deleteUser(id);
			return ResponseEntity.ok("User account deleted permanently.");
		} catch (SecurityException e) {
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(e.getMessage());
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error processing removal task.");
		}
	}

	@PostMapping("/add")
	public ResponseEntity<?> addUser(@RequestBody User newAccountPayload) {
		try {
			userService.addUser(newAccountPayload);
			return ResponseEntity.status(HttpStatus.CREATED).body("User account created successfully.");
		} catch (SecurityException e) {
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(e.getMessage());
		} catch (IllegalStateException e) {
			return ResponseEntity.status(HttpStatus.CONFLICT).body(e.getMessage());
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error saving new account payload.");
		}
	}

	@PostMapping("/unblock/{id}")
	public ResponseEntity<?> unblockUser(@PathVariable Long id) {
		try {
			userService.unblockUser(id);
			return ResponseEntity.ok("Operation completed successfully.");
		} catch (SecurityException e) {
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(e.getMessage());
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body("Error clearing user network constraints.");
		}
	}

	@GetMapping("/list")
	public ResponseEntity<List<User>> listAllUsers() {
		return ResponseEntity.ok(userService.findAll());
	}

	@PostMapping("/change-password")
	public ResponseEntity<?> changePassword(@RequestBody PasswordChangeRequest request) {
		String username = SecurityContextHolder.getContext().getAuthentication().getName();

		try {
			userService.changePassword(username, request);
			return ResponseEntity.ok("Password updated successfully");
		} catch (SecurityException e) {
			return ResponseEntity.status(403).body(e.getMessage());
		} catch (Exception e) {
			return ResponseEntity.status(500).body("Error updating password");
		}
	}

	@GetMapping("/mfa/setup")
	public ResponseEntity<MfaSetupResponse> setupMfa() {
		String username = SecurityContextHolder.getContext().getAuthentication().getName();
		MfaSetupResponse setupData = userService.generateMfaSetup(username);
		return ResponseEntity.ok(setupData);
	}

	@PostMapping("/mfa/verify")
	public ResponseEntity<?> verifyMfaActivation(@RequestBody Map<String, String> body) {
		String username = SecurityContextHolder.getContext().getAuthentication().getName();

		if (body == null || !body.containsKey("code")) {
			return ResponseEntity.badRequest().body("MISSING_MFA_TOKEN_CODE");
		}

		try {
			int code = Integer.parseInt(body.get("code"));
			boolean dynamicTokenMatch = userService.verifyAndActivateMfa(username, code);

			if (dynamicTokenMatch) {
				return ResponseEntity.ok("MULTI_FACTOR_ACTIVATION_CONFIRMED");
			} else {
				return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("INVALID_MFA_TOKEN_CODE");
			}
		} catch (NumberFormatException e) {
			return ResponseEntity.badRequest().body("MFA_CODE_MUST_BE_A_VALID_NUMBER");
		}
	}

	@PostMapping("/mfa/disable-override")
	public ResponseEntity<?> disableMfaByAdmin(@RequestBody Map<String, String> body) {
		String requester = SecurityContextHolder.getContext().getAuthentication().getName();
		String targetUser = body.get("username");
		try {
			userService.administrativeMfaDisable(targetUser, requester);
			return ResponseEntity.ok("MFA_DISABLED_SUCCESSFULLY");
		} catch (SecurityException e) {
			return ResponseEntity.status(403).body(e.getMessage());
		}
	}

	@PostMapping("/force-password-override")
	public ResponseEntity<?> forcePasswordByAdmin(
			@RequestBody com.loginflow.iam.user.dto.ForcePasswordRequest request) {
		String requester = SecurityContextHolder.getContext().getAuthentication().getName();
		try {
			userService.administrativeForcePassword(request.getUsername(), request.getNewPassword(), requester);
			return ResponseEntity.ok("PASSWORD_FORCED_SUCCESSFULLY");
		} catch (SecurityException e) {
			return ResponseEntity.status(403).body(e.getMessage());
		}
	}
}