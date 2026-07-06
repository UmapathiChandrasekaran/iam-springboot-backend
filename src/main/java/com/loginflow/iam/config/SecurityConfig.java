package com.loginflow.iam.config;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration("customIamSecurityConfig")
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

	private final SessionAuthFilter sessionAuthFilter;

	@Autowired
	public SecurityConfig(SessionAuthFilter sessionAuthFilter) {
		this.sessionAuthFilter = sessionAuthFilter;
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
				// Disable default features we don't need for programmatic REST APIs
				.cors(cors -> cors.configurationSource(corsConfigurationSource())).csrf(csrf -> csrf.disable())
				.formLogin(form -> form.disable()).httpBasic(basic -> basic.disable())

				// Force the application to be completely stateless (no tracking cookies)
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

				// Set up our endpoint routing gatekeeper rules
				.authorizeHttpRequests(auth -> auth
						.requestMatchers(org.springframework.http.HttpMethod.OPTIONS, "/**").permitAll() 
						.requestMatchers("/api/login").permitAll()
						.requestMatchers("/favicon.ico").permitAll()
						.requestMatchers("/api/login/mfa-verify").permitAll()
						.requestMatchers("/api/public/oidc/status").permitAll()
						.requestMatchers("/api/public/oidc/login-url").permitAll()
						.requestMatchers("/api/public/oidc/callback").permitAll()
						.requestMatchers("/error").permitAll() 
						.requestMatchers("/api/**").authenticated()
				)
				.exceptionHandling(
						exception -> exception.authenticationEntryPoint((request, response, authException) -> {
							// Log the block event in your server console
							System.out.println("[SECURITY ALERT!!!!] Blocked unauthenticated request to: "
									+ request.getRequestURI());

							// Return a clean JSON object to the client (Postman)
							response.setStatus(jakarta.servlet.http.HttpServletResponse.SC_UNAUTHORIZED);
							response.setContentType("application/json");
							response.getWriter().write(
									"{\"status\": 401, \"error\": \"Unauthorized\", \"message\": \"Missing or invalid X-IAM-SESSION-ID header.\"}");
						}))

				// Inject our custom filter right into Spring's security pipeline
				.addFilterBefore(sessionAuthFilter, UsernamePasswordAuthenticationFilter.class);

		return http.build();
	}

	@Bean
	public UserDetailsService userDetailsService() {
		// Returning an empty manager satisfies Spring's auto-config check,
		// silencing the console alert without changing your custom filter logic!
		return new InMemoryUserDetailsManager();
	}

	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(List.of("http://localhost:4200")); // Trusted Angular Port
		configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
		configuration.setAllowedHeaders(List.of("Content-Type", "X-IAM-SESSION-ID"));
		configuration.setExposedHeaders(List.of("X-IAM-SESSION-ID")); // Allows UI layer to extract token
		configuration.setAllowCredentials(true);

		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}
}
