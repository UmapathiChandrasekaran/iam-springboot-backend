package com.loginflow.iam.config;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.loginflow.iam.user.session.Session;
import com.loginflow.iam.user.session.SessionRepository;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;


@Component
public class SessionAuthFilter extends OncePerRequestFilter{
	
	private final SessionRepository sessionRepository;

	@Autowired
	public SessionAuthFilter(SessionRepository sessionRepository) {
		this.sessionRepository = sessionRepository;
	}
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

        String path = request.getRequestURI();

        if (path.equals("/error") || 
            path.equals("/api/login") || 
            path.equals("/api/login/mfa/verify") || 
            path.startsWith("/api/public/")) {
            
            // Let the request pass through WITHOUT checking for a token
            filterChain.doFilter(request, response);
            return; // EXIT THE FILTER IMMEDIATELY
        }

		// 3. Intercept and extract our custom Session Token from the HTTP header
		String authToken = request.getHeader("X-IAM-SESSION-ID");
		
		// 4. Validate the incoming token
		if (authToken != null && !authToken.trim().isEmpty()) {
			
			Optional<Session> sessionOpt = sessionRepository.findBySessionToken(authToken);
			if (sessionOpt.isPresent()) {
				Session currentSession = sessionOpt.get();
				
				if (currentSession.getExpiresAt().isAfter(LocalDateTime.now())) {
					
					if (currentSession.getLastLogoutAt() != null) {
						filterChain.doFilter(request, response);
						return;
					}
					
					String username = currentSession.getUser().getUsername();
					String role = currentSession.getUser().getUserType();
					final String finalRole = "ROLE_" + role;
					UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
							username, null, Collections.singletonList(() -> finalRole) // Binds ROLE_USER or ROLE_ADMIN
					);

					// Anchor this identity into the ThreadLocal Application Context.
					SecurityContextHolder.getContext().setAuthentication(authentication);
				}
			}
		}
		
		filterChain.doFilter(request, response);
	}

}