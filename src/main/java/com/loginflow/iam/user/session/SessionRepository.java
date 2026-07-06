package com.loginflow.iam.user.session;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SessionRepository extends JpaRepository<Session, Long>
{

	Optional<Session> findBySessionToken(String sessionToken);
	
	void deleteBySessionToken(String sessionToken);
	
	void deleteByUserId(Long userId);
	
}
