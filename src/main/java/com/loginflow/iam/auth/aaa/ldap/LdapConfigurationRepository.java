package com.loginflow.iam.auth.aaa.ldap;

import org.springframework.data.jpa.repository.JpaRepository;

public interface LdapConfigurationRepository extends JpaRepository<LdapConfiguration, Long> {

}
