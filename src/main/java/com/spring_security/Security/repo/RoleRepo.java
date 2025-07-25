package com.spring_security.Security.repo;

import com.spring_security.Security.model.Roles;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepo extends JpaRepository<Roles, Integer> {
     Optional<Roles> findByRole(String role);
}
