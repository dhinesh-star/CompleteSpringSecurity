package com.spring_security.Security.repo;

import com.spring_security.Security.model.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepo extends JpaRepository<AppUser, Integer> {

     Optional<AppUser> findByName(String name);
}
