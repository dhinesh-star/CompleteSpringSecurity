package com.spring_security.Security.service;

import com.spring_security.Security.model.AppUser;
import com.spring_security.Security.model.Roles;
import com.spring_security.Security.repo.RoleRepo;
import com.spring_security.Security.repo.UserRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepo userRepo;
    private final RoleRepo roleRepo;

    public Object saveUser(AppUser user) {
        AppUser appUser = userRepo.findByName(user.getName()).orElse(null);
        if (appUser != null) {
            throw new RuntimeException("User already exists");
        }
        userRepo.save(user);
        String dataString = user.getName() + " is user save to Database";
        Object object = dataString;
        return object;
    }

    public Object saveRole(Roles role) throws RuntimeException {
        Roles roles = roleRepo.findByRole(role.getRole()).orElse(null);
        if (roles != null) {
            throw new RuntimeException("Role already exists");
        }
        roleRepo.save(role);
        String dataString = role.getRole() + " is role save to Database";
        Object object = dataString;
        return object;
    }

    public Object getAllUsers() {
        Object data = userRepo.findAll();
        return data;
    }

    public Object saveUserWithRoles(String userName, String role) throws RuntimeException {
        AppUser user = userRepo.findByName(userName)
                .orElseThrow(() -> new RuntimeException(userName + " is not found in database"));
        Roles roles = roleRepo.findByRole(role)
                .orElseThrow(() -> new RuntimeException(role + " is not found in database"));

        user.getRolesSet().add(roles);
//        roles.getUserSet().add(user);
        userRepo.save(user);
//        roleRepo.save(roles);
        String rolesSetToString = user.getRolesSet().stream()
                .map(Roles::getRole)
                .collect(Collectors.joining(", "));
        String dataString = user.getName() + " is mapped to these roles " + rolesSetToString;
        Object object = dataString;
        return object;
    }
}
