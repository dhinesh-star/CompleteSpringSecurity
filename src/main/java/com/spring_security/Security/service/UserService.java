package com.spring_security.Security.service;

import com.spring_security.Security.constants.ApplicationConstants;
import com.spring_security.Security.model.AppUser;
import com.spring_security.Security.model.Roles;
import com.spring_security.Security.repo.RoleRepo;
import com.spring_security.Security.repo.UserRepo;
import com.spring_security.Security.utils.JwtUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepo userRepo;
    private final RoleRepo roleRepo;
    private final AuthenticationManager authenticationManager;
    private final Environment env;

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

    public Object authenticateUser(String username, String password) throws RuntimeException {
        Authentication unauthenticated = UsernamePasswordAuthenticationToken.unauthenticated(username, password);
        Authentication authenticated = authenticationManager.authenticate(unauthenticated);
        List<String> authenticationList = authenticated.getAuthorities().stream().map(grandedAuthority -> grandedAuthority.getAuthority())
                .collect(Collectors.toList());
        String accessToken = JwtUtils.getAcessToken("Security Practice", authenticated.getName(), authenticationList, env.getProperty(ApplicationConstants.JWT_SECRET, ApplicationConstants.JWT_SECRET_DEFAULT_KEY));
        Object data = accessToken;
        return data;
    }
}
