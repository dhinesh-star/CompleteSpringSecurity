package com.spring_security.Security.config;

import com.spring_security.Security.model.AppUser;
import com.spring_security.Security.repo.UserRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class MyAppUserService implements UserDetailsService {

    private final UserRepo userRepo;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser currentUser = userRepo.findByName(username)
                .orElseThrow(() -> new UsernameNotFoundException(username + " not found in database"));
        List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
        currentUser.getRolesSet().stream()
                .map(role -> new SimpleGrantedAuthority(role.getRole()))
                .forEach(role -> grantedAuthorities.add(role));
        return new User(currentUser.getName(), currentUser.getPassword(), grantedAuthorities);
    }
}
