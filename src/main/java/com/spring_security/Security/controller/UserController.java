package com.spring_security.Security.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.spring_security.Security.constants.ApplicationConstants;
import com.spring_security.Security.dto.requestDto.RequestRolesDTO;
import com.spring_security.Security.dto.requestDto.RequestUserDTO;
import com.spring_security.Security.dto.requestDto.UsersAndRolesDTO;
import com.spring_security.Security.dto.responseDto.FinalDTO;
import com.spring_security.Security.dto.responseDto.TokenDTO;
import com.spring_security.Security.model.AppUser;
import com.spring_security.Security.model.Roles;
import com.spring_security.Security.repo.UserRepo;
import com.spring_security.Security.service.UserService;
import com.spring_security.Security.utils.JwtUtils;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final Environment env;
    private final UserRepo userRepo;

    @PostMapping("/user/save")
    public ResponseEntity saveUser(@RequestBody RequestUserDTO requestUserDTO) {
        try {
            AppUser appUser = new AppUser();
            appUser.setName(requestUserDTO.getName());
            // appUser.setPassword(requestUserDTO.getPassword());
            appUser.setPassword(passwordEncoder.encode(requestUserDTO.getPassword()));
            Object data = userService.saveUser(appUser);
            FinalDTO finalDTO = FinalDTO.builder()
                    .status(HttpStatus.CREATED.value())
                    .data(data)
                    .build();
            return new ResponseEntity<>(finalDTO, HttpStatus.CREATED);
        } catch (Exception exception){
            Object data = exception.getMessage();
            FinalDTO finalDTO = FinalDTO.builder()
                    .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
                    .data(data)
                    .build();
            return new ResponseEntity<>(finalDTO, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/roles/save")
    public ResponseEntity saveRoles(@RequestBody RequestRolesDTO requestRolesDTO) {
        Roles roles = new Roles();
        roles.setRole(requestRolesDTO.getRoleName());
        Object data = userService.saveRole(roles);
        FinalDTO finalDTO = FinalDTO.builder()
                .status(HttpStatus.CREATED.value())
                .data(data)
                .build();
        return new ResponseEntity<>(finalDTO, HttpStatus.CREATED);
    }

    @GetMapping("/getUsers")
    public ResponseEntity getUsers() {
        Object data = userService.getAllUsers();
        FinalDTO finalDTO = FinalDTO.builder()
                .status(HttpStatus.OK.value())
                .data(data)
                .build();
        return new ResponseEntity<>(finalDTO, HttpStatus.OK);
    }

    @PostMapping("/users/saveWithRole")
    public ResponseEntity saveUserWithRole(@RequestBody UsersAndRolesDTO usersAndRolesDTO){
        Object data = userService.saveUserWithRoles(usersAndRolesDTO.getUserName(),
                usersAndRolesDTO.getRole());
        FinalDTO finalDTO = FinalDTO.builder()
                .status(HttpStatus.OK.value())
                .data(data)
                .build();
        return new ResponseEntity<>(finalDTO, HttpStatus.OK);
    }

    @PostMapping("/loginUser")
    public ResponseEntity authenticateUser(@RequestBody RequestUserDTO requestUserDTO) {
        Object data = userService.authenticateUser(requestUserDTO.getName(),
                requestUserDTO.getPassword());
        FinalDTO finalDTO = FinalDTO.builder()
                .status(HttpStatus.OK.value())
                .data(data)
                .build();
        return new ResponseEntity<>(finalDTO, HttpStatus.OK);
    }

    @GetMapping("/getTokens")
    public void getTokens(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String refreshToken = request.getHeader(ApplicationConstants.JWT_HEADER);
        try {
            String accessToken = userService.getTokens(refreshToken);
            Map<String, String> tokenMap = new HashMap<>();
            tokenMap.put("access_token", accessToken);
            tokenMap.put("refresh_token", refreshToken.substring("Bearer ".length()));
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            new ObjectMapper().writeValue(response.getOutputStream(), tokenMap);
        } catch (Exception exception){
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            Map<String, String> error = new HashMap<>();
            error.put("error", exception.getMessage());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            new ObjectMapper().writeValue(response.getOutputStream(), error);
        }
    }

    @GetMapping("/getTokensUsingBody")
    public ResponseEntity getTokensUsingBody(@RequestParam("refreshToken") String refreshToken){
        try{
            String accessToken = userService.getTokens(refreshToken);
            Object data = TokenDTO.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken.substring("Bearer ".length()))
                    .build();
            return new ResponseEntity<>(data, HttpStatus.OK);
        } catch (Exception exception){
            Object data = exception.getMessage();
            return new ResponseEntity<>(data, HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
