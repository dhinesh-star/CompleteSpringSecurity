package com.spring_security.Security.controller;

import com.spring_security.Security.dto.requestDto.RequestRolesDTO;
import com.spring_security.Security.dto.requestDto.RequestUserDTO;
import com.spring_security.Security.dto.requestDto.UsersAndRolesDTO;
import com.spring_security.Security.dto.responseDto.FinalDTO;
import com.spring_security.Security.model.AppUser;
import com.spring_security.Security.model.Roles;
import com.spring_security.Security.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

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
}
