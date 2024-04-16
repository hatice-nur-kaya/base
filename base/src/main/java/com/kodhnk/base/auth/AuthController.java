package com.kodhnk.base.auth;

import com.kodhnk.base.dataAccess.UserRepository;
import com.kodhnk.base.entities.User;
import com.kodhnk.base.security.dto.CreateUserRequest;
import com.kodhnk.base.security.services.JwtService;
import com.kodhnk.base.security.services.UserService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


import java.util.Optional;


@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);
    private final UserService userService;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final UserRepository repository;

    @PostMapping("/register")
    public User addUser(@RequestBody CreateUserRequest request) {
        return userService.createUser(request);
    }


    @PostMapping("/authenticate")
    public String authenticate(@RequestBody AuthenticationRequest request) {

        log.info("Authenticating user: {}", request.getUsername());
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );

        Optional<User> userOptional = repository.findByEmail(request.getUsername());
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            var jwtToken = jwtService.generateToken(user.getUsername());
            return jwtToken;
        } else {
            return "Kullanıcı bulunamadı";
        }
    }
}