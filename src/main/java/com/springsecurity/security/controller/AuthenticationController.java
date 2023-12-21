package com.springsecurity.security.controller;

import com.springsecurity.security.dto.*;
import com.springsecurity.security.services.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    /*
        Class to act as authentication API Gateway for users
     */

    // Instantiate Authentication Service object
    private final AuthenticationService authenticationService;

    @PostMapping("/signup")
    public ResponseEntity<SignUpResponse> signup(@RequestBody SignUpRequest signUpRequest) {
        /*
            Function to sign up new user
            - Function uses Authentication Service to persist new user data to database
            - Function returns a User object on successful sign up
         */
        return ResponseEntity.ok(authenticationService.signUpRequest(signUpRequest));
    }

    @PostMapping("/signin")
    public ResponseEntity<JwtAuthenticationResponse> signin(@RequestBody SignInRequest signInRequest) {
        /*
            Function to sign in new user
            - Function uses Authentication Service to sign in existing user
            - Function provides JWT Token in response to a successful sign in
         */
        return ResponseEntity.ok(authenticationService.signInRequest(signInRequest));
    }

    @PostMapping("/refresh")
    public ResponseEntity<JwtAuthenticationResponse> refresh(@RequestBody RefreshTokenRequest refreshTokenRequest) {
        /*
            Function to refresh JWT Token
            - Function uses Authentication Service to refresh JWT Token of existing user
            - Function provides JWT Token in response to a successful refresh of JWT Token
         */
        return ResponseEntity.ok(authenticationService.refreshToken(refreshTokenRequest));
    }
}
