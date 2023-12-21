package com.springsecurity.security.services.impl;

import com.springsecurity.security.dto.*;
import com.springsecurity.security.entities.Role;
import com.springsecurity.security.entities.User;
import com.springsecurity.security.repository.UserRepository;
import com.springsecurity.security.services.AuthenticationService;
import com.springsecurity.security.services.JWTService;
import com.springsecurity.security.dto.SignUpResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {
    /*
        Service to Sign Up new user and save to database
     */

    // Instantiate object for UserRepository
    private final UserRepository userRepository;
    // Instantiate object to encode password
    private final PasswordEncoder passwordEncoder;
    // Instantiate object for Authentication Manager
    private final AuthenticationManager authenticationManager;
    // Instantiate object for JWT Service
    private final JWTService jwtService;

    public SignUpResponse signUpRequest(SignUpRequest signUpRequest) {
        /*
            Function to sign up new user
            - The new user details are fetched through the passed "SignUpRequest"
            - The model entity "User" is instantiated
            - The details from "SignUpRequest" are fed to "User"
            - The "User" details are saved to the database
            - A new "SignUpResponse" is created and details from "SignUpRequest" are fed to it
            - The "SignUpResponse" is returned
         */

        // Instantiate a new User object
        User user = new User();

        // Feed details to User object from SignUpRequest
        // - Password needs to be encoded before saving to User model entity
        user.setEmail(signUpRequest.getEmail());
        user.setFirstname(signUpRequest.getFirstName());
        user.setSecondname(signUpRequest.getLastName());
        user.setRole(Role.USER);
        user.setPassword(passwordEncoder.encode(signUpRequest.getPassword()));

        // Save details to the database
        userRepository.save(user);

        // Create a new sing-up response
        SignUpResponse signUpResponse = new SignUpResponse();

        // Set fields for sign-up response
        signUpResponse.setFirstName(signUpRequest.getFirstName());
        signUpResponse.setLastName(signUpRequest.getLastName());
        signUpResponse.setEmail(signUpRequest.getEmail());
        signUpResponse.setUsername(signUpRequest.getEmail());

        // Return the sign-up response
        return signUpResponse;
    }

    public JwtAuthenticationResponse signInRequest(SignInRequest signInRequest) {
        /*
            Function to validate a Sign In Request and generate JWT token for the user
         */

        try {
            // Use Authentication Manager to validate the user from "Sign In Request"
            // - The Authentication Manager checks using the Authentication Provider if the user exist in database
            // - If the user does not exist, an "Authentication Exception" is thrown here
            // - This "Authentication Exception" is caught by the "catch" block and handled by it
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                    signInRequest.getEmail(),
                    signInRequest.getPassword()
            ));

            // At this point, the username and password are correct
            // This means that the username and password exist in the database

            // Collect the user details by email using "UserRepository"
            // - Otherwise, throw Illegal Argument Exception stating that user was not found in database
            var user = userRepository.findByEmail(signInRequest.getEmail())
                    .orElseThrow(()-> new IllegalArgumentException("User not found"));

            // Create JWT Token for the user
            var jwtToken = jwtService.generateToken(user);
            // Create new JWT refresh Token for the user
            var refreshToken = jwtService.generateRefreshedToken(new HashMap<>(), user);

            // Instantiate JWT authentication response
            JwtAuthenticationResponse jwtAuthenticationResponse = new JwtAuthenticationResponse();

            // Send created JWT Token and Refresh JWT Token to JWT Authentication response
            jwtAuthenticationResponse.setToken(jwtToken);
            jwtAuthenticationResponse.setRefreshToken(refreshToken);

            // Return JWT Authentication Response
            return jwtAuthenticationResponse;
        }
        catch (AuthenticationException authenticationException) {
            // Throw exception stating the username or password is incorrect
            throw new IllegalArgumentException("Invalid username or password");
        }
    }

    public JwtAuthenticationResponse refreshToken(RefreshTokenRequest refreshTokenRequest) {
        /*
            Function to refresh JWT Token
            - Function takes input as an HTTP API request
            - The Refresh JWT Token is fetched from the HTTP API request
            - Using the Refresh JWT Token, the User details are fetched by User Repository
            - A new JWT Token is generated using the User details
            - The new JWT Token is sent back as a response to the user
         */

        // Get token details from Refresh Token Request
        var refreshToken = refreshTokenRequest.getToken();

        // Get user details from the Old JWT Token
        String userEmail = jwtService.extractUserName(refreshToken);

        // Get user details from database
        // - Otherwise, throw Illegal Argument Exception stating that user was not found in database
        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(()-> new IllegalArgumentException("User not found"));

        // Check if user is not "null" and if JWT Token is valid
        // - Both these functionalities are in the "isTokenValid" method of "JWT Service"
        if(jwtService.isTokenValid(refreshToken, user)) {
            // Create JWT Token for the user
            var jwtToken = jwtService.generateToken(user);

            // Instantiate JWT authentication response
            JwtAuthenticationResponse jwtAuthenticationResponse = new JwtAuthenticationResponse();

            // Send created JWT Token and Refresh JWT Token to JWT Authentication response
            jwtAuthenticationResponse.setToken(jwtToken);
            jwtAuthenticationResponse.setRefreshToken(refreshToken);

            // Return JWT Authentication Response
            return jwtAuthenticationResponse;
        }

        // Otherwise, either the user is "null" or the Refresh JWT Token is not valid
        // Return "null"
        return null;
    }
}
