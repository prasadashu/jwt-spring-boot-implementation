package com.springsecurity.security.dto;

import lombok.Data;

@Data
public class JwtAuthenticationResponse {
    /*
        Class holding fields sent by Spring Boot server to user
        - The "JwtAuthenticationResponse" will be sent by server to user when JWT Token is generated or refreshed
     */
    private String token;
    private String refreshToken;
}
