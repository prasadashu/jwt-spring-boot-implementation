package com.springsecurity.security.dto;

import lombok.Data;

@Data
public class RefreshTokenRequest {
    /*
        Class holding fields to be sent in POST request to API
        - The "RefreshTokenRequest" will be sent to API when existing user logs in
        - The existing JWT Token will be sent to the API using which a refreshed JWT Token will be created
     */
    private String token;
}
