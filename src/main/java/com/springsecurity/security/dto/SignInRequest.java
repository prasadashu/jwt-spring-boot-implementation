package com.springsecurity.security.dto;

import lombok.Data;

@Data
public class SignInRequest {
    /*
        Class holding fields to be sent in POST request to API
        - The "SignInRequest" will be sent to API when existing user logs in
     */
    private String email;
    private String password;
}
