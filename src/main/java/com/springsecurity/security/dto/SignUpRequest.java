package com.springsecurity.security.dto;

import lombok.Data;

@Data
public class SignUpRequest {
    /*
        Class holding fields to be sent in POST request to API
        - The "SignUpRequest" will be sent to API when creating a new user
     */
    private String firstName;
    private String lastName;
    private String email;
    private String password;
}
