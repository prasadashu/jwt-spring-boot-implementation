package com.springsecurity.security.dto;

import lombok.Data;

@Data
public class SignUpResponse {
    private String firstName;
    private String lastName;
    private String email;
    private String username;
}
