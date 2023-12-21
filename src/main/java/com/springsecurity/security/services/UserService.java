package com.springsecurity.security.services;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface UserService {
    UserDetailsService userDetailsService();
    AuthenticationProvider authenticationProvider();
}
