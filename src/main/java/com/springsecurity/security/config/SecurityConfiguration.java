package com.springsecurity.security.config;

import com.springsecurity.security.entities.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import com.springsecurity.security.services.UserService;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {
    /*
        Class responsible for instantiating the Security Filters
        - When Spring Application starts, Spring Security will look for a "Bean" of type "SecurityFilterChain"
        - The "SecurityFilterChain" is a Bean responsible for configuring all HTTP security of our application
     */

    // Declare object for JWT Authentication filter
    private final JwtAuthenticationFilter jwtAuthFilter;

    // Declare object for User Details Service
    private final UserService userService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        /*
            Function to create a "SecurityFilterChain"
         */
        httpSecurity
                // Disable CSRF
                .csrf(AbstractHttpConfigurer::disable)
                // Declaring authentication for API Endpoints
                .authorizeHttpRequests(request -> request
                        // Whitelisting API Endpoints
                        .requestMatchers("/api/v1/auth/**").permitAll()
                        // ADMIN API Endpoints can only be accessed by users having ADMIN Role
                        .requestMatchers("/api/v1/admin").hasAnyAuthority(Role.ADMIN.name())
                        // USER API Endpoints can only be accessed by users having USER Role
                        .requestMatchers("/api/v1/user").hasAnyAuthority(Role.USER.name())
                        // Other API Endpoints need to be authenticated
                        .anyRequest().authenticated()
                )

                // Implementing Session Management
                // - This is because HTTP API request are Stateless in nature
                // - This means that the authentication state of an HTTP request must not be stored at the server
                // - Therefore, every time we receive an HTTP request, it needs to be authenticated
                // - Using Session Management, we can ensure that each HTTP request is authenticated
                .sessionManagement(manager -> manager
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                // Implementing Authentication Provider
                // - We will call an Authentication Provider
                // - Then we will call the JWT Authorization Filter before UsernamePasswordAuthentication Filter
                // - This is because we first check if the JWT is valid and only then update the Security Context
                // - The Security Context is updated using UsernamePasswordAuthentication token
                .authenticationProvider(userService.authenticationProvider()).addFilterBefore(
                        jwtAuthFilter, UsernamePasswordAuthenticationFilter.class
                );

        return httpSecurity.build();
    }
}