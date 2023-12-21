package com.springsecurity.security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import com.springsecurity.security.services.JWTService;
import com.springsecurity.security.services.UserService;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    /*
        Class to intercept requests made to Controller
     */
    // Instantiate JWT Service
    private final JWTService jwtService;
    // Instantiate User Service
    private final UserService userService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        /*
            Function to filter HTTP request
            - Filters are the first responders to HTTP requests
            - Filters validate the HTTP requests before the requests are routed to Servlet
            - Filters can be chained with each other
            - Thus they follow the "Chain of Responsibility" design pattern
         */

        // Get the authorization header from HTTP request
        final String authHeader = request.getHeader("Authorization");
        // Declare JWT variable to hold JWT Token
        final String jwt;
        // Declare variable to hold email which acts as the username
        final String userEmail;

        // Check if authorization header is null or if the authorization header does not start with "Bearer "
        if(authHeader == null || !authHeader.startsWith("Bearer ")) {
            // Pass request and response to next filter in chain
            filterChain.doFilter(request, response);
            // Return from the function
            return;
        }

        // At this point, the authorization header is not null and is starting with "Bearer "

        // Get the JWT Token from authorization header starting from 7'th index
        // - This is because the last index of "Bearer " string is 6 after which the JWT Token starts
        // - Index:   0 1 2 3 4 5 6
        // - String: "B e a r e r  "
        jwt = authHeader.substring(7);

        // Get email from authorization header
        userEmail = jwtService.extractUserName(jwt);

        // Check if user email is not null and if the user has not already been authenticated
        if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            // Check if the user actually exist in the database
            // - UserDetails will help us to get the user details from the database
            // - Check against the database if a user by the username of their email exist in the database
            UserDetails userDetails = userService.userDetailsService().loadUserByUsername(userEmail);

            // Check if the token has not expired
            // This involves checking if the token is being sent by the same user who is logging in
            // This is because JWT Token will have some user details and that needs to be compared with user who is logging in
            if(jwtService.isTokenValid(jwt, userDetails)) {
                // Token is valid
                // - Which means the user details in JWT Token is the same as that which is being passed in the credentials
                // - Also, the JWT Token has not expired yet

                // Create a Security Context for this user
                // - Security Context holds all live context for different users
                // - If for a user, Security Context exists, they have already previously logged in
                // - They don't need to be authenticated again
                // - Since this user does not have an active Security Context, the Security Context has to be updated
                SecurityContext securityContext = SecurityContextHolder.createEmptyContext();

                // To update a Security Context, we will have to create a UsernamePasswordAuthenticationToken
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities()
                );

                // The UsernamePasswordAuthenticationToken needs to be updated with a few more details from the HTTP request
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Finally, send this UsernamePasswordAuthenticationToken to Security Context
                securityContext.setAuthentication(authToken);
                SecurityContextHolder.setContext(securityContext);
            }

            // Call the next filter in the filter chain
            filterChain.doFilter(request, response);
        }
    }
}
