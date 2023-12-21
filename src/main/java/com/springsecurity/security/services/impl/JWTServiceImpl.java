package com.springsecurity.security.services.impl;

import com.springsecurity.security.services.JWTService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.Objects;
import java.util.function.Function;
import java.util.Map;

@Service
public class JWTServiceImpl implements JWTService {
    /*
        Service to perform JWT related tasks
     */

    // Defining methods to generate JWT Token

    private Key getSignKey() {
        /*
            Function to generate Signing Key
         */
        byte[] key = Decoders.BASE64.decode("413F4428472B4B6250655368566D5970337336763979244226452948404D6351");
        return Keys.hmacShaKeyFor(key);
    }

    public String generateToken(UserDetails userDetails) {
        /*
            Function to generate Token
            - The JWT Token created is valid for a day
         */
        return Jwts.builder()
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateRefreshedToken(Map<String, Objects> extraClaims, UserDetails userDetails) {
        /*
            Function to generate refreshed Token
            - Refreshed token is valid for 7 days
         */
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24 * 7))
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // Defining methods to extract Claims from JWT Tokens in HTTP Response

    private Claims extractAllClaims(String token) {
        /*
            Function to extract all Claims from JWT Token
            - Function checks if the JWT Token has not been tampered with
            - This is done by computing the signature from the Header + Payload
            - This computed signature is compared with the signature provided in the JWT Token
            - If both signatures match, the request is processed
            - Otherwise, the function throws an error
         */
        return Jwts.parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolvers) {
        /*
            Function to extract a particular Claim from JWT Token
         */
        final Claims claims = extractAllClaims(token);
        return claimsResolvers.apply(claims);
    }

    public String extractUserName(String token) {
        /*
            Function to extract username from token
            - This function is intended to be use 'extractClaim' method to extract username
         */
        return extractClaim(token, Claims::getSubject);
    }

    private boolean isTokenExpired(String token) {
        /*
            Function to check if the token has expired
         */
        // Check and return if expiration date is less than current date
        // - If expiration date is before the current date, then the function will return True
        // - This means that the JWT Token has expired
        return extractClaim(token, Claims::getExpiration).before(new Date());
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        /*
            Function to check if token is valid and is issued to a particular user
         */
        // Extract username from token
        final String username = extractUserName(token);
        // Check and return if token is valid and is issued to a particular user
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}
