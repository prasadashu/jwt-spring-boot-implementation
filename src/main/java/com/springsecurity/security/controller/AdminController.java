package com.springsecurity.security.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/admin")
@RequiredArgsConstructor
public class AdminController {
    /*
        Class to act as API Gateway for admin
     */

    @GetMapping
    public ResponseEntity<String> sayHello() {
        /*
            Function to send back admin a response
         */
        return ResponseEntity.ok("Hi Admin!");
    }
}
