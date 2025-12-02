package com.auth2.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

/**
 * FILE: ApiController.java
 * ROLE: The "Destination" or "Business Logic".
 * FLOW:
 * 1. This is where the request finally arrives after passing through the
 * Security Filter Chain.
 * 2. It defines the actual URLs (Endpoints) the user can visit.
 * 
 * CONNECTION:
 * - Protected by SecurityConfig (which decides who can access these URLs).
 */
@RestController // Tells Spring: "This class handles web requests and returns data (JSON), not
                // HTML views."
@RequestMapping("/api") // All URLs in this class start with "/api" (e.g., /api/public).
public class ApiController {

    /**
     * A Public Endpoint.
     * FLOW: SecurityConfig allows "permitAll()" for this URL.
     * Anyone can access it, even without a token.
     */
    @GetMapping("/public")
    public ResponseEntity<String> publicEndpoint() {
        return ResponseEntity.ok("This is a public endpoint. Accessible to everyone.");
    }

    /**
     * A Protected Endpoint.
     * FLOW: SecurityConfig requires ".authenticated()" for this URL.
     * 1. If the request reaches here, it means JwtAuthFilter successfully validated
     * the token.
     * 2. Spring Security injects the 'Principal' object (the user details)
     * automatically.
     * 
     * @param principal The currently logged-in user (set by JwtAuthFilter).
     */
    @GetMapping("/protected")
    public ResponseEntity<String> protectedEndpoint(Principal principal) {
        // We can access the user's name (email) from the Principal object.
        return ResponseEntity
                .ok("Hello, " + principal.getName() + "! This is a protected endpoint. You are authenticated via JWT.");
    }
}
