package com.auth2.security;

import com.auth2.service.JwtService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * FILE: JwtAuthenticationSuccessHandler.java
 * ROLE: The "Token Issuer".
 * FLOW:
 * 1. This class ONLY runs when a user successfully logs in via Google (OAuth2).
 * 2. It intercepts the "Success" event.
 * 3. It grabs the user's email from the Google data.
 * 4. It asks JwtService to generate a token.
 * 5. It writes that token as JSON to the response.
 * 
 * CONNECTION:
 * - Uses JwtService (to create tokens).
 * - Is used by SecurityConfig (registered as the .successHandler()).
 */
@Component // Tells Spring to manage this bean.
public class JwtAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtService jwtService;
    private final ObjectMapper objectMapper; // Tool to convert Java Maps to JSON strings.

    public JwtAuthenticationSuccessHandler(JwtService jwtService) {
        this.jwtService = jwtService;
        this.objectMapper = new ObjectMapper();
    }

    /**
     * Called automatically by Spring Security when login succeeds.
     * 
     * @param request        The HTTP request.
     * @param response       The HTTP response we will write to.
     * @param authentication Contains the user's details (Principal) from Google.
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {
        // 1. Cast the Principal to OAuth2User to get access to Google's data
        // (attributes).
        OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();

        // 2. Extract the email.
        // Google returns a map of attributes. "email" is a standard key.
        String email = oauth2User.getAttribute("email");
        if (email == null) {
            // Fallback if email is missing (rare with Google, but good practice).
            email = oauth2User.getName();
        }

        // 3. Generate the JWT using our service.
        // This is where the "Magic" happens: Email -> Signed Encrypted String.
        String token = jwtService.generateToken(email);

        // 4. Prepare the Response.
        // We want to return JSON, not HTML.
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        // 5. Create the JSON body.
        Map<String, String> responseBody = new HashMap<>();
        responseBody.put("token", token);

        // 6. Write the JSON to the output stream.
        // Result: {"token": "eyJhbGciOi..."}
        response.getWriter().write(objectMapper.writeValueAsString(responseBody));
    }
}
