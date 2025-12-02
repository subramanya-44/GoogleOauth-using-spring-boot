package com.auth2.security;

import com.auth2.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

/**
 * FILE: JwtAuthFilter.java
 * ROLE: The "Gatekeeper".
 * FLOW:
 * 1. Intercepts EVERY HTTP request coming into the server.
 * 2. Checks if there is a "Bearer" token in the header.
 * 3. If yes, it asks JwtService: "Is this valid?"
 * 4. If valid, it tells Spring Security: "This user is authenticated."
 * 
 * CONNECTION:
 * - Uses JwtService (to validate tokens).
 * - Is used by SecurityConfig (added to the filter chain).
 */
@Component // Tells Spring to manage this class as a Bean.
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    // Constructor Injection: Spring automatically provides the JwtService instance.
    public JwtAuthFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    /**
     * The main logic method.
     * 
     * @param request     The incoming HTTP request (headers, body, etc.).
     * @param response    The outgoing HTTP response.
     * @param filterChain The chain of other filters (e.g., CORS, Logout) that need
     *                    to run.
     */
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        // 1. Get the "Authorization" header from the request.
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;

        // 2. Check if the header exists and starts with "Bearer ".
        // If not, this request doesn't have a token. We stop here and let the request
        // continue down the chain.
        // (If the request is for a protected URL, Spring Security will block it later
        // because the context is empty).
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // 3. Extract the actual token string (remove "Bearer " prefix).
        jwt = authHeader.substring(7);

        try {
            // 4. Extract the email (username) from the token using JwtService.
            userEmail = jwtService.extractUsername(jwt);

            // 5. If we found an email AND the user is not already authenticated in this
            // request context...
            if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {

                // 6. Validate the token fully (signature + expiration).
                if (jwtService.isTokenValid(jwt, userEmail)) {

                    // 7. Create an Authentication Token.
                    // This object tells Spring Security: "User is: userEmail", "Credentials: null
                    // (we trust the token)", "Authorities: [] (no roles)".
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userEmail,
                            null,
                            Collections.emptyList() // Authorities (Roles) would go here.
                    );

                    // 8. Add extra details (like IP address, Session ID) to the auth token.
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    // 9. THE CRITICAL STEP: Set the Authentication in the SecurityContext.
                    // This effectively "Logs In" the user for this specific request.
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
        } catch (Exception e) {
            // If token is invalid or expired, we just ignore it.
            // The request will proceed without authentication, and if it's a protected
            // endpoint, it will get a 401/403.
        }

        // 10. Continue the filter chain. Pass the request to the next filter (or the
        // Controller).
        filterChain.doFilter(request, response);
    }
}
