package com.auth2.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * FILE: JwtService.java
 * ROLE: The "Toolset" or Utility Class.
 * FLOW:
 * 1. Used by JwtAuthenticationSuccessHandler to CREATE tokens when a user logs
 * in.
 * 2. Used by JwtAuthFilter to VALIDATE tokens when a user makes a request.
 * 
 * This class doesn't know about HTTP, Requests, or SecurityContext.
 * It only knows how to do the math to Sign and Verify strings (JWTs).
 */
@Service // Tells Spring: "Please create an instance of this class so other classes can
         // use it (Dependency Injection)."
public class JwtService {

    // CONNECTION: Reads 'jwt.secret' from src/main/resources/application.properties
    // This is the secret password used to sign the tokens. If someone knows this,
    // they can forge tokens.
    @Value("${jwt.secret}")
    private String secretKey;

    // CONNECTION: Reads 'jwt.expiration' from application.properties
    // Determines how long a token is valid (e.g., 24 hours).
    @Value("${jwt.expiration}")
    private long jwtExpiration;

    /**
     * Extracts the username (subject) from a given token.
     * FLOW: Called by JwtAuthFilter to identify WHO is trying to access the API.
     */
    public String extractUsername(String token) {
        // Uses the generic extractClaim method, passing a function to get the "Subject"
        // (which is the username/email).
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Generic method to extract a specific piece of data (Claim) from the token.
     * 
     * @param claimsResolver A function that says "Give me the Subject" or "Give me
     *                       the Expiration".
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        // First, we must parse the token and verify its signature to get all claims.
        final Claims claims = extractAllClaims(token);
        // Then we apply the specific function to get the data we want.
        return claimsResolver.apply(claims);
    }

    /**
     * Generates a new Token for a user.
     * FLOW: Called by JwtAuthenticationSuccessHandler after Google Login succeeds.
     */
    public String generateToken(String username) {
        // Delegates to the main generateToken method with no extra claims.
        return generateToken(new HashMap<>(), username);
    }

    /**
     * The core method that builds the JWT string.
     * 
     * @param extraClaims Any custom data we want to store in the token (e.g., role:
     *                    "ADMIN").
     * @param username    The user's ID (email) to be stored as the "Subject".
     */
    public String generateToken(Map<String, Object> extraClaims, String username) {
        return Jwts.builder()
                .setClaims(extraClaims) // 1. Add custom data
                .setSubject(username) // 2. Add the user's ID (Standard Claim: 'sub')
                .setIssuedAt(new Date(System.currentTimeMillis())) // 3. Add creation time (Standard Claim: 'iat')
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpiration)) // 4. Add expiration time (Standard
                                                                                     // Claim: 'exp')
                .signWith(getSignInKey(), SignatureAlgorithm.HS256) // 5. Sign it with our Secret Key using HMAC-SHA256
                                                                    // algorithm.
                .compact(); // 6. Compress it into the final String (e.g., "eyJhbGci...")
    }

    /**
     * Checks if a token is valid.
     * FLOW: Called by JwtAuthFilter.
     * Logic:
     * 1. Does the username in the token match the user we are checking?
     * 2. Is the token expired?
     */
    public boolean isTokenValid(String token, String username) {
        final String extractedUsername = extractUsername(token);
        // True if usernames match AND token is NOT expired.
        return (extractedUsername.equals(username)) && !isTokenExpired(token);
    }

    /**
     * Helper to check if the token has passed its expiration date.
     */
    private boolean isTokenExpired(String token) {
        // Checks if the expiration date is BEFORE the current time (now).
        return extractExpiration(token).before(new Date());
    }

    /**
     * Helper to extract just the Expiration Date from the token.
     */
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * The "Heavy Lifting" method.
     * It parses the token string, verifies the signature using the Secret Key, and
     * returns the data (Claims).
     * If the signature is invalid (token was tampered with), this will throw an
     * Exception.
     */
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey()) // Set the key to verify the signature.
                .build()
                .parseClaimsJws(token) // Parse the string. Throws exception if invalid.
                .getBody(); // Get the data part (Payload).
    }

    /**
     * Decodes our Base64 encoded secret key into a format the JWT library can use.
     */
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
