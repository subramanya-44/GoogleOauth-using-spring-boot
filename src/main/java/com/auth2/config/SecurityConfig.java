package com.auth2.config;

import com.auth2.security.JwtAuthFilter;
import com.auth2.security.JwtAuthenticationSuccessHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * FILE: SecurityConfig.java
 * ROLE: The "Brain" or "Traffic Controller".
 * FLOW:
 * 1. This is the first place Spring looks to understand how to secure the app.
 * 2. It defines the "Security Filter Chain" - a list of rules and checks for
 * every request.
 * 3. It plugs in our custom components (Filter and SuccessHandler).
 * 
 * CONNECTION:
 * - Uses JwtAuthFilter (to check tokens).
 * - Uses JwtAuthenticationSuccessHandler (to handle login success).
 */
@Configuration // Tells Spring: "This class contains system instructions (Beans)."
@EnableWebSecurity // Tells Spring: "Turn on the Web Security module."
public class SecurityConfig {

        private final JwtAuthFilter jwtAuthFilter;
        private final JwtAuthenticationSuccessHandler jwtAuthenticationSuccessHandler;

        // Constructor Injection: Spring gives us the instances of our custom classes.
        public SecurityConfig(JwtAuthFilter jwtAuthFilter,
                        JwtAuthenticationSuccessHandler jwtAuthenticationSuccessHandler) {
                this.jwtAuthFilter = jwtAuthFilter;
                this.jwtAuthenticationSuccessHandler = jwtAuthenticationSuccessHandler;
        }

        /**
         * The Main Security Rules Definition.
         * 
         * @param http The object that lets us configure security for HTTP requests.
         * @return The built filter chain that Spring Security will use.
         */
        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
                http
                                // 1. Disable CSRF (Cross-Site Request Forgery) protection.
                                // WHY: CSRF is needed for Session/Cookie based apps. Since we use stateless
                                // JWTs, we don't need it.
                                .csrf(AbstractHttpConfigurer::disable)

                                // 2. Define URL Access Rules.
                                .authorizeHttpRequests(auth -> auth
                                                .requestMatchers("/api/public").permitAll() // Allow ANYONE to access
                                                                                            // /api/public.
                                                .anyRequest().authenticated() // For EVERYTHING else, the user must be
                                                                              // logged in
                                                                              // (authenticated).
                                )

                                // 3. Configure Session Management.
                                // WHY: By default, Spring creates a JSESSIONID cookie. We want to be STATELESS
                                // (no server memory of users).
                                // We rely 100% on the JWT token for every request.
                                .sessionManagement(session -> session
                                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                                // 4. Configure OAuth2 Login (Google).
                                .oauth2Login(oauth2 -> oauth2
                                                // When login succeeds, don't just redirect to home. Run our custom
                                                // handler
                                                // instead.
                                                .successHandler(jwtAuthenticationSuccessHandler))

                                // 6. Add our Custom Filter.
                                // CRITICAL: We want to check for a JWT *before* Spring checks for a
                                // username/password.
                                // So we place our JwtAuthFilter BEFORE the standard
                                // UsernamePasswordAuthenticationFilter.
                                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

                return http.build();
        }
}
