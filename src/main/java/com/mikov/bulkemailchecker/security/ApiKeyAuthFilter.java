package com.mikov.bulkemailchecker.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Base64;
import java.util.Collections;

/**
 * Filter for API key authentication.
 * TESTING MODE: Authentication is completely disabled - all requests are accepted.
 * 
 * @author zahari.mikov
 */
public class ApiKeyAuthFilter extends OncePerRequestFilter {

    private static final String API_KEY_HEADER = "X-API-Key";
    private final String apiKey;

    public ApiKeyAuthFilter(final String apiKey) {
        this.apiKey = apiKey;
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request,
                                  final HttpServletResponse response,
                                  final FilterChain filterChain)
            throws ServletException, IOException {
        
        // TESTING MODE: Always authenticate the request, regardless of API key
        final Authentication auth = new CustomAuthenticationToken(
            "api-client",
            null,
            Collections.singletonList(new SimpleGrantedAuthority("ROLE_API_CLIENT"))
        );
        
        SecurityContextHolder.getContext().setAuthentication(auth);
        filterChain.doFilter(request, response);
    }

    private boolean validateApiKey(final String requestApiKey) {
        // TESTING MODE: Always return true to allow all requests
        return true;
    }
} 