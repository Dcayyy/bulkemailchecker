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
 * Validates the X-API-Key header against a configured secret.
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
        
        try {
            final String requestApiKey = request.getHeader(API_KEY_HEADER);
            
            if (requestApiKey == null || !validateApiKey(requestApiKey)) {
                throw new BadCredentialsException("Invalid API Key");
            }

            final Authentication auth = new CustomAuthenticationToken(
                "api-client",
                null,
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_API_CLIENT"))
            );
            
            SecurityContextHolder.getContext().setAuthentication(auth);
            filterChain.doFilter(request, response);
        } catch (BadCredentialsException e) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.getWriter().write("Unauthorized: " + e.getMessage());
        }
    }

    private boolean validateApiKey(final String requestApiKey) {
        try {
            final String decodedRequestKey = new String(Base64.getDecoder().decode(requestApiKey));
            final String decodedStoredKey = new String(Base64.getDecoder().decode(apiKey));
            return decodedRequestKey.equals(decodedStoredKey);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
} 