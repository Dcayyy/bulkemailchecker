package com.mikov.bulkemailchecker.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.filter.OncePerRequestFilter;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.util.List;

@Slf4j
public class ApiKeyAuthFilter extends OncePerRequestFilter {

    private final List<String> validApiKeys;
    private final SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
    private final SecurityContextRepository securityContextRepository;

    public ApiKeyAuthFilter(List<String> validApiKeys, SecurityContextRepository securityContextRepository) {
        this.validApiKeys = validApiKeys;
        this.securityContextRepository = securityContextRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        
        String apiKey = request.getHeader("X-API-KEY");
        log.info("Received request with API Key: {}", apiKey);
        
        if (apiKey == null || !validApiKeys.contains(apiKey)) {
            log.warn("Invalid API Key provided: {}", apiKey);
            throw new BadCredentialsException("Invalid API Key");
        }

        log.info("Valid API Key found, creating authentication");
        Authentication authentication = new ApiKeyAuthentication(apiKey);
        
        SecurityContext context = securityContextHolderStrategy.createEmptyContext();
        context.setAuthentication(authentication);
        securityContextRepository.saveContext(context, request, response);
        
        log.info("Authentication set in SecurityContext, proceeding with filter chain");
        try {
            filterChain.doFilter(request, response);
        } finally {
            HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, response);
            SecurityContext contextAfterChainExecution = securityContextRepository.loadContext(holder);
            if (contextAfterChainExecution.getAuthentication() == null) {
                securityContextHolderStrategy.clearContext();
            }
        }
    }
} 