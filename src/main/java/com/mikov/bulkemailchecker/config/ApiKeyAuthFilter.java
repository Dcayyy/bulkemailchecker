package com.mikov.bulkemailchecker.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
public final class ApiKeyAuthFilter extends OncePerRequestFilter {

    private final List<String> validApiKeys;
    private final SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
    private final SecurityContextRepository securityContextRepository;

    public ApiKeyAuthFilter(final List<String> validApiKeys, final SecurityContextRepository securityContextRepository) {
        this.validApiKeys = validApiKeys;
        this.securityContextRepository = securityContextRepository;
        log.info("Initialized ApiKeyAuthFilter with valid API keys: {}", validApiKeys);
    }

    @Override
    protected void doFilterInternal(final HttpServletRequest request, 
                                  final HttpServletResponse response, 
                                  final FilterChain filterChain) throws ServletException, IOException {
        final String apiKey = request.getHeader("X-API-KEY");
        log.info("Received request with API Key: {}", apiKey);
        
        if (apiKey == null || !validApiKeys.contains(apiKey)) {
            log.warn("Invalid API Key provided: {}", apiKey);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid API Key");
            return;
        }

        log.info("Valid API Key found, creating authentication");
        final Authentication authentication = new ApiKeyAuthentication(apiKey);
        
        final SecurityContext context = securityContextHolderStrategy.createEmptyContext();
        context.setAuthentication(authentication);
        securityContextRepository.saveContext(context, request, response);
        
        log.info("Authentication set in SecurityContext, proceeding with filter chain");
        try {
            filterChain.doFilter(request, response);
        } finally {
            final HttpRequestResponseHolder holder = new HttpRequestResponseHolder(request, response);
            final SecurityContext contextAfterChainExecution = securityContextRepository.loadContext(holder);
            if (contextAfterChainExecution.getAuthentication() == null) {
                securityContextHolderStrategy.clearContext();
            }
        }
    }
} 