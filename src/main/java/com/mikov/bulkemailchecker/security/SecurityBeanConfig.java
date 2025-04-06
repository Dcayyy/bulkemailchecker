package com.mikov.bulkemailchecker.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Configuration class for security-related beans.
 * 
 * @author zahari.mikov
 */
@Configuration
public class SecurityBeanConfig {

    @Value("${security.api-key}")
    private String apiKey;

    @Bean
    public ApiKeyAuthFilter apiKeyAuthFilter() {
        return new ApiKeyAuthFilter(apiKey);
    }
} 