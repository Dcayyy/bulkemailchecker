package com.mikov.bulkemailchecker.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Configuration class for security-related beans.
 * 
 * @author zahari.mikov
 */
@Configuration
public class SecurityBeanConfig {

    @Value("${security.api-key}")
    private String apiKey;

    @Value("${security.allowed-ips}")
    private String allowedIps;

    @Bean
    public ApiKeyAuthFilter apiKeyAuthFilter() {
        return new ApiKeyAuthFilter(apiKey);
    }

    @Bean
    public IpWhitelistFilter ipWhitelistFilter() {
        Set<String> allowedIpSet = Arrays.stream(allowedIps.split(","))
                .map(String::trim)
                .collect(Collectors.toSet());
        return new IpWhitelistFilter(allowedIpSet);
    }
} 