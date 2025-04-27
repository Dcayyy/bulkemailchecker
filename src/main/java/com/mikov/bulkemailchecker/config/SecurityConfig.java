package com.mikov.bulkemailchecker.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import lombok.extern.slf4j.Slf4j;
import jakarta.servlet.http.HttpServletResponse;

import java.util.Arrays;
import java.util.List;

@Configuration
@EnableWebSecurity
@Slf4j
public class SecurityConfig {

    private static final List<String> VALID_API_KEYS = Arrays.asList(
        "zahariZDEwNWRlYTUtZjMzMy00MzE4LWJlN2QtZTIxYzYzZTFlODAy",
        "martinZDEwNWRlYTUtZjMzMy00MzE4LWJlN2QtZTIxYzYzZTFlODAy",
        "yoanZDEwNWRlYTUtZjMzMy00MzE4LWJlN2QtZTIxYzYzZTFlODAy"
    );

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, SecurityContextRepository securityContextRepository) throws Exception {
        log.info("Configuring security filter chain");
        
        // Set the security context holder strategy to MODE_INHERITABLETHREADLOCAL
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
        
        http
            .csrf(csrf -> csrf.disable())
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .securityContext(securityContext -> securityContext
                .securityContextRepository(securityContextRepository)
            )
            .authorizeHttpRequests(auth -> {
                auth
                    .requestMatchers("/error").permitAll()
                    .requestMatchers("/bulkemailchecker/**").hasRole("API")
                    .anyRequest().authenticated();
            })
            .addFilterBefore(new ApiKeyAuthFilter(VALID_API_KEYS, securityContextRepository), BasicAuthenticationFilter.class)
            .exceptionHandling(exception -> {
                exception.authenticationEntryPoint((request, response, authException) -> {
                    log.error("Authentication error: {}", authException.getMessage());
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
                });
                exception.accessDeniedHandler((request, response, accessDeniedException) -> {
                    log.error("Authorization error: {}", accessDeniedException.getMessage());
                    response.sendError(HttpServletResponse.SC_FORBIDDEN, "Forbidden");
                });
            });

        return http.build();
    }

    @Bean
    public SecurityContextRepository securityContextRepository() {
        return new HttpSessionSecurityContextRepository();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("*"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setExposedHeaders(Arrays.asList("X-API-KEY"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
} 