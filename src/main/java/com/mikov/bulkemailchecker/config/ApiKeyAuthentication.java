package com.mikov.bulkemailchecker.config;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import lombok.extern.slf4j.Slf4j;

import java.util.Collection;

@Slf4j
public final class ApiKeyAuthentication implements Authentication {

    private final String apiKey;
    private boolean authenticated = true;

    public ApiKeyAuthentication(final String apiKey) {
        this.apiKey = apiKey;
        log.info("Created new ApiKeyAuthentication for key: {}", apiKey);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        final Collection<? extends GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_API");
        log.info("Returning authorities: {}", authorities);
        return authorities;
    }

    @Override
    public Object getCredentials() {
        return apiKey;
    }

    @Override
    public Object getDetails() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return apiKey;
    }

    @Override
    public boolean isAuthenticated() {
        return authenticated;
    }

    @Override
    public void setAuthenticated(final boolean isAuthenticated) throws IllegalArgumentException {
        this.authenticated = isAuthenticated;
    }

    @Override
    public String getName() {
        return apiKey;
    }
} 