package com.mikov.bulkemailchecker.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.io.Serial;
import java.io.Serializable;
import java.util.Collection;

/**
 * Custom authentication token for our security setup.
 * Implements Serializable to support propagation across threads.
 * 
 * @author zahari.mikov
 */
public class CustomAuthenticationToken extends AbstractAuthenticationToken implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    private final Object principal;
    private final Object credentials;

    public CustomAuthenticationToken(Object principal, Object credentials,
                                   Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.credentials = credentials;
        super.setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return this.credentials;
    }

    @Override
    public Object getPrincipal() {
        return this.principal;
    }
} 