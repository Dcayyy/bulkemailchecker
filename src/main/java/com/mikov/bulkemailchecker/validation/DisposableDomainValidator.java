package com.mikov.bulkemailchecker.validation;

import com.mikov.bulkemailchecker.dtos.ValidationResult;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Validator that checks if an email uses a disposable or temporary domain.
 * Uses an in-memory set of known disposable domains.
 *
 * @author zahari.mikov
 */
@Component
public class DisposableDomainValidator implements EmailValidator {
    private static final Logger logger = LoggerFactory.getLogger(DisposableDomainValidator.class);

    private static final String DISPOSABLE_DOMAINS_FILE = "/disposable_domains.txt";
    private final Set<String> disposableDomains = new HashSet<>();

    @PostConstruct
    public void init() {
        try {
            final var is = getClass().getResourceAsStream(DISPOSABLE_DOMAINS_FILE);
            if (is != null) {
                try (final var reader = new BufferedReader(new InputStreamReader(is))) {
                    disposableDomains.addAll(
                        reader.lines()
                              .map(String::trim)
                              .filter(s -> !s.isEmpty() && !s.startsWith("#"))
                              .collect(Collectors.toSet())
                    );
                }
            } else {
                disposableDomains.addAll(Set.of(
                    "mailinator.com", "tempmail.com", "temp-mail.org", "fakeinbox.com",
                    "guerrillamail.com", "sharklasers.com", "yopmail.com", "10minutemail.com",
                    "trashmail.com", "mailnesia.com", "maildrop.cc", "getairmail.com",
                    "getnada.com", "temp-mail.ru", "dispostable.com", "emailondeck.com",
                    "throwawaymail.com", "spambog.com", "tempr.email", "tempmail.de"
                ));
            }
        } catch (final Exception e) {
            logger.error("Error loading disposable domains list", e);
        }
    }

    @Override
    public ValidationResult validate(final String email) {
        if (email == null || email.isBlank()) {
            return ValidationResult.invalid(getName(), "Email is null or empty");
        }
        
        final var parts = email.split("@", 2);
        if (parts.length != 2) {
            return ValidationResult.invalid(getName(), "Invalid email format");
        }
        
        final var domain = parts[1].toLowerCase();
        if (disposableDomains.contains(domain)) {
            return ValidationResult.invalid(getName(), "Email uses a disposable domain: " + domain);
        }
        
        for (final var disposableDomain : disposableDomains) {
            if (domain.endsWith("." + disposableDomain)) {
                return ValidationResult.invalid(getName(), "Email uses a subdomain of disposable domain: " + disposableDomain);
            }
        }
        
        return ValidationResult.valid(getName(), 1.0);
    }

    @Override
    public String getName() {
        return "disposable-domain";
    }
} 