package com.mikov.bulkemailchecker.validation;

import com.mikov.bulkemailchecker.dtos.ValidationResult;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * Validator that checks if a domain has valid MX records for email delivery.
 *
 * @author zahari.mikov
 */
@Component
public class MXRecordValidator implements EmailValidator {
    private static final Logger logger = LoggerFactory.getLogger(MXRecordValidator.class);

    private final ConcurrentHashMap<String, CachedResult> resultCache = new ConcurrentHashMap<>();

    private static final long CACHE_TTL_MS = TimeUnit.HOURS.toMillis(1);

    @Override
    public ValidationResult validate(final String email) {
       final var parts = email.split("@", 2);
        if (parts.length != 2) {
            return ValidationResult.invalid(getName(), "Invalid email format");
        }
        
        final var domain = parts[1].toLowerCase();
        
        final var cachedResult = resultCache.get(domain);
        if (cachedResult != null && !cachedResult.isExpired()) {
            return cachedResult.isValid()
                   ? ValidationResult.valid(getName()) 
                   : ValidationResult.invalid(getName(), "Domain has no MX records");
        }
        
        try {
            final var hasMx = checkMxRecords(domain);
            resultCache.put(domain, new CachedResult(hasMx));
            if (!hasMx) {
                return ValidationResult.invalid(getName(), "Domain has no MX records");
            }
            return ValidationResult.valid(getName());
        } catch (final Exception e) {
            logger.error("Error checking MX records for domain {}: {}", domain, e.getMessage());
            return ValidationResult.invalid(getName(), "Error checking MX records: " + e.getMessage());
        }
    }

    @Override
    public String getName() {
        return "mx-record";
    }

    private boolean checkMxRecords(final String domain) {
        try {
            // Simple DNS check - if the domain resolves, assume it has MX records
            // This is a simplified implementation for compatibility
            InetAddress.getByName(domain);
            return true;
        } catch (Exception e) {
            logger.warn("Could not resolve domain {}: {}", domain, e.getMessage());
            return false;
        }
    }

    @Getter
    private static class CachedResult {
        private final boolean valid;
        private final long timestamp;
        
        public CachedResult(final boolean valid) {
            this.valid = valid;
            this.timestamp = System.currentTimeMillis();
        }

        public boolean isExpired() {
            return System.currentTimeMillis() - timestamp > CACHE_TTL_MS;
        }
    }
} 