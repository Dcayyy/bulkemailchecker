package com.mikov.bulkemailchecker.model;

import lombok.Getter;

import java.util.HashMap;
import java.util.Map;

/**
 * Service-level result of email validation.
 * Used specifically for the service layer validation results.
 * This is the internal model used within the service components.
 * 
 * @author zahari.mikov
 */
@Getter
public class ServiceValidationResult {
    private final boolean isValid;
    private final String validator;
    private final double confidence;
    private final String reason;
    private final Map<String, Double> details;
    
    private ServiceValidationResult(final boolean isValid, final String validator, final double confidence, 
            final String reason, final Map<String, Double> details) {
        this.isValid = isValid;
        this.validator = validator;
        this.confidence = confidence;
        this.reason = reason;
        this.details = details;
    }

    public static ServiceValidationResult valid(final String validator, final double confidence, final Map<String, Double> details) {
        return new ServiceValidationResult(true, validator, confidence, null, details);
    }

    public static ServiceValidationResult invalid(final String validator, final String reason) {
        return new ServiceValidationResult(false, validator, 0.0, reason, new HashMap<>());
    }
} 