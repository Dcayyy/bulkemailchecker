package com.mikov.bulkemailchecker.model;

import java.util.HashMap;
import java.util.Map;

/**
 * Service-level result of email validation.
 * Used specifically for the service layer validation results.
 * This is the internal model used within the service components.
 * 
 * @author zahari.mikov
 */
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
    
    /**
     * Create a valid result
     * @param validator Name of the validator
     * @param confidence Confidence score (0-1)
     * @param details Additional details
     * @return ServiceValidationResult
     */
    public static ServiceValidationResult valid(final String validator, final double confidence, final Map<String, Double> details) {
        return new ServiceValidationResult(true, validator, confidence, null, details);
    }
    
    /**
     * Create an invalid result
     * @param validator Name of the validator
     * @param reason Reason for invalidity
     * @return ServiceValidationResult
     */
    public static ServiceValidationResult invalid(final String validator, final String reason) {
        return new ServiceValidationResult(false, validator, 0.0, reason, new HashMap<>());
    }
    
    public boolean isValid() {
        return isValid;
    }
    
    public String getValidator() {
        return validator;
    }
    
    public double getConfidence() {
        return confidence;
    }
    
    public String getReason() {
        return reason;
    }
    
    public Map<String, Double> getDetails() {
        return details;
    }
} 