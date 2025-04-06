package com.mikov.bulkemailchecker.model;

import java.util.HashMap;
import java.util.Map;

/**
 * Result of email validation
 */
public class ValidationResult {
    private final boolean isValid;
    private final String validator;
    private final double confidence;
    private final String reason;
    private final Map<String, Double> details;
    
    private ValidationResult(boolean isValid, String validator, double confidence, String reason, Map<String, Double> details) {
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
     * @return ValidationResult
     */
    public static ValidationResult valid(String validator, double confidence, Map<String, Double> details) {
        return new ValidationResult(true, validator, confidence, null, details);
    }
    
    /**
     * Create an invalid result
     * @param validator Name of the validator
     * @param reason Reason for invalidity
     * @return ValidationResult
     */
    public static ValidationResult invalid(String validator, String reason) {
        return new ValidationResult(false, validator, 0.0, reason, new HashMap<>());
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