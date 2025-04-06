package com.mikov.bulkemailchecker.services;

import com.mikov.bulkemailchecker.model.ValidationResult;

/**
 * Interface for email validation in the services package
 */
public interface EmailValidator {
    /**
     * Validates an email address
     * @param email Email to validate
     * @return Validation result
     */
    ValidationResult validate(String email);
    
    /**
     * Gets the name of the validator
     * @return Name of validator
     */
    String getName();
} 