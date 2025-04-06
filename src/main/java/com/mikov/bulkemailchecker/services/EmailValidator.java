package com.mikov.bulkemailchecker.services;

import com.mikov.bulkemailchecker.model.ServiceValidationResult;

/**
 * Interface for email validation in the services package
 * 
 * @author zahari.mikov
 */
public interface EmailValidator {
    /**
     * Validates an email address
     * @param email Email to validate
     * @return Validation result
     */
    ServiceValidationResult validate(final String email);
    
    /**
     * Gets the name of the validator
     * @return Name of validator
     */
    String getName();
} 