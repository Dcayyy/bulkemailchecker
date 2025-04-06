package com.mikov.bulkemailchecker.validation;

import com.mikov.bulkemailchecker.dtos.ValidationResult;

/**
 * Interface for all email validators in the validation pipeline.
 * Defines the contract for email validation implementations.
 * 
 * @author zahari.mikov
 */
public interface EmailValidator {

    /**
     * Validates an email and returns the validation result.
     *
     * @param email The email to validate
     * @return The validation result
     */
    ValidationResult validate(final String email);
    
    /**
     * Returns the name of this validator, used for identification in results.
     *
     * @return The validator name
     */
    String getName();
} 