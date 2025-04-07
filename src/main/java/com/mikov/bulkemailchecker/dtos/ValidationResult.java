package com.mikov.bulkemailchecker.dtos;

import lombok.Builder;
import lombok.Data;

import java.util.HashMap;
import java.util.Map;

/**
 * Data Transfer Object (DTO) that holds the result of an email validation.
 * Used for transferring validation results between layers of the application.
 * This is the primary validation result class used throughout the validation pipeline.
 *
 * @author zahari.mikov
 */
@Data
@Builder
public class ValidationResult {

    private final boolean valid;
    private final String validatorName;
    private final String reason;

    @Builder.Default
    private final Map<String, Object> details = new HashMap<>();

    public static ValidationResult valid(final String validatorName) {
        return ValidationResult.builder()
                .valid(true)
                .validatorName(validatorName)
                .build();
    }

    public static ValidationResult valid(final String validatorName, final Map<String, Object> details) {
        return ValidationResult.builder()
                .valid(true)
                .validatorName(validatorName)
                .details(details)
                .build();
    }

    public static ValidationResult invalid(final String validatorName, final String reason) {
        return ValidationResult.builder()
                .valid(false)
                .validatorName(validatorName)
                .reason(reason)
                .build();
    }

    public static ValidationResult invalid(final String validatorName, final String reason, final Map<String, Object> details) {
        return ValidationResult.builder()
                .valid(false)
                .validatorName(validatorName)
                .reason(reason)
                .details(details)
                .build();
    }

    /**
     * Creates a result for a catch-all domain
     * Catch-all domains are considered valid for delivery, but marked specially
     * 
     * @param validatorName Name of the validator
     * @param reason Reason for the result
     * @param details Additional details
     * @return A validation result with catch-all information
     */
    public static ValidationResult catchAll(final String validatorName, final String reason, final Map<String, Object> details) {
        return ValidationResult.builder()
                .valid(true) // Catch-all domains are technically valid
                .validatorName(validatorName)
                .reason(reason)
                .details(details)
                .build();
    }
} 