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
    private final Map<String, Double> details = new HashMap<>();

    public static ValidationResult valid(final String validatorName) {
        return ValidationResult.builder()
                .valid(true)
                .validatorName(validatorName)
                .build();
    }

    public static ValidationResult valid(final String validatorName, final Map<String, Double> details) {
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

    public static ValidationResult invalid(final String validatorName, final String reason, final Map<String, Double> details) {
        return ValidationResult.builder()
                .valid(false)
                .validatorName(validatorName)
                .reason(reason)
                .details(details)
                .build();
    }
} 