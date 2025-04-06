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

    @Builder.Default
    private final double score = 0.0;

    private final String validatorName;
    private final String reason;

    @Builder.Default
    private final Map<String, Double> details = new HashMap<>();

    public static ValidationResult valid(final String validatorName, final double score) {
        return ValidationResult.builder()
                .valid(true)
                .score(Math.min(1.0, Math.max(0.0, score)))
                .validatorName(validatorName)
                .build();
    }

    public static ValidationResult valid(final String validatorName, final double score, final Map<String, Double> details) {
        return ValidationResult.builder()
                .valid(true)
                .score(Math.min(1.0, Math.max(0.0, score)))
                .validatorName(validatorName)
                .details(details)
                .build();
    }

    public static ValidationResult invalid(final String validatorName, final String reason) {
        return ValidationResult.builder()
                .valid(false)
                .score(0.0)
                .validatorName(validatorName)
                .reason(reason)
                .build();
    }

    public static ValidationResult invalid(final String validatorName, final String reason, final Map<String, Double> details) {
        return ValidationResult.builder()
                .valid(false)
                .score(0.0)
                .validatorName(validatorName)
                .reason(reason)
                .details(details)
                .build();
    }

    public static ValidationResult invalid() {
        return invalid("unknown", "Unknown validation failure");
    }

    public ValidationResult combine(final ValidationResult other) {
        if (other == null) {
            return this;
        }

        final var isValid = this.isValid() && other.isValid();
        final var combined = ValidationResult.builder()
                .valid(isValid)
                .score((this.getScore() + other.getScore()) / 2.0)
                .validatorName("combined");
        
        final var combinedDetails = new HashMap<>(this.getDetails());
        combinedDetails.putAll(other.getDetails());
        combined.details(combinedDetails);
        
        if (!isValid) {
            if (!this.isValid()) {
                combined.reason(this.getReason());
            } else {
                combined.reason(other.getReason());
            }
        }
        
        return combined.build();
    }
} 