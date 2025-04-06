package com.mikov.bulkemailchecker.utils;

import com.mikov.bulkemailchecker.dtos.ValidationResult;
import com.mikov.bulkemailchecker.model.ServiceValidationResult;

import java.util.HashMap;

/**
 * Utility class for converting between different ValidationResult implementations.
 * Handles conversion between the DTO ValidationResult and the service layer's ServiceValidationResult.
 * 
 * @author zahari.mikov
 */
public class ValidationResultConverter {

    /**
     * Converts a ServiceValidationResult to a ValidationResult (DTO).
     * 
     * @param serviceResult The service layer validation result
     * @return The DTO validation result
     */
    public static ValidationResult toValidationResult(final ServiceValidationResult serviceResult) {
        if (serviceResult == null) {
            return ValidationResult.invalid();
        }
        
        final var builder = ValidationResult.builder()
                .valid(serviceResult.isValid())
                .score(serviceResult.getConfidence())
                .validatorName(serviceResult.getValidator());
                
        if (!serviceResult.isValid() && serviceResult.getReason() != null) {
            builder.reason(serviceResult.getReason());
        }
        
        if (serviceResult.getDetails() != null) {
            builder.details(new HashMap<>(serviceResult.getDetails()));
        }
        
        return builder.build();
    }
    
    /**
     * Converts a ValidationResult (DTO) to a ServiceValidationResult.
     * 
     * @param validationResult The DTO validation result
     * @return The service layer validation result
     */
    public static ServiceValidationResult toServiceValidationResult(final ValidationResult validationResult) {
        if (validationResult == null) {
            return ServiceValidationResult.invalid("unknown", "Unknown validation failure");
        }
        
        if (validationResult.isValid()) {
            return ServiceValidationResult.valid(
                validationResult.getValidatorName(),
                validationResult.getScore(),
                validationResult.getDetails() != null ? 
                    new HashMap<>(validationResult.getDetails()) : 
                    new HashMap<>()
            );
        } else {
            return ServiceValidationResult.invalid(
                validationResult.getValidatorName(),
                validationResult.getReason()
            );
        }
    }
} 