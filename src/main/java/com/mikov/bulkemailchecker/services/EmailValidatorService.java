package com.mikov.bulkemailchecker.services;

import com.mikov.bulkemailchecker.dtos.ValidationResult;
import com.mikov.bulkemailchecker.smtp.SmtpValidator;
import com.mikov.bulkemailchecker.smtp.model.SmtpResult;
import com.mikov.bulkemailchecker.smtp.model.SmtpErrorCode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailValidatorService implements EmailValidator {
    private final SmtpValidator smtpValidator;

    @Override
    public ValidationResult validate(String email) {
        log.info("Starting SMTP validation for email: {}", email);
        
        try {
            SmtpResult smtpResult = smtpValidator.validate(email);
            log.info("SMTP validation result for {}: {}", email, smtpResult);

            if (smtpResult.isTemporaryError()) {
                return createErrorResult(smtpResult.getErrorMessage(), "Temporary SMTP error");
            }

            if (smtpResult.isPermanentError()) {
                return createErrorResult(smtpResult.getErrorMessage(), "Permanent SMTP error");
            }

            Map<String, Object> details = new HashMap<>();
            details.put("email", email);
            details.put("server", smtpResult.getMxHost());
            details.put("ip_address", smtpResult.getIpAddress());
            details.put("deliverable", smtpResult.isDeliverable());
            details.put("catch_all", smtpResult.getErrorCode() == SmtpErrorCode.CATCH_ALL);
            details.put("greylisting", smtpResult.getErrorCode() == SmtpErrorCode.GREYLISTING);
            details.put("requires_neverbounce", smtpResult.requiresNeverBounceVerification());

            if (smtpResult.getDetails() != null) {
                details.putAll(smtpResult.getDetails());
            }

            return ValidationResult.builder()
                    .valid(smtpResult.isDeliverable())
                    .validatorName(getName())
                    .reason(smtpResult.getResponseMessage())
                    .details(details)
                    .build();

        } catch (Exception e) {
            log.error("Error during SMTP validation for {}: {}", email, e.getMessage());
            return createErrorResult(e.getMessage(), "SMTP validation failed");
        }
    }

    private ValidationResult createErrorResult(String errorMessage, String errorType) {
        Map<String, Object> details = new HashMap<>();
        details.put("error_message", errorMessage);
        details.put("error_type", errorType);
        
        return ValidationResult.builder()
                .valid(false)
                .validatorName(getName())
                .reason(errorMessage)
                .details(details)
                .build();
    }

    @Override
    public String getName() {
        return "smtp";
    }
} 