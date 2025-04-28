package com.mikov.bulkemailchecker.services;

import com.mikov.bulkemailchecker.dtos.ValidationResult;
import com.mikov.bulkemailchecker.smtp.SmtpValidator;
import com.mikov.bulkemailchecker.smtp.model.SmtpResult;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class EmailValidatorService implements EmailValidator {
    private final SmtpValidator smtpValidator;

    @Override
    public ValidationResult validate(String email) {
        try {
            SmtpResult result = smtpValidator.validate(email);
            return createValidationResult(result);
        } catch (Exception e) {
            return createErrorResult(e);
        }
    }

    private ValidationResult createValidationResult(SmtpResult result) {
        Map<String, Object> details = new HashMap<>(result.getDetails());
        details.put("smtp-validated", 1.0);
        details.put("catch-all", result.isCatchAll() ? 1.0 : 0.0);
        details.put("has-mx", 1.0);
        details.put("smtp-server", result.getMxHost());
        details.put("ip-address", result.getIpAddress());
        details.put("provider", result.getProvider());
        
        if (result.isDeliverable()) {
            details.put("event", result.isCatchAll() ? "is_catchall" : "mailbox_exists");
            return ValidationResult.valid(getName(), details);
        } else {
            details.put("event", "mailbox_does_not_exist");
            return ValidationResult.invalid(getName(), "Email not deliverable", details);
        }
    }

    private ValidationResult createErrorResult(Exception e) {
        Map<String, Object> details = new HashMap<>();
        details.put("event", "inconclusive");
        details.put("status", "unknown");
        details.put("error", e.getMessage());
        return ValidationResult.valid(getName(), details);
    }

    @Override
    public String getName() {
        return "smtp";
    }
} 