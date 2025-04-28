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
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailValidatorService implements EmailValidator {
    private final SmtpValidator smtpValidator;
    private static final int MAX_RETRIES = 3;
    private static final int RETRY_DELAY_MS = 1000;

    @Override
    public ValidationResult validate(String email) {
        log.info("Starting SMTP validation for email: {}", email);
        
        try {
            SmtpResult smtpResult = null;
            int retryCount = 0;
            
            while (retryCount < MAX_RETRIES) {
                smtpResult = smtpValidator.validate(email);
                log.info("SMTP validation attempt {} for {}: {}", retryCount + 1, email, smtpResult);

                if (smtpResult.isTemporaryError()) {
                    log.info("Temporary error detected for {}, retrying...", email);
                    retryCount++;
                    if (retryCount < MAX_RETRIES) {
                        TimeUnit.MILLISECONDS.sleep(RETRY_DELAY_MS);
                        continue;
                    }
                }
                break;
            }

            if (smtpResult == null) {
                return createErrorResult("Failed to validate email after " + MAX_RETRIES + " attempts", "Validation failed");
            }

            Map<String, Object> details = new HashMap<>();
            details.put("email", email);
            details.put("server", smtpResult.getMxHost());
            details.put("ip_address", smtpResult.getIpAddress());
            details.put("deliverable", smtpResult.isDeliverable());
            details.put("catch_all", smtpResult.getErrorCode() == SmtpErrorCode.CATCH_ALL);
            details.put("greylisting", smtpResult.getErrorCode() == SmtpErrorCode.GREYLISTING);
            details.put("requires_neverbounce", smtpResult.requiresNeverBounceVerification());
            details.put("retry_count", retryCount);

            if (smtpResult.getDetails() != null) {
                details.putAll(smtpResult.getDetails());
            }

            // Handle DNS issues
            if (details.containsKey("has_dns_issues") && Boolean.TRUE.equals(details.get("has_dns_issues"))) {
                log.warn("DNS issues detected for {}: SPF={}, DKIM={}, DMARC={}", 
                    email, 
                    details.get("spf_record"),
                    details.get("dkim_record"),
                    details.get("dmarc_record"));
            }

            // Handle catch-all detection
            if (smtpResult.getErrorCode() == SmtpErrorCode.CATCH_ALL) {
                log.info("Catch-all domain detected for {}", email);
                details.put("event", "is_catchall");
            }

            // Handle inconclusive results
            if (smtpResult.getErrorCode() == SmtpErrorCode.INCONCLUSIVE) {
                log.info("Inconclusive result for {}", email);
                details.put("event", "inconclusive");
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