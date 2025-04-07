package com.mikov.bulkemailchecker.services;

import com.mikov.bulkemailchecker.dtos.ValidationResult;
import com.mikov.bulkemailchecker.model.EmailVerificationResponse;
import com.mikov.bulkemailchecker.validation.MXRecordValidator;
import com.mikov.bulkemailchecker.validation.SyntaxValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.core.task.TaskExecutor;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

/**
 * Service for bulk email verification.
 * Orchestrates multiple validators to comprehensively verify email addresses.
 * 
 * @author zahari.mikov
 */
@Service
public class BulkEmailCheckerService {
    private static final Logger logger = LoggerFactory.getLogger(BulkEmailCheckerService.class);
    
    private static final int MAX_CONCURRENT_PER_DOMAIN = 3;
    private static final long DOMAIN_THROTTLE_DELAY_MS = 500;
    private final ConcurrentHashMap<String, Semaphore> domainLimiters = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long> lastDomainAccessTime = new ConcurrentHashMap<>();

    private final SMTPValidator smtpValidator;
    private final SyntaxValidator syntaxValidator;
    private final MXRecordValidator mxRecordValidator;
    private final TaskExecutor taskExecutor;

    // Map to store pending verification results that clients can query later
    private final Map<String, CompletableFuture<EmailVerificationResponse>> pendingVerifications = new ConcurrentHashMap<>();

    @Autowired
    public BulkEmailCheckerService(final SMTPValidator smtpValidator,
                                   final SyntaxValidator syntaxValidator,
                                   final MXRecordValidator mxRecordValidator,
                                   final TaskExecutor taskExecutor) {
        this.smtpValidator = smtpValidator;
        this.syntaxValidator = syntaxValidator;
        this.mxRecordValidator = mxRecordValidator;
        this.taskExecutor = taskExecutor;
    }

    /**
     * Verify a single email address
     */
    public EmailVerificationResponse verifyEmail(final String email) {
        final var startTime = Instant.now();
        logger.info("Starting email verification for: {}", email);
        
        // Execute validation pipeline
        final var result = executeValidationPipeline(email);
        final var detailsByValidator = getDetailsByValidator(result);
        
        // Extract properties from validation results
        final var hasMx = detailsByValidator.values().stream()
                .anyMatch(details -> details.containsKey("has-mx") && details.get("has-mx") != null && 
                        details.get("has-mx").toString().equals("1.0"));
        
        final var smtpValidated = detailsByValidator.containsKey("smtp") &&
                detailsByValidator.get("smtp").containsKey("smtp-validated") &&
                detailsByValidator.get("smtp").get("smtp-validated") != null &&
                detailsByValidator.get("smtp").get("smtp-validated").toString().equals("1.0");
        
        // Check for pending verification (rate-limited)
        Map<String, Object> smtpDetails = detailsByValidator.getOrDefault("smtp", new HashMap<>());
        if (smtpDetails != null && smtpDetails.containsKey("event") && 
                "retry_scheduled".equals(smtpDetails.get("event"))) {
            
            // Create a unique verification ID for this pending email
            String verificationId = UUID.randomUUID().toString();
            
            // Create a pending response
            EmailVerificationResponse pendingResponse = EmailVerificationResponse.createPendingResponse(
                    email, "Email verification delayed due to rate limiting. Please check status endpoint.");
            
            // Store the pending future so it can be completed later when validation completes
            CompletableFuture<EmailVerificationResponse> pendingFuture = new CompletableFuture<>();
            pendingVerifications.put(verificationId, pendingFuture);
            
            // Schedule the completion of this pending verification when SMTP validator completes it
            schedulePendingVerificationCompletion(email, verificationId);
            
            logger.info("Rate-limited email verification for {} queued with ID {}", email, verificationId);
            return pendingResponse;
        }
        
        final var detailMap = new HashMap<String, Object>();
        for (final var entry : detailsByValidator.entrySet()) {
            detailMap.putAll(entry.getValue());
        }
        
        // Build response
        final var responseBuilder = new EmailVerificationResponse.Builder(email)
                .withValid(result.isValid())
                .withResponseTime(Duration.between(startTime, Instant.now()).toMillis())
                .withHasMx(hasMx);
        
        // Set flags based on validation results
        setEmailVerificationFlags(responseBuilder, detailMap);
        
        // Set status and result code
        String status;
        if (!result.isValid()) {
            status = "invalid";
        } else if (detailMap.containsKey("catch-all") && detailMap.get("catch-all").toString().equals("1.0")) {
            status = "catch-all";
        } else if (detailMap.containsKey("event") && 
                  ("inconclusive".equals(detailMap.get("event")) || detailMap.get("event").toString().contains("inconclusive"))) {
            status = "inconclusive";
        } else {
            status = "valid";
        }
        
        final var resultCode = getResultCode(result);
        
        responseBuilder.withStatus(status)
                .withResultCode(resultCode);
                
        final var response = responseBuilder.build();
        
        logger.info("Email verification result for {}: {}", email, response.getResultCode());
        return response;
    }

    /**
     * Schedule a task to complete a pending verification
     */
    private void schedulePendingVerificationCompletion(String email, String verificationId) {
        // Poll the SMTP validator every 10 seconds to check for completion
        CompletableFuture.runAsync(() -> {
            int maxAttempts = 30; // Try for 5 minutes (30 * 10s)
            for (int i = 0; i < maxAttempts; i++) {
                try {
                    // Wait between polls
                    Thread.sleep(10000);
                    
                    // Check if we have a result for this email
                    EmailVerificationResponse completedResult = checkForCompletedVerification(email);
                    
                    if (completedResult != null) {
                        // Complete the future with the result
                        CompletableFuture<EmailVerificationResponse> future = pendingVerifications.get(verificationId);
                        if (future != null && !future.isDone()) {
                            future.complete(completedResult);
                            logger.info("Pending verification {} completed for email {}", verificationId, email);
                            
                            // Once completed, we can remove it from tracking
                            pendingVerifications.remove(verificationId);
                        }
                        return;
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (Exception e) {
                    logger.error("Error checking pending verification for {}: {}", email, e.getMessage());
                }
            }
            
            // If we get here, verification timed out
            CompletableFuture<EmailVerificationResponse> future = pendingVerifications.get(verificationId);
            if (future != null && !future.isDone()) {
                // Complete with timeout error
                EmailVerificationResponse timeoutResult = new EmailVerificationResponse.Builder(email)
                        .withStatus("failed")
                        .withValid(false)
                        .withResultCode("timeout")
                        .withMessage("Verification timed out after 5 minutes")
                        .withEvent("verification_timeout")
                        .build();
                
                future.complete(timeoutResult);
                pendingVerifications.remove(verificationId);
                logger.warn("Pending verification {} timed out for email {}", verificationId, email);
            }
        });
    }
    
    /**
     * Check if a previously rate-limited email has now been validated
     */
    private EmailVerificationResponse checkForCompletedVerification(String email) {
        // Re-do validation to see if retry queue has completed it
        final var startTime = Instant.now();
        final var result = executeValidationPipeline(email);
        final var detailsByValidator = getDetailsByValidator(result);
        
        // Check if we still get a pending/retry status
        Map<String, Object> smtpDetails = detailsByValidator.getOrDefault("smtp", new HashMap<>());
        if (smtpDetails != null && smtpDetails.containsKey("event") && 
                ("retry_scheduled".equals(smtpDetails.get("event")) || 
                  smtpDetails.get("event").toString().contains("pending"))) {
            return null; // Still pending
        }
        
        // Extract properties from validation results
        final var hasMx = detailsByValidator.values().stream()
                .anyMatch(details -> details.containsKey("has-mx") && details.get("has-mx") != null && 
                        details.get("has-mx").toString().equals("1.0"));
        
        final var detailMap = new HashMap<String, Object>();
        for (final var entry : detailsByValidator.entrySet()) {
            detailMap.putAll(entry.getValue());
        }
        
        // Build response
        final var responseBuilder = new EmailVerificationResponse.Builder(email)
                .withValid(result.isValid())
                .withResponseTime(Duration.between(startTime, Instant.now()).toMillis())
                .withHasMx(hasMx);
        
        // Set flags based on validation results
        setEmailVerificationFlags(responseBuilder, detailMap);
        
        // Set status and result code
        String status;
        if (!result.isValid()) {
            status = "invalid";
        } else if (detailMap.containsKey("catch-all") && detailMap.get("catch-all").toString().equals("1.0")) {
            status = "catch-all";
        } else if (detailMap.containsKey("event") && 
                  ("inconclusive".equals(detailMap.get("event")) || detailMap.get("event").toString().contains("inconclusive"))) {
            status = "inconclusive";
        } else {
            status = "valid";
        }
        
        final var resultCode = getResultCode(result);
        
        responseBuilder.withStatus(status)
                .withResultCode(resultCode);
                
        final var response = responseBuilder.build();
        
        logger.info("Completed previously pending verification for {}: {}", email, response.getResultCode());
        return response;
    }

    /**
     * Verify multiple email addresses in batch
     */
    public List<EmailVerificationResponse> verifyEmails(final List<String> emails) {
        logger.info("Starting batch verification for {} emails", emails.size());
        final var results = new ArrayList<EmailVerificationResponse>(emails.size());
        
        for (final var email : emails) {
            try {
                results.add(verifyEmail(email));
            } catch (final Exception e) {
                logger.error("Error verifying email {}: {}", email, e.getMessage());
                final var errorResponseBuilder = new EmailVerificationResponse.Builder(email)
                        .withValid(false)
                        .withStatus("error")
                        .withResultCode("error")
                        .withMessage("Error: " + e.getMessage());
                results.add(errorResponseBuilder.build());
            }
        }
        
        logger.info("Completed batch verification for {} emails", emails.size());
        return results;
    }

    private ValidationResult executeValidationPipeline(final String email) {
        // Initialize combined result
        ValidationResult result = null;
        
        // Process each validator individually to avoid type issues
        try {
            ValidationResult syntaxResult = syntaxValidator.validate(email);
            result = syntaxResult;
            
            // Short-circuit if syntax validation fails
            if (!syntaxResult.isValid()) {
                logger.debug("Short-circuiting validation for {} after syntax validator returned invalid", email);
                return result;
            }
            
            ValidationResult mxResult = mxRecordValidator.validate(email);
            result = combineResults(result, mxResult);
            
            // Short-circuit if MX validation fails
            if (!mxResult.isValid()) {
                logger.debug("Short-circuiting validation for {} after mx-record validator returned invalid", email);
                return result;
            }
            
            ValidationResult smtpResult = smtpValidator.validate(email);
            result = combineResults(result, smtpResult);
            
        } catch (final Exception e) {
            logger.error("Error in validation pipeline: {}", e.getMessage());
        }
        
        // If we somehow got no result, create a default invalid one
        if (result == null) {
            result = ValidationResult.invalid("pipeline", "Validation pipeline failed");
        }
        
        return result;
    }
    
    /**
     * Helper method to add getDetailsByValidator functionality to ValidationResult
     */
    private Map<String, Map<String, Object>> getDetailsByValidator(ValidationResult result) {
        // In a real implementation, this would retrieve validator-specific details
        // For now, we'll create a simple map with the validator's details
        Map<String, Map<String, Object>> detailsByValidator = new HashMap<>();
        detailsByValidator.put(result.getValidatorName(), result.getDetails());
        return detailsByValidator;
    }
    
    /**
     * Helper method to combine validation results
     */
    private ValidationResult combineResults(ValidationResult first, ValidationResult second) {
        // Simple implementation: use the second result's validity only if the first was valid
        boolean combinedValid = first.isValid() && second.isValid();
        
        // Merge details from both results
        Map<String, Object> combinedDetails = new HashMap<>(first.getDetails());
        combinedDetails.putAll(second.getDetails());
        
        // Return a new result with the combined data
        return ValidationResult.builder()
                .valid(combinedValid)
                .validatorName("combined")
                .reason(combinedValid ? null : (second.isValid() ? first.getReason() : second.getReason()))
                .details(combinedDetails)
                .build();
    }

    private boolean shouldShortCircuit(final String validatorName) {
        // Skip SMTP validation if the email fails syntax or DNS validation
        return "syntax".equals(validatorName) || "dns".equals(validatorName) || "mx-record".equals(validatorName);
    }

    private String getResultCode(final ValidationResult result) {
        final var detailsByValidator = getDetailsByValidator(result);
        
        if (detailsByValidator.containsKey("syntax") && !detailsByValidator.get("syntax").isEmpty()) {
            if (!result.isValid()) {
                return "invalid_format";
            }
        }
        
        if (detailsByValidator.containsKey("mx-record") && !detailsByValidator.get("mx-record").isEmpty()) {
            if (!result.isValid()) {
                return "no_mx_records";
            }
        }
        
        if (detailsByValidator.containsKey("smtp") && !detailsByValidator.get("smtp").isEmpty()) {
            final var smtpDetails = detailsByValidator.get("smtp");
            
            if (smtpDetails.containsKey("event")) {
                final var event = smtpDetails.get("event").toString();
                switch (event) {
                    case "mailbox_exists": return "deliverable";
                    case "mailbox_does_not_exist": return "undeliverable";
                    case "is_catchall": return "catch_all";
                    case "verification_pending": return "pending";
                    case "retry_scheduled": return "pending";
                    case "retry_limit_exceeded": return "inconclusive";
                    default: return "inconclusive";
                }
            }
        }
        
        return result.isValid() ? "deliverable" : "undeliverable";
    }

    private void setEmailVerificationFlags(final EmailVerificationResponse.Builder builder, 
                                          final Map<String, Object> details) {
        // Extract common flags from validation details
        final var disposable = details.containsKey("disposable") && 
                (details.get("disposable").toString().equals("1.0"));
        
        final var role = details.containsKey("role") && 
                (details.get("role").toString().equals("1.0"));
        
        final var subAddressing = details.containsKey("sub-addressing") && 
                (details.get("sub-addressing").toString().equals("1.0"));
        
        final var free = details.containsKey("free") && 
                (details.get("free").toString().equals("1.0"));
        
        final var spam = details.containsKey("spam") && 
                (details.get("spam").toString().equals("1.0"));
        
        final var catchAll = details.containsKey("catch-all") && 
                (details.get("catch-all").toString().equals("1.0"));
        
        // Set optional fields
        builder.withDisposable(disposable)
               .withRole(role)
               .withSubAddressing(subAddressing)
               .withFree(free)
               .withSpam(spam);
        
        // Set general fields
        if (details.containsKey("reason")) {
            builder.withMessage(details.get("reason").toString());
        }
        
        if (details.containsKey("smtp-server")) {
            builder.withSmtpServer(details.get("smtp-server").toString());
        }
        
        if (details.containsKey("ip-address")) {
            builder.withIpAddress(details.get("ip-address").toString());
        }
        
        if (details.containsKey("country")) {
            builder.withCountry(details.get("country").toString());
        }
        
        if (details.containsKey("event")) {
            builder.withEvent(details.get("event").toString());
        }
        
        // Add any additional info
        final var additionalInfo = new StringBuilder();
        if (catchAll) {
            additionalInfo.append("The domain is catch-all, mail server accepts all emails. ");
        }
        
        if (!additionalInfo.isEmpty()) {
            builder.withAdditionalInfo(additionalInfo.toString().trim());
        }
    }

    private String getAdditionalInfoValue(final Map<String, Object> details, final String key) {
        try {
            if (details.containsKey(key)) {
                final var value = details.get(key);
                if (value != null) {
                    return value.toString();
                }
            }
            if (details.containsKey(key + "-value")) {
                final var value = details.get(key + "-value");
                if (value != null) {
                    return value.toString();
                }
            }
            return null;
        } catch (final Exception e) {
            logger.warn("Error extracting additional info for {}: {}", key, e.getMessage());
            return null;
        }
    }

    private String extractDomain(final String email) {
        if (email == null || email.isBlank() || !email.contains("@")) {
            return "";
        }
        return email.substring(email.indexOf('@') + 1).toLowerCase();
    }

    private EmailVerificationResponse validateEmailWithRetry(String email) {
        long startTime = System.currentTimeMillis();
        
        try {
            // Clean up the email first
            email = email.trim().toLowerCase();
            
            // Run through the entire validation pipeline
            ValidationResult validationResult = executeValidationPipeline(email);
            
            // Start building the response
            EmailVerificationResponse.Builder responseBuilder = new EmailVerificationResponse.Builder(email)
                .withResponseTime(System.currentTimeMillis() - startTime);
            
            // Set response based on validation result
            if (validationResult.isValid()) {
                Map<String, Object> details = validationResult.getDetails();
                
                // Check for catch-all domain
                boolean isCatchAll = false;
                if (details != null && details.containsKey("catch-all")) {
                    isCatchAll = true;
                    responseBuilder
                        .withEvent("is_catchall")
                        .withMessage("Catch-all domain detected")
                        .withStatus("deliverable")
                        .withResultCode("catch_all")
                        .withValid(true);
                } 
                // Check for inconclusive results
                else if (validationResult.getReason() != null && 
                         (validationResult.getReason().contains("Inconclusive") || 
                          validationResult.getReason().contains("rate limit") || 
                          validationResult.getReason().contains("Rate limited"))) {
                    responseBuilder
                        .withStatus("inconclusive")
                        .withResultCode("inconclusive")
                        .withMessage(validationResult.getReason())
                        .withEvent("inconclusive")
                        .withValid(false);
                }
                // If valid and not catch-all
                else {
                    responseBuilder
                        .withStatus("valid")
                        .withResultCode("deliverable")
                        .withMessage("Email appears deliverable")
                        .withValid(true);
                }
            } else {
                responseBuilder
                    .withStatus("invalid")
                    .withResultCode("undeliverable")
                    .withMessage(validationResult.getReason())
                    .withValid(false);
            }
            
            // Add any useful additional details
            if (validationResult.getDetails() != null && !validationResult.getDetails().isEmpty()) {
                for (Map.Entry<String, Object> entry : validationResult.getDetails().entrySet()) {
                    if (entry.getKey().equals("has-mx")) {
                        responseBuilder.withHasMx(Boolean.valueOf(entry.getValue().toString()));
                    } else if (entry.getKey().equals("smtp-server")) {
                        responseBuilder.withSmtpServer(entry.getValue().toString());
                    }
                    // could add more mappings here
                }
            }
            
            return responseBuilder.build();
            
        } catch (Exception e) {
            logger.error("Error validating email {}: {}", email, e.getMessage(), e);
            return new EmailVerificationResponse.Builder(email)
                .withStatus("error")
                .withResultCode("error")
                .withMessage("Validation error: " + e.getMessage())
                .withResponseTime(System.currentTimeMillis() - startTime)
                .withValid(false)
                .build();
        }
    }
}
