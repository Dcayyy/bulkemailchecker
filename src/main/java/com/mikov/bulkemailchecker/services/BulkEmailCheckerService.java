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
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;

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
    private final NeverBounceService neverBounceService;

    // Map to store pending verification results that clients can query later
    private final Map<String, CompletableFuture<EmailVerificationResponse>> pendingVerifications = new ConcurrentHashMap<>();

    @Autowired
    public BulkEmailCheckerService(final SMTPValidator smtpValidator,
                                   final SyntaxValidator syntaxValidator,
                                   final MXRecordValidator mxRecordValidator,
                                   final TaskExecutor taskExecutor,
                                   final NeverBounceService neverBounceService) {
        this.smtpValidator = smtpValidator;
        this.syntaxValidator = syntaxValidator;
        this.mxRecordValidator = mxRecordValidator;
        this.taskExecutor = taskExecutor;
        this.neverBounceService = neverBounceService;
    }

    /**
     * Verify a single email address
     */
    public EmailVerificationResponse verifyEmail(String email) {
        logger.info("Starting email verification for: {}", email);
        
        if (email == null || email.isBlank()) {
            logger.info("Email is null or empty: {}", email);
            return new EmailVerificationResponse.Builder(email)
                    .withStatus("invalid")
                    .withResultCode("empty_email")
                    .build();
        }

        // Clean email (trim, lowercase)
        email = email.trim().toLowerCase();

        // Execute validation pipeline
        ValidationResult result = executeValidationPipeline(email);
        
        // Determine email status based on the validity of the result
        String status;
        
        if (!result.isValid()) {
            status = "invalid";
        } else if (result.getDetails() != null) {
            // Check for specific cases in the result details
            Map<String, Object> details = result.getDetails();
            
            // Check for catch-all domains - ensure they are always marked as catch-all
            if (details.containsKey("event") && "is_catchall".equals(details.get("event"))) {
                status = "catch-all";
            } 
            // Check for DNS issues that might affect deliverability
            else if (details.containsKey("has_dns_issues") && Boolean.TRUE.equals(details.get("has_dns_issues"))) {
                // If there are DNS issues but the email is otherwise valid, mark as potentially valid
                // but include the DNS issues in the response
                status = "valid_with_warnings";
            }
            // Check for greylisting behavior
            else if (details.containsKey("greylisting_detected") && Boolean.TRUE.equals(details.get("greylisting_detected"))) {
                // If greylisting was detected and bypassed, the email is likely valid
                status = "valid";
            }
            // Check for inconclusive events
            else if (details.containsKey("event") && "inconclusive".equals(details.get("event"))) {
                status = "inconclusive";
            } else {
                status = "valid";
            }
        } else {
            status = "valid";
        }
        
        // Get result code
        String resultCode = getResultCode(result);
        
        // Build response
        EmailVerificationResponse.Builder responseBuilder = new EmailVerificationResponse.Builder(email)
                .withStatus(status)
                .withResultCode(resultCode)
                .withValid(result.isValid());
                
        // Add details if available
        if (result.getDetails() != null) {
            Map<String, Object> details = result.getDetails();
            
            // Add basic SMTP details
            if (details.containsKey("server")) {
                responseBuilder.withSmtpServer((String) details.get("server"));
            }
            if (details.containsKey("ip_address")) {
                responseBuilder.withIpAddress((String) details.get("ip_address"));
            }
            if (details.containsKey("event")) {
                responseBuilder.withEvent((String) details.get("event"));
            }
            
            // Handle MX record info
            if (details.containsKey("has-mx")) {
                responseBuilder.withHasMx(Boolean.TRUE.equals(details.get("has-mx")));
            }
            
            // Add DNS verification details
            StringBuilder additionalInfo = new StringBuilder();
            if (details.containsKey("spf_record")) {
                additionalInfo.append("SPF: ").append(details.get("spf_record"));
            }
            if (details.containsKey("dmarc_record")) {
                if (additionalInfo.length() > 0) additionalInfo.append(", ");
                additionalInfo.append("DMARC: ").append(details.get("dmarc_record"));
            }
            if (details.containsKey("dkim_record")) {
                if (additionalInfo.length() > 0) additionalInfo.append(", ");
                additionalInfo.append("DKIM: ").append(details.get("dkim_record"));
            }
            
            if (additionalInfo.length() > 0) {
                responseBuilder.withAdditionalInfo(additionalInfo.toString());
            }
        }
        
        // Set current timestamp
        responseBuilder.withCreatedAt(OffsetDateTime.now().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME));
        
        return responseBuilder.build();
    }

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

    /**
     * Execute validation pipeline
     */
    private ValidationResult executeValidationPipeline(final String email) {
        // Validate syntax first - this is the fastest check
        ValidationResult syntaxResult = syntaxValidator.validate(email);
        if (!syntaxResult.isValid()) {
            logger.debug("Email {} failed syntax validation: {}", email, syntaxResult.getReason());
            return syntaxResult;
        }
        
        // Validate MX record - also relatively fast
        ValidationResult mxResult = mxRecordValidator.validate(email);
        if (!mxResult.isValid()) {
            logger.debug("Email {} failed MX record validation: {}", email, mxResult.getReason());
            return mxResult;
        }
        
        // Finally validate via SMTP - this is the most time-consuming check
        ValidationResult smtpResult = smtpValidator.validate(email);
        
        if (!smtpResult.isValid()) {
            logger.debug("Email {} failed SMTP validation: {}", email, smtpResult.getReason());
            return smtpResult;
        }
        
        // Check if the result indicates a catch-all domain
        if (smtpResult.getDetails() != null) {
            Map<String, Object> details = smtpResult.getDetails();
            if (details.containsKey("event") && "is_catchall".equals(details.get("event"))) {
                logger.info("Catch-all domain detected for email {}. Performing additional verification with NeverBounce.", email);
                
                // For catch-all domains, perform an additional verification with NeverBounce
                ValidationResult neverBounceResult = neverBounceService.verifyEmail(email);
                
                // If NeverBounce gave a definitive result (valid or invalid), use that
                if (neverBounceResult.getDetails().containsKey("formatted_result")) {
                    // Extract formatted result from NeverBounce
                    @SuppressWarnings("unchecked")
                    Map<String, Object> formattedResult = 
                        (Map<String, Object>) neverBounceResult.getDetails().get("formatted_result");
                    
                    String nbResult = (String) formattedResult.get("result");
                    logger.info("NeverBounce gave definitive result for catch-all domain email {}: {}", email, nbResult);
                    
                    // If NeverBounce says the email is valid, return it as valid 
                    if ("valid".equals(nbResult)) {
                        // Copy event from NeverBounce result to SMTP result
                        if (neverBounceResult.getDetails().containsKey("event")) {
                            details.put("event", neverBounceResult.getDetails().get("event"));
                        }
                        return smtpResult; // Return as valid but keep the original SMTP details
                    } 
                    // If NeverBounce confirms it's a catch-all, keep the catch-all status
                    else if ("catchall".equals(nbResult)) {
                        // Make sure the event is marked as catch-all
                        details.put("event", "is_catchall");
                        return smtpResult; // Keep the catch-all status
                    }
                    // If NeverBounce says it's invalid, return the NeverBounce result
                    else if ("invalid".equals(nbResult)) {
                        return neverBounceResult;
                    }
                }
                
                // If NeverBounce didn't give a definitive result, fall back to SMTP result
                // But ensure it has the catch-all event set
                details.put("event", "is_catchall");
                return smtpResult;
            }
        }
        
        // Return the SMTP result if no catch-all issues
        return smtpResult;
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

    private String getResultCode(ValidationResult result) {
        if (!result.isValid()) {
            return result.getReason() != null ? result.getReason() : "invalid_email";
        }
        
        // If valid but with specific conditions
        if (result.getDetails() != null) {
            Map<String, Object> details = result.getDetails();
            
            // Check for catch-all domains
            if (details.containsKey("event") && "is_catchall".equals(details.get("event"))) {
                return "catch_all_domain";
            }
            
            // Check for DNS issues
            if (details.containsKey("has_dns_issues") && Boolean.TRUE.equals(details.get("has_dns_issues"))) {
                if (details.containsKey("spf_record") && "missing".equals(details.get("spf_record"))) {
                    return "missing_spf";
                }
                if (details.containsKey("dmarc_record") && "missing".equals(details.get("dmarc_record"))) {
                    return "missing_dmarc";
                }
                return "dns_configuration_issues";
            }
            
            // Check for greylisting
            if (details.containsKey("greylisting_detected") && Boolean.TRUE.equals(details.get("greylisting_detected"))) {
                return "greylisting_passed";
            }
            
            // Check for inconclusive events
            if (details.containsKey("event") && "inconclusive".equals(details.get("event"))) {
                return "inconclusive_result";
            }
        }
        
        return "valid_email";
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

    /**
     * Verify a single email address with retry and advanced catch-all analysis
     */
    public EmailVerificationResponse validateEmailWithRetry(final String email) {
        final var startTime = Instant.now();
        logger.info("Starting email verification for: {}", email);
        
        // Clean the email
        String cleanEmail = email.trim().toLowerCase();
        
        // Execute validation pipeline
        final var result = executeValidationPipeline(cleanEmail);
        final var detailsByValidator = getDetailsByValidator(result);
        
        // Extract properties from validation results
        final var hasMx = detailsByValidator.values().stream()
                .anyMatch(details -> details.containsKey("has-mx") && details.get("has-mx") != null && 
                        details.get("has-mx").toString().equals("1.0"));
        
        final var detailMap = new HashMap<String, Object>();
        for (final var entry : detailsByValidator.entrySet()) {
            detailMap.putAll(entry.getValue());
        }
        
        // Build response
        final var responseBuilder = new EmailVerificationResponse.Builder(cleanEmail)
                .withValid(result.isValid())
                .withResponseTime(Duration.between(startTime, Instant.now()).toMillis())
                .withHasMx(hasMx);
        
        // Set flags based on validation results
        setEmailVerificationFlags(responseBuilder, detailMap);
        
        // Determine status for catch-all domains with improved heuristics
        String status;
        String resultCode;
        
        if (!result.isValid()) {
            status = "invalid";
            resultCode = "undeliverable";
        } else if (detailMap.containsKey("catch-all") && detailMap.get("catch-all").toString().equals("1.0")) {
            // For catch-all domains, apply heuristics
            if (analyzeEmailInCatchAllDomain(cleanEmail)) {
                status = "valid";
                resultCode = "deliverable";
                logger.info("Email {} in catch-all domain assessed as likely deliverable", cleanEmail);
            } else {
                status = "catch-all";
                resultCode = "catch_all";
                logger.info("Email {} in catch-all domain without additional confidence", cleanEmail);
            }
        } else if (detailMap.containsKey("event") && 
                  ("inconclusive".equals(detailMap.get("event")) || detailMap.get("event").toString().contains("inconclusive"))) {
            status = "inconclusive";
            resultCode = "inconclusive";
        } else {
            status = "valid";
            resultCode = "deliverable";
        }
        
        responseBuilder.withStatus(status)
                .withResultCode(resultCode);
                
        final var response = responseBuilder.build();
        
        logger.info("Email verification result for {}: {}", cleanEmail, response.getResultCode());
        return response;
    }
    
    /**
     * Analyze an email in a catch-all domain with heuristics to determine
     * if it's likely a real address despite being in a catch-all domain.
     * 
     * @param email The email to analyze
     * @return true if the email is likely valid within the catch-all domain
     */
    private boolean analyzeEmailInCatchAllDomain(String email) {
        try {
            String[] parts = email.split("@", 2);
            if (parts.length != 2) {
                return false;
            }
            
            String localPart = parts[0];
            String domain = parts[1];
            
            // Heuristic 1: Common email patterns (first.last, first_last, firstlast)
            if (isCommonEmailPattern(localPart)) {
                logger.debug("Email {} matches common naming pattern", email);
                return true;
            }
            
            // Heuristic 2: Length-based analysis (extremely long or very short emails are less likely)
            if (localPart.length() > 30 || localPart.length() < 3) {
                logger.debug("Email {} has unusual length local part: {}", email, localPart.length());
                return false;
            }
            
            // Heuristic 3: Character distribution (real emails tend to have more letters than numbers/symbols)
            double letterRatio = calculateLetterRatio(localPart);
            if (letterRatio < 0.5) {
                logger.debug("Email {} has low letter ratio: {}", email, letterRatio);
                return false;
            }
            
            // Heuristic 4: Domain-specific conventions
            if (domainHasKnownFormat(domain, localPart)) {
                logger.debug("Email {} matches known domain format for {}", email, domain);
                return true;
            }
            
            // Default: moderate confidence
            return true;
            
        } catch (Exception e) {
            logger.warn("Error analyzing email in catch-all domain: {}", e.getMessage());
            return false;
        }
    }
    
    /**
     * Checks if the local part follows common email patterns
     */
    private boolean isCommonEmailPattern(String localPart) {
        // Pattern 1: first.last
        if (localPart.contains(".") && !localPart.startsWith(".") && !localPart.endsWith(".")) {
            String[] nameParts = localPart.split("\\.");
            if (nameParts.length == 2 && nameParts[0].length() >= 2 && nameParts[1].length() >= 2) {
                return true;
            }
        }
        
        // Pattern 2: first_last
        if (localPart.contains("_") && !localPart.startsWith("_") && !localPart.endsWith("_")) {
            String[] nameParts = localPart.split("_");
            if (nameParts.length == 2 && nameParts[0].length() >= 2 && nameParts[1].length() >= 2) {
                return true;
            }
        }
        
        // Pattern 3: firstlast (e.g., johndoe)
        if (localPart.length() >= 5 && localPart.length() <= 20 && localPart.matches("[a-zA-Z]+")) {
            return true;
        }
        
        // Pattern 4: first initial + last name (e.g., jdoe)
        if (localPart.length() >= 4 && localPart.length() <= 12 && 
            localPart.matches("[a-zA-Z][a-zA-Z]+") && 
            Character.isLetter(localPart.charAt(0))) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Calculate the ratio of letters to total characters
     */
    private double calculateLetterRatio(String text) {
        if (text.isEmpty()) {
            return 0;
        }
        
        int letterCount = 0;
        for (char c : text.toCharArray()) {
            if (Character.isLetter(c)) {
                letterCount++;
            }
        }
        
        return (double) letterCount / text.length();
    }
    
    /**
     * Check if the email matches known patterns for specific domains
     */
    private boolean domainHasKnownFormat(String domain, String localPart) {
        // Gmail typically uses firstname.lastname or firstnamelastname
        if (domain.equals("gmail.com")) {
            return localPart.contains(".") || localPart.matches("[a-zA-Z]+");
        }
        
        // Microsoft domains often use firstname.lastname or first.last@
        if (domain.equals("outlook.com") || domain.equals("hotmail.com") || domain.equals("live.com")) {
            return localPart.contains(".") || localPart.contains("_");
        }
        
        // Company domains often use first initial + last name or first.last
        if (domain.contains(".com") && !isCommonPublicDomain(domain)) {
            return localPart.contains(".") || 
                   (localPart.length() >= 4 && localPart.length() <= 12);
        }
        
        return false;
    }
    
    /**
     * Check if domain is a common public email provider
     */
    private boolean isCommonPublicDomain(String domain) {
        String[] publicDomains = {
            "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", 
            "aol.com", "icloud.com", "protonmail.com", "mail.com"
        };
        
        for (String publicDomain : publicDomains) {
            if (domain.equals(publicDomain)) {
                return true;
            }
        }
        return false;
    }
}
