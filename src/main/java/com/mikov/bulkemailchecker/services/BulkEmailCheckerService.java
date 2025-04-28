package com.mikov.bulkemailchecker.services;

import com.mikov.bulkemailchecker.dtos.ValidationResult;
import com.mikov.bulkemailchecker.model.EmailVerificationResponse;
import com.mikov.bulkemailchecker.validation.MXRecordValidator;
import com.mikov.bulkemailchecker.validation.SyntaxValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.neverbounce.api.model.SingleCheckResponse;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Service for bulk email verification.
 * Orchestrates multiple validators to comprehensively verify email addresses.
 * 
 * @author zahari.mikov
 */
@Service
public final class BulkEmailCheckerService {
    private static final Logger logger = LoggerFactory.getLogger(BulkEmailCheckerService.class);

    private final EmailValidatorService emailValidatorService;
    private final SyntaxValidator syntaxValidator;
    private final MXRecordValidator mxRecordValidator;
    private final NeverBounceService neverBounceService;

    @Autowired
    public BulkEmailCheckerService(final EmailValidatorService emailValidatorService,
                                   final SyntaxValidator syntaxValidator,
                                   final MXRecordValidator mxRecordValidator,
                                   final NeverBounceService neverBounceService) {
        this.emailValidatorService = emailValidatorService;
        this.syntaxValidator = syntaxValidator;
        this.mxRecordValidator = mxRecordValidator;
        this.neverBounceService = neverBounceService;
    }

    public EmailVerificationResponse verifyEmail(final String email, final String neverbounceApiKey) {
        logger.info("Starting email verification for: {}", email);
        logger.debug("NeverBounce API key in verifyEmail: {}", 
            neverbounceApiKey != null && !neverbounceApiKey.isBlank() ? "provided" : "missing");
        
        if (email == null || email.isBlank()) {
            logger.info("Email is null or empty: {}", email);
            return new EmailVerificationResponse.Builder(email)
                    .withStatus("invalid")
                    .withResultCode("empty_email")
                    .build();
        }

        final var normalizedEmail = email.trim().toLowerCase();

        final var result = executeValidationPipeline(normalizedEmail, neverbounceApiKey);
        
        final var status = determineStatus(result);
        final var resultCode = getResultCode(result);
        
        final var responseBuilder = new EmailVerificationResponse.Builder(normalizedEmail)
                .withStatus(status)
                .withResultCode(resultCode)
                .withValid(result.isValid());
                
        if (result.getDetails() != null) {
            final var details = result.getDetails();
            
            if (details.containsKey("server")) {
                responseBuilder.withSmtpServer((String) details.get("server"));
            }
            if (details.containsKey("ip_address")) {
                responseBuilder.withIpAddress((String) details.get("ip_address"));
            }
            if (details.containsKey("event")) {
                responseBuilder.withEvent((String) details.get("event"));
            }
            
            if (details.containsKey("has-mx")) {
                responseBuilder.withHasMx(Boolean.TRUE.equals(details.get("has-mx")));
            }
            
            final var additionalInfo = new StringBuilder();
            if (details.containsKey("spf_record")) {
                additionalInfo.append("SPF: ").append(details.get("spf_record"));
            }
            if (details.containsKey("dmarc_record")) {
                if (!additionalInfo.isEmpty()) additionalInfo.append(", ");
                additionalInfo.append("DMARC: ").append(details.get("dmarc_record"));
            }
            if (details.containsKey("dkim_record")) {
                if (!additionalInfo.isEmpty()) additionalInfo.append(", ");
                additionalInfo.append("DKIM: ").append(details.get("dkim_record"));
            }
            
            if (!additionalInfo.isEmpty()) {
                responseBuilder.withAdditionalInfo(additionalInfo.toString());
            }
        }
        
        responseBuilder.withCreatedAt(OffsetDateTime.now().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME));
        
        return responseBuilder.build();
    }

    private String determineStatus(final ValidationResult result) {
        if (!result.isValid()) {
            return "invalid";
        }
        
        if (result.getDetails() != null) {
            final var details = result.getDetails();

            if (details.containsKey("event") && "server_restricted".equals(details.get("event"))) {
                return "unknown";
            }

            if (details.containsKey("event") && "is_catchall".equals(details.get("event"))) {
                return "catch-all";
            }

            if (details.containsKey("has_dns_issues") && Boolean.TRUE.equals(details.get("has_dns_issues"))) {
                return "valid_with_warnings";
            }

            if (details.containsKey("greylisting_detected") && Boolean.TRUE.equals(details.get("greylisting_detected"))) {
                return "valid";
            }

            if (details.containsKey("event") && "inconclusive".equals(details.get("event"))) {
                return "inconclusive";
            }
        }
        
        return "valid";
    }

    private EmailVerificationResponse checkForCompletedVerification(final String email, final String neverbounceApiKey) {
        final var startTime = Instant.now();
        final var result = executeValidationPipeline(email, neverbounceApiKey);
        final var detailsByValidator = getDetailsByValidator(result);
        
        final var smtpDetails = detailsByValidator.getOrDefault("smtp", new HashMap<>());
        if (smtpDetails != null && smtpDetails.containsKey("event") && 
                ("retry_scheduled".equals(smtpDetails.get("event")) || 
                  smtpDetails.get("event").toString().contains("pending"))) {
            return null; // Still pending
        }
        
        final var hasMx = detailsByValidator.values().stream()
                .anyMatch(details -> details.containsKey("has-mx") && details.get("has-mx") != null && 
                        details.get("has-mx").toString().equals("1.0"));
        
        final var detailMap = new HashMap<String, Object>();
        for (final var entry : detailsByValidator.entrySet()) {
            detailMap.putAll(entry.getValue());
        }
        
        final var responseBuilder = new EmailVerificationResponse.Builder(email)
                .withValid(result.isValid())
                .withResponseTime(Duration.between(startTime, Instant.now()).toMillis())
                .withHasMx(hasMx);
        
        setEmailVerificationFlags(responseBuilder, detailMap);
        
        final var status = determineStatusFromDetails(detailMap);
        final var resultCode = getResultCode(result);
        
        responseBuilder.withStatus(status)
                .withResultCode(resultCode);
                
        final var response = responseBuilder.build();
        
        logger.info("Completed previously pending verification for {}: {}", email, response.getResultCode());
        return response;
    }

    private String determineStatusFromDetails(final Map<String, Object> details) {
        if (details.containsKey("catch-all") && details.get("catch-all").toString().equals("1.0")) {
            return "catch-all";
        }
        if (details.containsKey("event") && 
            ("inconclusive".equals(details.get("event")) || details.get("event").toString().contains("inconclusive"))) {
            return "inconclusive";
        }
        return "valid";
    }

    public List<EmailVerificationResponse> verifyEmails(final List<String> emails, final String neverbounceApiKey) {
        logger.info("Starting batch verification for {} emails", emails.size());
        final var results = new ArrayList<EmailVerificationResponse>(emails.size());
        
        for (final var email : emails) {
            try {
                results.add(verifyEmail(email, neverbounceApiKey));
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

    private ValidationResult executeValidationPipeline(final String email, final String neverbounceApiKey) {
        logger.debug("Executing validation pipeline for email: {} with NeverBounce API key present: {}", 
            email, neverbounceApiKey != null && !neverbounceApiKey.isBlank());
            
        final var syntaxResult = syntaxValidator.validate(email);
        if (!syntaxResult.isValid()) {
            logger.debug("Email {} failed syntax validation: {}", email, syntaxResult.getReason());
            return syntaxResult;
        }
        
        final var mxResult = mxRecordValidator.validate(email);
        if (!mxResult.isValid()) {
            logger.debug("Email {} failed MX record validation: {}", email, mxResult.getReason());
            return mxResult;
        }
        
        final var smtpResult = emailValidatorService.validate(email);
        
        if (!smtpResult.isValid()) {
            logger.debug("Email {} failed SMTP validation: {}", email, smtpResult.getReason());
            return smtpResult;
        }
        
        if (smtpResult.getDetails() != null) {
            final var details = smtpResult.getDetails();
            if (details.containsKey("event") && ("is_catchall".equals(details.get("event")) || "inconclusive".equals(details.get("event")) || String.valueOf(details.get("error_message")).contains("451"))) {
                logger.info("Catch-all domain detected for email {}. Performing additional verification with NeverBounce.", email);
                logger.debug("NeverBounce API key before calling service: {}", 
                    neverbounceApiKey != null ? "present" : "null");
                
                final var neverBounceResult = neverBounceService.verifyEmail(email, neverbounceApiKey);
                
                if (neverBounceResult.getDetails() != null &&
                    neverBounceResult.getDetails().containsKey("error_code") && 
                    "invalid_api_key".equals(neverBounceResult.getDetails().get("error_code"))) {
                    logger.error("NeverBounce API key is invalid. Throwing exception.");
                    throw new RuntimeException("Invalid NeverBounce API key. Please provide a valid API key.");
                }
                
                final var responseObj = neverBounceResult.getDetails().get("response");
                if (responseObj instanceof SingleCheckResponse response) {
                    final var nbResult = response.getResult().name();
                    logger.info("NeverBounce gave definitive result for catch-all domain email {}: {}", email, nbResult);

                    if ("VALID".equalsIgnoreCase(nbResult)) {
                        details.put("event", "mailbox_exists");
                        details.put("neverbounce_result", "deliverable");
                        return smtpResult;
                    }
                    if ("CATCHALL".equalsIgnoreCase(nbResult)) {
                        details.put("event", "is_catchall");
                        details.put("neverbounce_result", "catchall");
                        return smtpResult;
                    }
                    if ("INVALID".equalsIgnoreCase(nbResult)) {
                        details.put("event", "mailbox_does_not_exist");
                        details.put("neverbounce_result", "undeliverable");
                        return neverBounceResult;
                    }
                }
                details.put("event", "is_catchall");
                return smtpResult;
            }
        }
        
        return smtpResult;
    }

    private Map<String, Map<String, Object>> getDetailsByValidator(final ValidationResult result) {
        final var detailsByValidator = new HashMap<String, Map<String, Object>>();
        detailsByValidator.put(result.getValidatorName(), result.getDetails());
        return detailsByValidator;
    }

    private String getResultCode(final ValidationResult result) {
        if (!result.isValid()) {
            return result.getReason() != null ? result.getReason() : "invalid_email";
        }
        
        if (result.getDetails() != null) {
            final var details = result.getDetails();
            
            if (details.containsKey("event") && "is_catchall".equals(details.get("event"))) {
                return "catch_all_domain";
            }
            
            if (details.containsKey("has_dns_issues") && Boolean.TRUE.equals(details.get("has_dns_issues"))) {
                if (details.containsKey("spf_record") && "missing".equals(details.get("spf_record"))) {
                    return "missing_spf";
                }
                if (details.containsKey("dmarc_record") && "missing".equals(details.get("dmarc_record"))) {
                    return "missing_dmarc";
                }
                return "dns_configuration_issues";
            }
            
            if (details.containsKey("greylisting_detected") && Boolean.TRUE.equals(details.get("greylisting_detected"))) {
                return "greylisting_passed";
            }
            
            if (details.containsKey("event") && "inconclusive".equals(details.get("event"))) {
                return "inconclusive_result";
            }
        }
        
        return "valid_email";
    }

    private void setEmailVerificationFlags(final EmailVerificationResponse.Builder builder, 
                                          final Map<String, Object> details) {
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
        
        builder.withDisposable(disposable)
               .withRole(role)
               .withSubAddressing(subAddressing)
               .withFree(free)
               .withSpam(spam);
        
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
        
        final var additionalInfo = new StringBuilder();
        if (catchAll) {
            additionalInfo.append("The domain is catch-all, mail server accepts all emails. ");
        }
        
        if (!additionalInfo.isEmpty()) {
            builder.withAdditionalInfo(additionalInfo.toString().trim());
        }
    }

    public EmailVerificationResponse validateEmailWithRetry(final String email, final String neverbounceApiKey) {
        logger.debug("validateEmailWithRetry called for email {} with NeverBounce API key: {}", 
            email, neverbounceApiKey != null && !neverbounceApiKey.isBlank() ? "provided" : "missing");
            
        final var completedResponse = checkForCompletedVerification(email, neverbounceApiKey);
        if (completedResponse != null) {
            return completedResponse;
        }
        
        final var startTime = Instant.now();
        final var result = executeValidationPipeline(email, neverbounceApiKey);
        final var detailsByValidator = getDetailsByValidator(result);
        
        final var hasMx = detailsByValidator.values().stream()
                .anyMatch(details -> details.containsKey("has-mx") && details.get("has-mx") != null && 
                        details.get("has-mx").toString().equals("1.0"));
        
        final var detailMap = new HashMap<String, Object>();
        for (final var entry : detailsByValidator.entrySet()) {
            detailMap.putAll(entry.getValue());
        }
        
        final var responseBuilder = new EmailVerificationResponse.Builder(email)
                .withValid(result.isValid())
                .withResponseTime(Duration.between(startTime, Instant.now()).toMillis())
                .withHasMx(hasMx);
        
        setEmailVerificationFlags(responseBuilder, detailMap);
        
        final var status = determineStatusFromDetails(detailMap);
        final var resultCode = getResultCode(result);
        
        responseBuilder.withStatus(status)
                .withResultCode(resultCode);
                
        final var response = responseBuilder.build();
        
        logger.info("Completed verification for {}: {}", email, response.getResultCode());
        return response;
    }
}
