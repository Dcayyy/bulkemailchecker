package com.mikov.bulkemailchecker.services;

import com.mikov.bulkemailchecker.model.EmailVerificationResponse;
import com.mikov.bulkemailchecker.validation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.core.task.TaskExecutor;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.time.Instant;

/**
 * Service for handling email verification.
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

    public EmailVerificationResponse verifyEmail(final String email) {
        final var normalizedEmail = email.trim().toLowerCase();
        final var builder = new EmailVerificationResponse.Builder(normalizedEmail)
                .withCreatedAt(Instant.now().toString());

        final var formatResult = syntaxValidator.validate(normalizedEmail);
        if (!formatResult.isValid()) {
            final var response = builder.withStatus("invalid")
                    .withValid(false)
                    .withResultCode("invalid_format")
                    .withMessage(formatResult.getReason())
                    .withHasMx(false)
                    .withCountry("")
                    .withEvent("is_non-existent")
                    .build();
                    
            logger.info("Email verification result for {}: INVALID FORMAT", email);
            return response;
        }

        final var parts = normalizedEmail.split("@", 2);
        final var domain = parts[1].toLowerCase();

        final var mxRecordResult = mxRecordValidator.validate(normalizedEmail);
        if (!mxRecordResult.isValid()) {
            final var response = builder.withStatus("invalid")
                    .withValid(false)
                    .withResultCode("mx_record_not_found")
                    .withMessage("No MX records found for domain " + domain)
                    .withHasMx(false)
                    .withCountry("")
                    .withEvent("is_non-existent")
                    .build();
                    
            logger.info("Email verification result for {}: NO MX RECORDS", email);
            return response;
        }

        builder.withHasMx(true);
        builder.withCountry("");

        final var smtpResult = smtpValidator.validate(normalizedEmail);
        var isCatchAll = false;
        String event = "is_deliverable";
        String status = "deliverable";
        String emailMessage = null;
        String additionalInfo = "";
        double confidence = 0.0;
        
        builder.withHasMx(true);
        
        if (smtpResult.getDetails() != null) {
            if (smtpResult.getDetails().containsKey("catch-all") &&
                smtpResult.getDetails().get("catch-all").equals(1.0)) {
                isCatchAll = true;
            }
            
            if (smtpResult.getDetails().containsKey("status")) {
                status = smtpResult.getDetails().get("status").toString();
            }
            
            if (smtpResult.getDetails().containsKey("event")) {
                event = smtpResult.getDetails().get("event").toString();
            }
            
            if (smtpResult.getDetails().containsKey("confidence")) {
                try {
                    confidence = (Double) smtpResult.getDetails().get("confidence");
                    additionalInfo = "Confidence score: " + String.format("%.2f", confidence);
                } catch (Exception e) {
                    logger.warn("Could not parse confidence value");
                }
            }
            
            if (smtpResult.getDetails().containsKey("smtp-server")) {
                final var server = smtpResult.getDetails().get("smtp-server").toString();
                if (server != null && !server.isEmpty()) {
                    builder.withSmtpServer(server);
                }
            }
            
            if (smtpResult.getDetails().containsKey("ip-address")) {
                final var ip = smtpResult.getDetails().get("ip-address").toString();
                if (ip != null && !ip.isEmpty()) {
                    builder.withIpAddress(ip);
                }
            }
            
            if (smtpResult.getDetails().containsKey("provider")) {
                final var emailProvider = smtpResult.getDetails().get("provider").toString();
                if (emailProvider != null && !emailProvider.isEmpty()) {
                    if (!additionalInfo.isEmpty()) {
                        additionalInfo += "; ";
                    }
                    additionalInfo += "Email provider: " + emailProvider;
                }
            }
            
            if (smtpResult.getDetails().containsKey("reason")) {
                final var reason = smtpResult.getDetails().get("reason").toString();
                if (reason != null && !reason.isEmpty()) {
                    emailMessage = reason;
                }
            }
        }
        
        if (!additionalInfo.isEmpty()) {
            builder.withAdditionalInfo(additionalInfo);
        }

        final EmailVerificationResponse response;
        
        if (isCatchAll) {
            response = builder.withStatus("unknown")
                    .withValid(true)
                    .withResultCode("is_catchall")
                    .withMessage("This domain appears to be a catch-all domain. While this email may be deliverable, the domain accepts mail for any address.")
                    .withHasMx(true)
                    .withCountry("")
                    .withEvent("is_catchall")
                    .build();
                    
            logger.info("Email verification result for {}: CATCH-ALL DOMAIN", email);
        } else if (status.equals("unknown")) {
            response = builder.withStatus("unknown")
                    .withValid(true)
                    .withResultCode("inconclusive")
                    .withMessage(emailMessage != null ? emailMessage : "The email verification result is inconclusive")
                    .withHasMx(true)
                    .withCountry("")
                    .withEvent(event)
                    .build();
                    
            logger.info("Email verification result for {}: INCONCLUSIVE", email);
        } else if (smtpResult.isValid() || event.equals("mailbox_exists")) {
            String resultMessage = emailMessage;
            if (resultMessage == null) {
                if (confidence >= 0.9) {
                    resultMessage = "Email address exists and can receive email";
                } else if (confidence >= 0.7) {
                    resultMessage = "Email address is likely to exist and receive email";
                } else {
                    resultMessage = "Email address appears to exist, but verification is not conclusive";
                }
            }
            
            response = builder.withStatus("deliverable")
                    .withValid(true)
                    .withResultCode("success")
                    .withMessage(resultMessage)
                    .withHasMx(true)
                    .withCountry("")
                    .withEvent(event)
                    .build();
                    
            logger.info("Email verification result for {}: DELIVERABLE", email);
        } else {
            response = builder.withStatus("undeliverable")
                    .withValid(false)
                    .withResultCode("failure")
                    .withMessage(emailMessage != null ? emailMessage : "Email address does not exist")
                    .withHasMx(true)
                    .withCountry("")
                    .withEvent(event)
                    .build();
                    
            logger.info("Email verification result for {}: UNDELIVERABLE", email);
        }
        
        return response;
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

    public List<EmailVerificationResponse> verifyEmails(final List<String> emails) {
        logger.info("Verifying batch of {} emails", emails.size());
        
        final var emailsByDomain = emails.stream()
                .collect(Collectors.groupingBy(this::extractDomain));

        final var verifiedEmails = getVerifiedEmails(emailsByDomain);
        final var results = verifiedEmails.stream()
                .map(CompletableFuture::join)
                .collect(Collectors.toList());
                
        logger.info("Completed verification of {} emails", emails.size());
        
        return results;
    }

    private ArrayList<CompletableFuture<EmailVerificationResponse>> getVerifiedEmails(final Map<String, List<String>> emailsByDomain) {
        final var futures = new ArrayList<CompletableFuture<EmailVerificationResponse>>();
        
        for (final var entry : emailsByDomain.entrySet()) {
            final var domain = entry.getKey();
            final var domainEmails = entry.getValue();
            final var domainLimiter = domainLimiters.computeIfAbsent(
                domain, k -> new Semaphore(MAX_CONCURRENT_PER_DOMAIN)
            );
            
            for (final var email : domainEmails) {
                final var emailFuture = CompletableFuture.supplyAsync(() -> {
                    try {
                        if (!domainLimiter.tryAcquire(30, TimeUnit.SECONDS)) {
                            logger.warn("Timeout waiting for rate limit permit for domain {}", domain);
                        }
                        
                        applyDomainThrottling(domain);
                        
                        try {
                            return verifyEmail(email);
                        } finally {
                            lastDomainAccessTime.put(domain, System.currentTimeMillis());
                            domainLimiter.release();
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        logger.error("Interrupted while waiting for rate limit permit", e);
                        
                        return new EmailVerificationResponse.Builder(email)
                                .withCreatedAt(Instant.now().toString())
                                .withStatus("error")
                                .withValid(false)
                                .withResultCode("rate_limit_error")
                                .withMessage("Email verification was interrupted")
                                .withHasMx(false)
                                .withCountry("")
                                .withEvent("inconclusive")
                                .build();
                    }
                }, taskExecutor);
                
                futures.add(emailFuture);
            }
        }
        
        return futures;
    }
    
    private void applyDomainThrottling(String domain) {
        final var lastAccess = lastDomainAccessTime.getOrDefault(domain, 0L);
        final var elapsedSinceLastAccess = System.currentTimeMillis() - lastAccess;
        
        if (lastAccess > 0 && elapsedSinceLastAccess < DOMAIN_THROTTLE_DELAY_MS) {
            try {
                final var delayNeeded = DOMAIN_THROTTLE_DELAY_MS - elapsedSinceLastAccess;
                if (delayNeeded > 0) {
                    logger.debug("Throttling domain {} for {} ms", domain, delayNeeded);
                    Thread.sleep(delayNeeded);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                logger.warn("Domain throttling interrupted for {}", domain);
            }
        }
    }

    private String extractDomain(final String email) {
        final var atIndex = email.lastIndexOf('@');
        if (atIndex != -1 && atIndex < email.length() - 1) {
            return email.substring(atIndex + 1).toLowerCase();
        }
        return "";
    }
}
