package com.mikov.bulkemailchecker.validation;

import com.mikov.bulkemailchecker.dtos.ValidationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

/**
 * Pipeline for email validation that runs multiple validators in parallel.
 *
 * @author zahari.mikov
 */
public class EmailValidationPipeline {
    private static final Logger logger = LoggerFactory.getLogger(EmailValidationPipeline.class);
    
    private final ExecutorService executor;
    private final List<EmailValidator> validators;
    private final CustomScoreCalculator scoreCalculator;
    
    public EmailValidationPipeline(final List<EmailValidator> validators, final CustomScoreCalculator scoreCalculator) {
        this.validators = new ArrayList<>(validators);
        this.scoreCalculator = scoreCalculator;
        // Use virtual threads for optimal I/O concurrency with minimal resource usage
        this.executor = Executors.newVirtualThreadPerTaskExecutor();
        for (final var validator : validators) {
            logger.debug("Loaded validator: {}", validator.getName());
        }
    }

    public ValidationResult validate(final String email) {
        final var normalizedEmail = email.trim().toLowerCase();
        
        final var validatorResults = new ConcurrentHashMap<String, ValidationResult>();
        final var futures = new ArrayList<CompletableFuture<Void>>();
        
        for (final var validator : validators) {
            final var future = CompletableFuture.runAsync(() -> {
                try {
                    final var result = validator.validate(normalizedEmail);
                    validatorResults.put(validator.getName(), result);
                } catch (final Exception e) {
                    logger.error("Error in validator {}: {}", validator.getName(), e.getMessage());
                    validatorResults.put(validator.getName(), 
                        ValidationResult.invalid(validator.getName(), "Validation error: " + e.getMessage()));
                }
            }, executor);
            
            futures.add(future);
        }
        
        try {
            CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
        } catch (final Exception e) {
            logger.error("Error waiting for validators: {}", e.getMessage());
        }
        
        final var detailScores = new HashMap<String, Double>();
        var isValid = true;
        var isCatchAll = false;
        var isSmtpBlocked = false;
        var domainAge = 0;
        
        for (final var entry : validatorResults.entrySet()) {
            final var validatorName = entry.getKey();
            final var result = entry.getValue();
            
            detailScores.put(validatorName, result.getScore());
            
            if (validatorName.equals("smtp")) {
                isCatchAll = result.getDetails().getOrDefault("catch-all", 0.0) > 0;
                // Check if SMTP verification is blocked
                if (result.getScore() <= 0.2 && result.isValid()) {
                    isSmtpBlocked = true;
                    logger.debug("SMTP verification blocked for email {}", normalizedEmail);
                }
            }
            
            if (validatorName.equals("domain-age") && result.getDetails().containsKey("age")) {
                domainAge = result.getDetails().get("age").intValue();
            }
            
            if (!result.isValid()) {
                isValid = false;
            }
        }
        
        // Special handling for blocked SMTP validation
        if (isSmtpBlocked) {
            // If we have HTTP or web-scraper results, treat them with higher priority
            var hasFallbackVerification = false;
            
            if (validatorResults.containsKey("http") && validatorResults.get("http").isValid()) {
                final var httpScore = validatorResults.get("http").getScore();
                if (httpScore > 0.5) {
                    hasFallbackVerification = true;
                    logger.debug("Using HTTP validation fallback for blocked SMTP: {}", normalizedEmail);
                }
            }
            
            if (validatorResults.containsKey("web-scraper") && validatorResults.get("web-scraper").isValid()) {
                final var scraperScore = validatorResults.get("web-scraper").getScore();
                if (scraperScore > 0.6) {
                    hasFallbackVerification = true;
                    logger.debug("Using web-scraper validation fallback for blocked SMTP: {}", normalizedEmail);
                }
            }
            
            // Override validity based on fallback verification methods
            if (hasFallbackVerification) {
                isValid = true;
            }
        }
        
        final var finalScore = scoreCalculator.calculateScore(detailScores, domainAge);
        
        final var resultBuilder = ValidationResult.builder()
                .valid(isValid)
                .score(finalScore)
                .validatorName("combined");
        
        resultBuilder.details(detailScores);
        detailScores.put("overall", finalScore);
        
        if (!isValid) {
            for (final var result : validatorResults.values()) {
                if (!result.isValid()) {
                    resultBuilder.reason(result.getReason());
                    break;
                }
            }
        } else if (isSmtpBlocked) {
            // Add a note about using alternative verification
            resultBuilder.reason("Verified using alternative methods due to SMTP blocks");
        }
        
        return resultBuilder.build();
    }

    /**
     * Validates a batch of emails in parallel, optimizing resources by grouping by domain.
     * This is much more efficient than validating each email individually.
     *
     * @param emails The list of emails to validate
     * @return Map of email to validation result
     */
    public Map<String, ValidationResult> validateBatch(final List<String> emails) {
        if (emails == null || emails.isEmpty()) {
            return Collections.emptyMap();
        }
        
        final var results = new ConcurrentHashMap<String, ValidationResult>();
        
        // Group emails by domain for efficient validation
        final var emailsByDomain = emails.stream()
            .filter(email -> email != null && !email.isBlank())
            .collect(Collectors.groupingBy(
                email -> {
                    final var parts = email.split("@", 2);
                    return parts.length == 2 ? parts[1].toLowerCase() : "";
                }
            ));
        
        // Process each domain in parallel
        final var domainFutures = new ArrayList<CompletableFuture<Void>>();
        
        for (final var entry : emailsByDomain.entrySet()) {
            final var domain = entry.getKey();
            final var domainEmails = entry.getValue();
            
            final var domainFuture = CompletableFuture.runAsync(() -> {
                // Process all emails in this domain in parallel
                final var emailFutures = new ArrayList<CompletableFuture<Void>>();
                
                for (final var email : domainEmails) {
                    final var emailFuture = CompletableFuture.runAsync(() -> {
                        try {
                            // Validate this email
                            final var result = validate(email);
                            results.put(email, result);
                        } catch (final Exception e) {
                            logger.error("Error validating email {}: {}", email, e.getMessage());
                            results.put(email, ValidationResult.invalid("error", "Validation error: " + e.getMessage()));
                        }
                    }, executor);
                    
                    emailFutures.add(emailFuture);
                }
                
                // Wait for all emails in this domain to complete
                try {
                    CompletableFuture.allOf(emailFutures.toArray(new CompletableFuture[0])).join();
                } catch (final Exception e) {
                    logger.error("Error waiting for emails in domain {}: {}", domain, e.getMessage());
                }
            }, executor);
            
            domainFutures.add(domainFuture);
        }
        
        // Wait for all domains to complete
        try {
            CompletableFuture.allOf(domainFutures.toArray(new CompletableFuture[0])).join();
        } catch (final Exception e) {
            logger.error("Error waiting for domains: {}", e.getMessage());
        }
        
        return results;
    }
    
    /**
     * Gets the actual validator objects.
     *
     * @return List of validator objects
     */
    public List<EmailValidator> getValidatorObjects() {
        return new ArrayList<>(validators);
    }
} 