package com.mikov.bulkemailchecker.services;

import com.mikov.bulkemailchecker.model.EmailVerificationResponse;
import com.mikov.bulkemailchecker.dtos.ValidationResult;
import com.mikov.bulkemailchecker.model.ServiceValidationResult;
import com.mikov.bulkemailchecker.validation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.concurrent.ConcurrentHashMap;
import java.time.Instant;

/**
 * Service for handling email verification.
 * This service coordinates between the validation package (using ValidationResult)
 * and the service layer (using ServiceValidationResult).
 * 
 * @author zahari.mikov
 */
@Service
public class BulkEmailCheckerService {
    private static final Logger logger = LoggerFactory.getLogger(BulkEmailCheckerService.class);

    private final SMTPValidator smtpValidator;
    private final SyntaxValidator syntaxValidator; 
    private final MXRecordValidator mxRecordValidator;
    private final ExecutorService executorService;
    
    // Cache for recently verified emails to reduce load
    private final ConcurrentHashMap<String, CachedResult> resultCache = new ConcurrentHashMap<>();
    private static final long CACHE_TTL_MS = TimeUnit.MINUTES.toMillis(30); // Cache results for 30 minutes
    
    // Domain-based throttling to prevent abuse
    private final ConcurrentHashMap<String, ThrottleInfo> domainThrottling = new ConcurrentHashMap<>();
    private static final int MAX_REQUESTS_PER_MINUTE = 60;
    
    @Autowired
    public BulkEmailCheckerService(final SMTPValidator smtpValidator, final SyntaxValidator syntaxValidator, 
                                  final MXRecordValidator mxRecordValidator) {
        this.smtpValidator = smtpValidator;
        this.syntaxValidator = syntaxValidator;
        this.mxRecordValidator = mxRecordValidator;
        // Use virtual threads for optimal I/O concurrency with minimal resource usage
        this.executorService = Executors.newVirtualThreadPerTaskExecutor();
        
        // Start a cleanup task for the cache
        startCacheCleanupTask();
    }
    
    /**
     * Verify a single email address
     * @param email Email to verify
     * @return Email verification response
     */
    @SuppressWarnings("unchecked")
    public EmailVerificationResponse verifyEmail(final String email) {
        // Normalize email
        final var normalizedEmail = email.trim().toLowerCase();
        
        // Create response builder
        final var builder = new EmailVerificationResponse.Builder(normalizedEmail)
                .withCreatedAt(Instant.now().toString());

        // Check if the email has a valid format
        final var formatResult = syntaxValidator.validate(normalizedEmail);
        if (!formatResult.isValid()) {
            return builder.withStatus("invalid")
                    .withValid(false)
                    .withResultCode("invalid_format")
                    .withMessage(formatResult.getReason())
                    .withHasMx(false)
                    .withCountry("")
                    .build();
        }

        // Get domain from email
        final var parts = normalizedEmail.split("@", 2);
        final var domain = parts[1].toLowerCase();

        // Validate MX record
        final var mxRecordResult = mxRecordValidator.validate(normalizedEmail);
        if (!mxRecordResult.isValid()) {
            return builder.withStatus("invalid")
                    .withValid(false)
                    .withResultCode("mx_record_not_found")
                    .withMessage("No MX records found for domain " + domain)
                    .withHasMx(false)
                    .withCountry("")
                    .build();
        }

        // MX records exist, set hasMx to true for all subsequent responses
        builder.withHasMx(true);
        builder.withCountry("");

        // Validate SMTP
        final var smtpResult = smtpValidator.validate(normalizedEmail);
        boolean isCatchAll = false;
        String smtpServer = null;
        String ipAddress = null;
        String provider = null;
        
        // Always set hasMx based on previous MX validation
        builder.withHasMx(true);
        
        // Extract additional information from SMTP result details
        if (smtpResult.getDetails() != null) {
            // Check if domain is catch-all
            if (smtpResult.getDetails().containsKey("catch-all") && 
                smtpResult.getDetails().get("catch-all") == 1.0) {
                isCatchAll = true;
            }
            
            // Extract SMTP server info if available
            if (smtpResult.getDetails().containsKey("smtp-server")) {
                smtpServer = getAdditionalInfoValue(smtpResult.getDetails(), "smtp-server");
                if (smtpServer != null && !smtpServer.isEmpty()) {
                    builder.withSmtpServer(smtpServer);
                }
            }
            
            // Extract IP address if available
            if (smtpResult.getDetails().containsKey("ip-address")) {
                ipAddress = getAdditionalInfoValue(smtpResult.getDetails(), "ip-address");
                if (ipAddress != null && !ipAddress.isEmpty()) {
                    builder.withIpAddress(ipAddress);
                }
            }
            
            // Extract provider information if available
            if (smtpResult.getDetails().containsKey("provider")) {
                provider = getAdditionalInfoValue(smtpResult.getDetails(), "provider");
                // Add provider as additional info to response
                if (provider != null && !provider.isEmpty()) {
                    builder.withAdditionalInfo("Email provider: " + provider);
                }
            }
        }

        // Process results
        if (isCatchAll) {
            // Handle catch-all domains specially
            return builder.withStatus("unknown")
                    .withValid(true)
                    .withResultCode("is_catchall")
                    .withMessage("This domain appears to be a catch-all domain. While this email may be deliverable, the domain accepts mail for any address.")
                    .withHasMx(true)
                    .withCountry("")
                    .build();
        } else if (smtpResult.isValid()) {
            // Handle valid email
            return builder.withStatus("deliverable")
                    .withValid(true)
                    .withResultCode("success")
                    .withMessage("Email address exists and can receive email")
                    .withHasMx(true)
                    .withCountry("")
                    .build();
        } else {
            // Handle invalid email
            return builder.withStatus("undeliverable")
                    .withValid(false)
                    .withResultCode("failure")
                    .withMessage("Email address does not exist")
                    .withHasMx(true)
                    .withCountry("")
                    .build();
        }
    }
    
    /**
     * Extracts value from the additional info in SMTP validator details
     */
    private String getAdditionalInfoValue(final Map<String, Double> details, final String key) {
        try {
            // Check if we have an encoded value (key-value format)
            if (details.containsKey(key + "-value")) {
                final var encodedValue = details.get(key + "-value");
                // Use the SMTPValidator to decode the value
                return smtpValidator.getStringValue(encodedValue);
            }
            return null;
        } catch (Exception e) {
            logger.warn("Error extracting additional info for {}: {}", key, e.getMessage());
            return null;
        }
    }
    
    /**
     * Verify multiple email addresses in parallel
     * @param emails List of emails to verify
     * @return List of email verification responses
     */
    public List<EmailVerificationResponse> verifyEmails(final List<String> emails) {
        // Group by domain for more efficient processing
        final var emailsByDomain = emails.stream()
                .collect(Collectors.groupingBy(this::extractDomain));
        
        final var futures = new ArrayList<CompletableFuture<EmailVerificationResponse>>();
        
        // Process each domain sequentially to avoid overwhelming individual mail servers
        for (final var entry : emailsByDomain.entrySet()) {
            final var domain = entry.getKey();
            final var domainEmails = entry.getValue();
            
            // Process emails within each domain in parallel
            domainEmails.forEach(email -> {
                final var future = CompletableFuture.supplyAsync(() -> verifyEmail(email), executorService);
                futures.add(future);
                
                // Small delay between requests to the same domain
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }
        
        return futures.stream()
                .map(CompletableFuture::join)
                .collect(Collectors.toList());
    }
    
    private String extractDomain(final String email) {
        final var atIndex = email.lastIndexOf('@');
        if (atIndex != -1 && atIndex < email.length() - 1) {
            return email.substring(atIndex + 1).toLowerCase();
        }
        return "";
    }
    
    private boolean shouldThrottle(final String domain) {
        final var info = domainThrottling.get(domain);
        if (info == null) {
            return false;
        }
        
        // Check if we're exceeding the rate limit
        final var currentTime = System.currentTimeMillis();
        final var windowStart = currentTime - TimeUnit.MINUTES.toMillis(1);
        
        // Remove requests older than 1 minute
        info.getRequestTimes().removeIf(time -> time < windowStart);
        
        return info.getRequestTimes().size() >= MAX_REQUESTS_PER_MINUTE;
    }
    
    private void updateThrottlingInfo(final String domain) {
        final var info = domainThrottling.computeIfAbsent(domain, k -> new ThrottleInfo());
        info.addRequest(System.currentTimeMillis());
    }
    
    private EmailVerificationResponse createThrottledResponse() {
        return new EmailVerificationResponse.Builder("")
                .withStatus("unknown")
                .withValid(false)
                .withHasMx(false)
                .withCountry("")
                .withMessage("Too many requests. Please reduce rate of requests.")
                .withResultCode("throttle_limit_reached")
                .build();
    }
    
    private void startCacheCleanupTask() {
        final var cleanupThread = new Thread(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    Thread.sleep(TimeUnit.MINUTES.toMillis(5));
                    final var currentTime = System.currentTimeMillis();
                    resultCache.entrySet().removeIf(entry -> entry.getValue().isExpired(currentTime));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        });
        cleanupThread.setDaemon(true);
        cleanupThread.start();
    }
    
    private static class CachedResult {
        private final EmailVerificationResponse response;
        private final long timestamp;
        
        public CachedResult(final EmailVerificationResponse response) {
            this.response = response;
            this.timestamp = System.currentTimeMillis();
        }
        
        public EmailVerificationResponse getResponse() {
            return response;
        }
        
        public boolean isExpired(final long currentTime) {
            return currentTime - timestamp > CACHE_TTL_MS;
        }
    }
    
    private static class ThrottleInfo {
        private final List<Long> requestTimes = new ArrayList<>();
        
        public void addRequest(final long timestamp) {
            requestTimes.add(timestamp);
        }
        
        public List<Long> getRequestTimes() {
            return requestTimes;
        }
    }
}
