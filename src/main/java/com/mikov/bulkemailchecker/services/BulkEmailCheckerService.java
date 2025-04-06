package com.mikov.bulkemailchecker.services;

import com.mikov.bulkemailchecker.model.EmailVerificationResponse;
import com.mikov.bulkemailchecker.dtos.ValidationResult;
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
 * Service for handling email verification
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
    public BulkEmailCheckerService(SMTPValidator smtpValidator, SyntaxValidator syntaxValidator, 
                                  MXRecordValidator mxRecordValidator) {
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
        final String normalizedEmail = email.trim().toLowerCase();
        
        // Create response builder
        final var builder = new EmailVerificationResponse.Builder(normalizedEmail)
                .withCreatedAt(Instant.now().toString());

        // Check if the email has a valid format
        final var formatResult = syntaxValidator.validate(normalizedEmail);
        if (!formatResult.isValid()) {
            return builder.withStatus("invalid")
                    .withValid(false)
                    .withResultCode("invalid_email")
                    .withMessage(formatResult.getReason())
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
                    .build();
        }

        // Validate SMTP
        final var smtpResult = smtpValidator.validate(normalizedEmail);
        boolean isCatchAll = false;
        String smtpServer = null;
        String ipAddress = null;
        String provider = null;
        
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
                    .withMessage("Email cannot be verified (catch-all domain)")
                    .build();
        } else if (smtpResult.isValid()) {
            // Handle valid email
            return builder.withStatus("deliverable")
                    .withValid(true)
                    .withResultCode("mailbox_exists")
                    .withMessage("Email address exists and can receive email")
                    .build();
        } else {
            // Handle invalid email
            return builder.withStatus("undeliverable")
                    .withValid(false)
                    .withResultCode("mailbox_does_not_exist")
                    .withMessage("Email address does not exist")
                    .build();
        }
    }
    
    /**
     * Extracts value from the additional info in SMTP validator details
     */
    private String getAdditionalInfoValue(Map<String, Double> details, String key) {
        try {
            // Check if we have an encoded value (key-value format)
            if (details.containsKey(key + "-value")) {
                double encodedValue = details.get(key + "-value");
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
    public List<EmailVerificationResponse> verifyEmails(List<String> emails) {
        // Group by domain for more efficient processing
        Map<String, List<String>> emailsByDomain = emails.stream()
                .collect(Collectors.groupingBy(this::extractDomain));
        
        List<CompletableFuture<EmailVerificationResponse>> futures = new ArrayList<>();
        
        // Process each domain sequentially to avoid overwhelming individual mail servers
        for (Map.Entry<String, List<String>> entry : emailsByDomain.entrySet()) {
            String domain = entry.getKey();
            List<String> domainEmails = entry.getValue();
            
            // Process emails within each domain in parallel
            domainEmails.forEach(email -> {
                CompletableFuture<EmailVerificationResponse> future = 
                    CompletableFuture.supplyAsync(() -> verifyEmail(email), executorService);
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
    
    private String extractDomain(String email) {
        int atIndex = email.lastIndexOf('@');
        if (atIndex != -1 && atIndex < email.length() - 1) {
            return email.substring(atIndex + 1).toLowerCase();
        }
        return "";
    }
    
    private boolean shouldThrottle(String domain) {
        ThrottleInfo info = domainThrottling.get(domain);
        if (info == null) {
            return false;
        }
        
        // Check if we're exceeding the rate limit
        long currentTime = System.currentTimeMillis();
        long windowStart = currentTime - TimeUnit.MINUTES.toMillis(1);
        
        // Remove requests older than 1 minute
        info.getRequestTimes().removeIf(time -> time < windowStart);
        
        // Check if we've exceeded the limit
        return info.getRequestTimes().size() >= MAX_REQUESTS_PER_MINUTE;
    }
    
    private void updateThrottlingInfo(String domain) {
        domainThrottling.compute(domain, (k, v) -> {
            if (v == null) {
                v = new ThrottleInfo();
            }
            v.addRequest(System.currentTimeMillis());
            return v;
        });
    }
    
    private EmailVerificationResponse createThrottledResponse(String email, long startTime) {
        long responseTime = System.currentTimeMillis() - startTime;
        
        return new EmailVerificationResponse.Builder(email)
                .withStatus("unknown")
                .withValid(false)
                .withResultCode("rate_limited")
                .withMessage("Too many requests for this domain. Please try again later.")
                .withResponseTime(responseTime)
                .withDisposable(false)
                .withRole(false)
                .withSubAddressing(false)
                .withFree(false)
                .withSpam(false)
                .withHasMx(false)
                .withCountry("")
                .withSmtpServer("")
                .withIpAddress("")
                .withAdditionalInfo("")
                .build();
    }
    
    private void startCacheCleanupTask() {
        Thread cleanupThread = new Thread(() -> {
            while (true) {
                try {
                    // Sleep for 5 minutes
                    Thread.sleep(TimeUnit.MINUTES.toMillis(5));
                    
                    // Clean up expired cache entries
                    resultCache.entrySet().removeIf(entry -> entry.getValue().isExpired());
                    
                    logger.debug("Cache cleanup complete. Current size: {}", resultCache.size());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (Exception e) {
                    logger.error("Error during cache cleanup", e);
                }
            }
        });
        cleanupThread.setDaemon(true);
        cleanupThread.setName("email-verification-cache-cleanup");
        cleanupThread.start();
    }
    
    /**
     * Cached result with expiration
     */
    private static class CachedResult {
        private final EmailVerificationResponse response;
        private final long timestamp;
        
        public CachedResult(EmailVerificationResponse response) {
            this.response = response;
            this.timestamp = System.currentTimeMillis();
        }
        
        public EmailVerificationResponse getResponse() {
            return response;
        }
        
        public boolean isExpired() {
            return System.currentTimeMillis() - timestamp > CACHE_TTL_MS;
        }
    }
    
    /**
     * Throttling information for a domain
     */
    private static class ThrottleInfo {
        private final List<Long> requestTimes = new ArrayList<>();
        
        public void addRequest(long timestamp) {
            requestTimes.add(timestamp);
        }
        
        public List<Long> getRequestTimes() {
            return requestTimes;
        }
    }
}
