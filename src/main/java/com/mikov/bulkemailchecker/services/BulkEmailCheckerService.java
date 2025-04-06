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
 * Service for handling email verification.
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
    
    private final ConcurrentHashMap<String, CachedResult> resultCache = new ConcurrentHashMap<>();
    private static final long CACHE_TTL_MS = TimeUnit.MINUTES.toMillis(30);

    @Autowired
    public BulkEmailCheckerService(final SMTPValidator smtpValidator, final SyntaxValidator syntaxValidator, 
                                  final MXRecordValidator mxRecordValidator) {
        this.smtpValidator = smtpValidator;
        this.syntaxValidator = syntaxValidator;
        this.mxRecordValidator = mxRecordValidator;
        this.executorService = Executors.newVirtualThreadPerTaskExecutor();
        startCacheCleanupTask();
    }

    @SuppressWarnings("unchecked")
    public EmailVerificationResponse verifyEmail(final String email) {
        final var normalizedEmail = email.trim().toLowerCase();
        final var builder = new EmailVerificationResponse.Builder(normalizedEmail)
                .withCreatedAt(Instant.now().toString());

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

        final var parts = normalizedEmail.split("@", 2);
        final var domain = parts[1].toLowerCase();

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

        builder.withHasMx(true);
        builder.withCountry("");

        final var smtpResult = smtpValidator.validate(normalizedEmail);
        boolean isCatchAll = false;
        String smtpServer;
        String ipAddress;
        String provider;
        
        builder.withHasMx(true);
        
        if (smtpResult.getDetails() != null) {
            if (smtpResult.getDetails().containsKey("catch-all") &&
                smtpResult.getDetails().get("catch-all") == 1.0) {
                isCatchAll = true;
            }
            
            if (smtpResult.getDetails().containsKey("smtp-server")) {
                smtpServer = getAdditionalInfoValue(smtpResult.getDetails(), "smtp-server");
                if (smtpServer != null && !smtpServer.isEmpty()) {
                    builder.withSmtpServer(smtpServer);
                }
            }
            
            if (smtpResult.getDetails().containsKey("ip-address")) {
                ipAddress = getAdditionalInfoValue(smtpResult.getDetails(), "ip-address");
                if (ipAddress != null && !ipAddress.isEmpty()) {
                    builder.withIpAddress(ipAddress);
                }
            }
            
            if (smtpResult.getDetails().containsKey("provider")) {
                provider = getAdditionalInfoValue(smtpResult.getDetails(), "provider");
                if (provider != null && !provider.isEmpty()) {
                    builder.withAdditionalInfo("Email provider: " + provider);
                }
            }
        }

        if (isCatchAll) {
            return builder.withStatus("unknown")
                    .withValid(true)
                    .withResultCode("is_catchall")
                    .withMessage("This domain appears to be a catch-all domain. While this email may be deliverable, the domain accepts mail for any address.")
                    .withHasMx(true)
                    .withCountry("")
                    .build();
        } else if (smtpResult.isValid()) {
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

    private String getAdditionalInfoValue(final Map<String, Double> details, final String key) {
        try {
            if (details.containsKey(key + "-value")) {
                final var encodedValue = details.get(key + "-value");
                return smtpValidator.getStringValue(encodedValue);
            }
            return null;
        } catch (Exception e) {
            logger.warn("Error extracting additional info for {}: {}", key, e.getMessage());
            return null;
        }
    }

    public List<EmailVerificationResponse> verifyEmails(final List<String> emails) {
        final var emailsByDomain = emails.stream()
                .collect(Collectors.groupingBy(this::extractDomain));
        
        final var futures = new ArrayList<CompletableFuture<EmailVerificationResponse>>();
        for (final var entry : emailsByDomain.entrySet()) {
            final var domainEmails = entry.getValue();

            domainEmails.forEach(email -> {
                final var future = CompletableFuture.supplyAsync(() -> verifyEmail(email), executorService);
                futures.add(future);
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
        private final long timestamp;
        
        public CachedResult(final EmailVerificationResponse response) {
            this.timestamp = System.currentTimeMillis();
        }

        public boolean isExpired(final long currentTime) {
            return currentTime - timestamp > CACHE_TTL_MS;
        }
    }
}
