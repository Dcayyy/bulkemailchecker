package com.mikov.bulkemailchecker.services;

import com.mikov.bulkemailchecker.dtos.ValidationResult;
import com.mikov.bulkemailchecker.dtos.SmtpServerInfo;
import com.mikov.bulkemailchecker.dtos.SmtpValidationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.*;
import java.util.regex.Pattern;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.Executors;
import java.util.Comparator;
import java.util.Map;
import java.util.ArrayList;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.net.SocketTimeoutException;
import java.net.ConnectException;
import java.net.SocketException;

/**
 * Validator that checks SMTP servers for email validity.
 * Performs SMTP connection tests and optimized catch-all detection.
 * Uses consensus verification for improved reliability.
 *
 * @author zahari.mikov
 */
@Component
public class SMTPValidator implements EmailValidator {
    private static final Logger logger = LoggerFactory.getLogger(SMTPValidator.class);
    
    // Basic settings - all waiting times set to zero
    private static final boolean ENABLE_FAST_MODE = false;
    private static final int SOCKET_TIMEOUT_MS = 5000;
    private static final int CONNECTION_TIMEOUT_MS = 5000;
    private static final int VERIFICATION_ATTEMPTS = 2;
    private static final int SMTP_PORT = 25;
    
    // Response parsing
    private static final String[] INVALID_RESPONSE_SUBSTRINGS = {
        "does not exist", "no such user", "user unknown", "invalid recipient", 
        "recipient rejected", "address rejected", "not found", "mailbox unavailable",
        "no mailbox", "not a valid mailbox", "not our customer", "address unknown",
        "no such recipient", "bad address", "delivery failed", "recipient address rejected"
    };
    
    // Basic cache
    private final Map<String, CachedValidationResult> resultCache = new HashMap<>();
    
    private static final Random random = new Random();
    
    @Override
    public ValidationResult validate(final String email) {
        logger.info("Starting SMTP validation for email: {}", email);
        
        if (email == null || email.isBlank()) {
            logger.info("Email is null or empty: {}", email);
            return ValidationResult.invalid(getName(), "Email is null or empty");
        }
        
        final var parts = email.split("@", 2);
        if (parts.length != 2) {
            logger.info("Invalid email format: {}", email);
            return ValidationResult.invalid(getName(), "Invalid email format");
        }
        
        final var localPart = parts[0];
        final var domain = parts[1].toLowerCase();
        
        final var cacheKey = (localPart + "@" + domain).toLowerCase();
        final var cachedResult = resultCache.get(cacheKey);
        if (cachedResult != null && !cachedResult.isExpired()) {
            logger.info("Using cached validation result for email: {}", email);
            return cachedResult.getResult();
        }
        
        try {
            final var mxHosts = getMxRecords(domain);
            if (mxHosts.length == 0) {
                logger.info("No MX records found for domain: {}", domain);
                final var result = ValidationResult.invalid(getName(), "No MX records found");
                cacheResult(cacheKey, result);
                return result;
            }
            
            logger.debug("Found {} MX records for domain {}: {}", mxHosts.length, domain, String.join(", ", mxHosts));
            
            final var provider = identifyProvider(mxHosts);
            final var mxHost = mxHosts[0];
            logger.debug("Checking primary MX host {} for domain {}", mxHost, domain);
            final var serverInfo = new SmtpServerInfo(mxHost, getIpAddress(mxHost), provider);
            
            boolean isCatchAll = false;
            
            // Skip catch-all detection in fast mode
            if (!ENABLE_FAST_MODE) {
                isCatchAll = detectCatchAll(email, domain, mxHost);
                
                if (isCatchAll) {
                    logger.info("Domain {} detected as catch-all using MX host {}", domain, mxHost);
                    final var details = createDetailsMap(true, "Catch-all domain",
                            serverInfo.getHostname(), serverInfo.getIpAddress(), serverInfo.getProvider());
                    details.put("event", "is_catchall");
                    details.put("status", "unknown");
                    final var result = ValidationResult.valid(getName(), details);
                    cacheResult(cacheKey, result);
                    return result;
                }
            }
            
            logger.debug("Performing SMTP verification for {} using MX host {}", email, mxHost);
            final var results = performDirectVerification(localPart, domain, mxHost);
            
            if (results.isEmpty()) {
                logger.info("No conclusive result for email {} after checking MX server", email);
                final var details = createDetailsMap(false, "Inconclusive SMTP check",
                        serverInfo.getHostname(), serverInfo.getIpAddress(), serverInfo.getProvider());
                details.put("event", "inconclusive");
                details.put("status", "unknown");
                
                final var result = ValidationResult.valid(getName(), details);
                cacheResult(cacheKey, result);
                return result;
            }
            
            if (!results.isEmpty()) {
                final var deliverableCount = results.stream()
                    .filter(SmtpValidationResult::isDeliverable)
                    .count();
                
                final var confidence = (double) deliverableCount / results.size();
                logger.debug("SMTP verification for {} using MX host {}: {} of {} attempts deliverable (confidence: {})", 
                        email, mxHost, deliverableCount, results.size(), String.format("%.2f", confidence));
                
                final var isDeliverable = confidence >= 0.5;
                
                if (isDeliverable) {
                    final var details = createDetailsMap(false, null,
                            serverInfo.getHostname(), serverInfo.getIpAddress(), serverInfo.getProvider());
                    details.put("confidence", confidence);
                    details.put("event", "mailbox_exists");
                    
                    logger.info("Email validation result for {}: DELIVERABLE (confidence: {}, MX: {})", 
                            email, String.format("%.2f", confidence), mxHost);
                    
                    final var result = ValidationResult.valid(getName(), details);
                    cacheResult(cacheKey, result);
                    return result;
                } else {
                    final var details = createDetailsMap(false, "Email not deliverable",
                            serverInfo.getHostname(), serverInfo.getIpAddress(), serverInfo.getProvider());
                    details.put("confidence", 1.0 - confidence);
                    details.put("event", "mailbox_does_not_exist");
                    
                    logger.info("Email validation result for {}: UNDELIVERABLE (confidence: {}, MX: {})", 
                            email, String.format("%.2f", 1.0 - confidence), mxHost);
                    
                    final var result = ValidationResult.invalid(getName(), "Email not deliverable", details);
                    cacheResult(cacheKey, result);
                    return result;
                }
            }
            
            logger.info("No conclusive result for email {} after checking MX server", email);
            final var details = createDetailsMap(false, "Inconclusive SMTP check",
                    mxHost, getIpAddress(mxHost), identifyProvider(new String[]{mxHost}));
            details.put("event", "inconclusive");
            details.put("status", "unknown");
            
            final var result = ValidationResult.valid(getName(), details);
            cacheResult(cacheKey, result);
            return result;
            
        } catch (final Exception e) {
            logger.warn("SMTP validation failed for email {}: {}", email, e.getMessage());
            final var details = createDetailsMap(false, "SMTP check error: " + e.getMessage(), "", "", "");
            details.put("event", "inconclusive");
            details.put("status", "unknown");
            return ValidationResult.valid(getName(), details);
        }
    }

    private boolean detectCatchAll(final String originalEmail, final String domain, final String mxHost) {
        try {
            logger.debug("Testing if domain {} is catch-all using server {}", domain, mxHost);
            
            final var parts = originalEmail.split("@", 2);
            final var invalidLocalPart = generateInvalidLocalPart(parts[0]);
            
            logger.debug("Catch-all test for domain {} using original '{}' and probe '{}'", 
                    domain, parts[0], invalidLocalPart);
            
            final var result = performOneSmtpVerification(invalidLocalPart, domain, mxHost);
            
            logger.debug("Catch-all test result for probe {}: deliverable={}, response code={}, response={}", 
                    invalidLocalPart, result.isDeliverable(), result.getResponseCode(), result.getFullResponse());
            
            if (result.isDeliverable()) {
                logger.debug("Domain {} IS catch-all: accepted invalid email {}", domain, invalidLocalPart + "@" + domain);
                return true;
            }
            
            if (!result.isDeliverable() && !result.isTempError() && result.getResponseCode() >= 500) {
                logger.debug("Domain {} is NOT catch-all: rejected invalid email {}", domain, invalidLocalPart + "@" + domain);
                return false;
            }
            
            logger.debug("Catch-all test for domain {} was inconclusive, assuming not catch-all", domain);
            return false;

        } catch (final Exception e) {
            logger.warn("Error testing if domain {} is catch-all: {}", domain, e.getMessage());
            return false;
        }
    }

    private String generateInvalidLocalPart(final String originalLocalPart) {
        final var randomSuffix = getRandomString(8);
        return originalLocalPart + "." + randomSuffix;
    }

    private String getRandomString(final int length) {
        final var allowedChars = "abcdefghijklmnopqrstuvwxyz";
        final var sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(allowedChars.charAt(random.nextInt(allowedChars.length())));
        }
        return sb.toString();
    }

    @Override
    public String getName() {
        return "smtp";
    }

    private List<SmtpValidationResult> performDirectVerification(
            final String localPart, final String domain, final String mxHost) {
        
        final var results = new ArrayList<SmtpValidationResult>();
        logger.debug("Starting SMTP verification for {}@{} on MX host {}", localPart, domain, mxHost);
        
        for (int i = 0; i < VERIFICATION_ATTEMPTS; i++) {
            logger.debug("SMTP verification attempt #{} for {}@{} on MX host {}", i+1, localPart, domain, mxHost);
            try {
                final var result = performOneSmtpVerification(localPart, domain, mxHost);
                results.add(result);
            } catch (Exception e) {
                logger.debug("SMTP verification attempt #{} for {}@{} resulted in error: {}", 
                    i+1, localPart, domain, e.getMessage());
            }
        }
        
        logger.debug("Completed SMTP verification for {}@{}: {} results collected", 
                localPart, domain, results.size());
        return results;
    }

    private SmtpValidationResult performOneSmtpVerification(final String localPart, final String domain, final String mxHost) {
        final String email = localPart + "@" + domain;
        
        logger.debug("Starting SMTP verification for {} on MX host {}", email, mxHost);
        
        try {
            final var socket = new Socket();
            socket.connect(new InetSocketAddress(mxHost, SMTP_PORT), CONNECTION_TIMEOUT_MS);
            socket.setSoTimeout(SOCKET_TIMEOUT_MS);
            
            final var in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            final var out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(socket.getOutputStream())), true);
            
            final var response = in.readLine(); // Read greeting
            
            if (getResponseCode(response) != 220) {
                logger.debug("Unexpected greeting from {}: {}", mxHost, response);
                return new SmtpValidationResult(false, false, getResponseCode(response), true);
            }
            
            // HELO command
            final var heloCmd = "HELO fake.com\r\n";
            out.print(heloCmd);
            out.flush();
            final var heloResponse = in.readLine();
            
            if (getResponseCode(heloResponse) != 250) {
                logger.debug("HELO rejected by {}: {}", mxHost, heloResponse);
                return new SmtpValidationResult(false, false, getResponseCode(heloResponse), true);
            }
            
            // MAIL FROM command
            final var mailFromCmd = "MAIL FROM:<verify@fake.com>\r\n";
            out.print(mailFromCmd);
            out.flush();
            final var mailFromResponse = in.readLine();
            
            if (getResponseCode(mailFromResponse) != 250) {
                logger.debug("MAIL FROM rejected by {}: {}", mxHost, mailFromResponse);
                return new SmtpValidationResult(false, false, getResponseCode(mailFromResponse), true);
            }
            
            // RCPT TO command
            final var rcptToCmd = "RCPT TO:<" + localPart + "@" + domain + ">\r\n";
            out.print(rcptToCmd);
            out.flush();
            final var rcptToResponse = in.readLine();
            
            int responseCode = getResponseCode(rcptToResponse);
            boolean isTempError = false;
            
            // Check if this is a 4xx temporary error
            if (responseCode >= 400 && responseCode < 500) {
                isTempError = true;
            }
            
            // Send QUIT command to be nice to the server
            out.print("QUIT\r\n");
            out.flush();
            
            // Read the QUIT response if possible
            try {
                in.readLine();
            } catch (Exception e) {
                // Ignore errors reading QUIT response
            }
            
            // Close the socket
            try {
                socket.close();
            } catch (Exception e) {
                // Ignore close errors
            }
            
            final var fullResponse = rcptToResponse != null ? rcptToResponse : "";
            
            // Determine deliverability
            boolean isDeliverable = false;
            boolean isCatchAll = false;
            
            // For 2xx responses, don't automatically assume deliverable
            if (responseCode >= 200 && responseCode < 300) {
                // Good sign, but don't immediately mark as deliverable
                isDeliverable = !fullResponse.toLowerCase().contains("catch-all");
                
                // Check for signs of catch-all domains
                if (fullResponse.toLowerCase().contains("catch-all") || 
                    fullResponse.toLowerCase().contains("accept all") || 
                    fullResponse.contains("accepting all")) {
                    isCatchAll = true;
                    isDeliverable = false; // More conservative: mark catch-alls as non-deliverable
                }
            }
            // For 4xx errors, be more strict
            else if (responseCode >= 400 && responseCode < 500) {
                isDeliverable = false;
                isTempError = true;
                
                // Check more strictly for invalid user messages
                for (String invalidPattern : INVALID_RESPONSE_SUBSTRINGS) {
                    if (fullResponse.toLowerCase().contains(invalidPattern.toLowerCase())) {
                        isDeliverable = false;
                        isTempError = false; // Not temporary if user doesn't exist
                        break;
                    }
                }
            }
            // For 5xx errors, always undeliverable
            else if (responseCode >= 500) {
                isDeliverable = false;
                isTempError = responseCode != 550; // 550 is usually permanent
            }
            
            // Create a more detailed result
            return new SmtpValidationResult(isDeliverable, isCatchAll, responseCode, isTempError, fullResponse, mxHost);
            
        } catch (final Exception e) {
            logger.debug("Error during SMTP check for {}@{} at {}: {}", localPart, domain, mxHost, e.getMessage());
            return new SmtpValidationResult(false, false, 0, true, e.getMessage(), mxHost);
        }
    }

    private String[] getMxRecords(final String domain) throws Exception {
        final var ctx = new javax.naming.directory.InitialDirContext();
        final var attrs = ctx.getAttributes("dns:/" + domain, new String[] {"MX"});
        final var attr = attrs.get("MX");
        
        if (attr == null || attr.size() == 0) {
            return new String[0];
        }
        
        final var mxHosts = new String[attr.size()];
        for (var i = 0; i < attr.size(); i++) {
            final var mxRecord = (String) attr.get(i);
            mxHosts[i] = mxRecord.split("\\s+")[1];
        }
        
        return mxHosts;
    }
    
    private String identifyProvider(final String[] mxHosts) {
        if (mxHosts == null || mxHosts.length == 0) {
            return "Unknown";
        }
        
        final var primaryMx = mxHosts[0].toLowerCase();

        // Create a map of patterns to provider names
        HashMap<Pattern, String> providerPatterns = new HashMap<>();
        providerPatterns.put(Pattern.compile(".*\\.google\\.com", Pattern.CASE_INSENSITIVE), "Google");
        providerPatterns.put(Pattern.compile(".*\\.outlook\\.com", Pattern.CASE_INSENSITIVE), "Microsoft");
        providerPatterns.put(Pattern.compile(".*\\.hotmail\\.com", Pattern.CASE_INSENSITIVE), "Microsoft");
        providerPatterns.put(Pattern.compile(".*\\.live\\.com", Pattern.CASE_INSENSITIVE), "Microsoft");
        providerPatterns.put(Pattern.compile(".*\\.office365\\.com", Pattern.CASE_INSENSITIVE), "Microsoft");
        providerPatterns.put(Pattern.compile(".*\\.yahoo\\.com", Pattern.CASE_INSENSITIVE), "Yahoo");
        providerPatterns.put(Pattern.compile(".*\\.yahoodns\\.net", Pattern.CASE_INSENSITIVE), "Yahoo");
        providerPatterns.put(Pattern.compile(".*\\.aol\\.com", Pattern.CASE_INSENSITIVE), "AOL");
        providerPatterns.put(Pattern.compile(".*\\.zoho\\.com", Pattern.CASE_INSENSITIVE), "Zoho");
        providerPatterns.put(Pattern.compile(".*\\.protonmail\\.ch", Pattern.CASE_INSENSITIVE), "ProtonMail");
        providerPatterns.put(Pattern.compile(".*\\.gmx\\.", Pattern.CASE_INSENSITIVE), "GMX");
        providerPatterns.put(Pattern.compile(".*\\.yandex\\.", Pattern.CASE_INSENSITIVE), "Yandex");

        for (final var entry : providerPatterns.entrySet()) {
            if (entry.getKey().matcher(primaryMx).matches()) {
                return entry.getValue();
            }
        }
        
        String provider = "Self-hosted";
        if (primaryMx.contains(".")) {
            final var domain = primaryMx.substring(primaryMx.lastIndexOf('.') + 1);
            if (!domain.isEmpty()) {
                provider = domain.substring(0, 1).toUpperCase() + domain.substring(1);
            }
        }
        
        return provider;
    }

    private String getIpAddress(final String hostname) {
        try {
            final var address = InetAddress.getByName(hostname);
            return address.getHostAddress();
        } catch (final Exception e) {
            return "";
        }
    }
    
    private int getResponseCode(final String response) {
        if (response == null || response.length() < 3) {
            return 0;
        }
        try {
            return Integer.parseInt(response.substring(0, 3));
        } catch (final NumberFormatException e) {
            return 0;
        }
    }
    
    private HashMap<String, Object> createDetailsMap(final boolean isCatchAll, final String reason, 
                                                     final String smtpServer, final String ipAddress, 
                                                     final String provider) {
        final var details = new HashMap<String, Object>();
        details.put("smtp-validated", 1.0);
        details.put("catch-all", isCatchAll ? 1.0 : 0.0);
        details.put("has-mx", 1.0);
        
        if (reason != null) {
            details.put("reason", reason);
        }
        
        if (smtpServer != null && !smtpServer.isEmpty()) {
            details.put("smtp-server", smtpServer);
        }
        if (ipAddress != null && !ipAddress.isEmpty()) {
            details.put("ip-address", ipAddress);
        }
        if (provider != null && !provider.isEmpty()) {
            details.put("provider", provider);
        }
        
        return details;
    }
    
    private void cacheResult(final String cacheKey, final ValidationResult result) {
        resultCache.put(cacheKey, new CachedValidationResult(result));
    }
    
    private static class CachedValidationResult {
        private final ValidationResult result;
        private final long timestamp;
        
        public CachedValidationResult(final ValidationResult result) {
            this.result = result;
            this.timestamp = System.currentTimeMillis();
        }
        
        public ValidationResult getResult() {
            return result;
        }
        
        public long getTimestamp() {
            return timestamp;
        }
        
        public boolean isExpired() {
            return false; // Never expires
        }
    }
} 