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
import java.util.concurrent.ExecutorService;
import jakarta.annotation.PreDestroy;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;

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
    private static final boolean ENABLE_AGGRESSIVE_VERIFICATION = true;
    private static final int SOCKET_TIMEOUT_MS = 5000;
    private static final int CONNECTION_TIMEOUT_MS = 5000;
    private static final int VERIFICATION_ATTEMPTS = 2;
    private static final int SMTP_PORT = 25;
    private static final int GREYLISTING_RETRY_DELAY_MS = 3000; // 3 seconds between retries
    private static final int GREYLISTING_MAX_RETRIES = 2; // Try up to 3 times total (initial + 2 retries)
    private static final int MAX_CONNECTIONS_PER_DOMAIN = 3; // Limit connections to a domain
    
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
    
    // Add at the top with other constants
    private static final int DNS_THREAD_POOL_SIZE = 4;
    private static final ExecutorService dnsExecutor = Executors.newFixedThreadPool(DNS_THREAD_POOL_SIZE);
    private static final int SMTP_THREAD_POOL_SIZE = 10;
    private static final ExecutorService smtpExecutor = Executors.newFixedThreadPool(SMTP_THREAD_POOL_SIZE);
    
    @Override
    public ValidationResult validate(final String email) {
        logger.info("Starting SMTP validation for email: {}", email);
        long totalStartTime = System.currentTimeMillis();
        
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
            // Get all MX records with their weights
            long mxStartTime = System.currentTimeMillis();
            final var mxRecordsWithWeights = getMxRecordsWithWeights(domain);
            logger.info("MX records lookup for {} took {}ms", domain, System.currentTimeMillis() - mxStartTime);
            
            if (mxRecordsWithWeights.isEmpty()) {
                logger.info("No MX records found for domain: {}", domain);
                final var result = ValidationResult.invalid(getName(), "No MX records found");
                cacheResult(cacheKey, result);
                return result;
            }
            
            logger.debug("Found {} MX records for domain {}", mxRecordsWithWeights.size(), domain);
            
            // Check DNS records for domain health
            long dnsStartTime = System.currentTimeMillis();
            Map<String, Object> dnsDetails = checkDomainDnsRecords(domain);
            logger.info("DNS checks for {} took {}ms", domain, System.currentTimeMillis() - dnsStartTime);
            boolean hasDnsIssues = Boolean.TRUE.equals(dnsDetails.get("has_dns_issues"));
            
            // Sort MX records by priority (lowest value first)
            mxRecordsWithWeights.sort((a, b) -> Integer.compare(a.priority, b.priority));
            
            // Create a list of just the hostnames
            final var mxHosts = mxRecordsWithWeights.stream()
                .map(record -> record.hostname)
                .toArray(String[]::new);
            
            final var provider = identifyProvider(mxHosts);
            
            // Primary MX (lowest priority value)
            final var primaryMxRecord = mxRecordsWithWeights.get(0);
            final var primaryMxHost = primaryMxRecord.hostname;
            
            logger.debug("Checking primary MX host {} (priority {}) for domain {}", 
                primaryMxHost, primaryMxRecord.priority, domain);
                
            // Get more detailed server info
            final var serverInfo = new SmtpServerInfo(primaryMxHost, getIpAddress(primaryMxHost), provider);
            
            // Test for catch-all domain status
            boolean isCatchAll = false;
            
            // Skip catch-all detection in fast mode
            if (!ENABLE_FAST_MODE) {
                // Try all MX servers for catch-all detection, stopping at first positive
                for (int i = 0; i < mxRecordsWithWeights.size(); i++) {
                    MxRecord mxRecord = mxRecordsWithWeights.get(i);
                    logger.debug("Testing MX server {} (priority {}) for catch-all detection", 
                        mxRecord.hostname, mxRecord.priority);
                    
                    boolean currentMxIsCatchAll = detectCatchAll(email, domain, mxRecord.hostname);
                    
                    // If we found a catch-all, no need to check more servers
                    if (currentMxIsCatchAll) {
                        isCatchAll = true;
                        break;
                    }
                    
                    // Only check up to 3 MX servers for catch-all to avoid excessive testing
                    if (i >= 2) break;
                }
                
                if (isCatchAll) {
                    logger.info("Domain {} detected as catch-all", domain);
                    
                    // For catch-all domains, include DNS health information
                    final var details = createDetailsMap(true, "Catch-all domain",
                            serverInfo.getHostname(), serverInfo.getIpAddress(), serverInfo.getProvider());
                    details.put("event", "is_catchall");
                    details.put("status", "unknown");
                    details.put("mx_count", mxRecordsWithWeights.size());
                    details.put("primary_mx", primaryMxHost);
                    
                    // Add DNS check details
                    details.putAll(dnsDetails);
                    
                    final var result = ValidationResult.valid(getName(), details);
                    cacheResult(cacheKey, result);
                    return result;
                }
            }
            
            logger.debug("Performing SMTP verification for {} using MX host {}", email, primaryMxHost);
            
            // Try greylisting test if aggressive verification is enabled
            if (ENABLE_AGGRESSIVE_VERIFICATION) {
                SmtpValidationResult greylistResult = performGreylistTest(localPart, domain, primaryMxHost);
                
                // If greylisting test gave us a definitive result, use it
                if (greylistResult != null && !greylistResult.isTempError()) {
                    final var details = createDetailsMap(greylistResult.isCatchAll(), 
                        greylistResult.isDeliverable() ? null : "Email not deliverable",
                        serverInfo.getHostname(), serverInfo.getIpAddress(), serverInfo.getProvider());
                    
                    details.put("event", greylistResult.isDeliverable() ? "mailbox_exists" : "mailbox_does_not_exist");
                    details.put("response_code", greylistResult.getResponseCode());
                    details.put("full_response", greylistResult.getFullResponse());
                    details.put("mx_count", mxRecordsWithWeights.size());
                    details.putAll(dnsDetails);
                    
                    logger.info("Greylisting test for {}: {}", email, 
                        greylistResult.isDeliverable() ? "DELIVERABLE" : "UNDELIVERABLE");
                    
                    final var result = greylistResult.isDeliverable() ? 
                        ValidationResult.valid(getName(), details) :
                        ValidationResult.invalid(getName(), "Email not deliverable", details);
                        
                    cacheResult(cacheKey, result);
                    return result;
                }
            }
            
            // Standard verification if greylisting didn't give conclusive results
            List<SmtpValidationResult> allResults = new ArrayList<>();
            
            // Try each MX server in priority order until we get a conclusive result
            for (int i = 0; i < mxRecordsWithWeights.size(); i++) {
                MxRecord mxRecord = mxRecordsWithWeights.get(i);
                String mxHost = mxRecord.hostname;
                
                logger.debug("Performing SMTP verification for {} using MX host {} (priority {})", 
                    email, mxHost, mxRecord.priority);
                
                List<SmtpValidationResult> currentMxResults = performDirectVerification(localPart, domain, mxHost);
                allResults.addAll(currentMxResults);
                
                // Check if we have a conclusive result (deliverable)
                boolean hasDeliverableResult = currentMxResults.stream().anyMatch(SmtpValidationResult::isDeliverable);
                
                // If we found a deliverable result, or we've checked at least 3 servers, stop checking
                if (hasDeliverableResult || i >= 2) {
                    logger.debug("Found conclusive result after checking {} MX servers", i + 1);
                    break;
                }
                
                // Apply additional throttling between different MX servers
                try {
                    Thread.sleep(300); // Additional delay between checking different MX servers
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            
            // Analysis of results continues with our comprehensive results list
            final var results = allResults;
            
            if (results.isEmpty()) {
                logger.info("No conclusive result for email {} after checking MX servers", email);
                final var details = createDetailsMap(false, "Inconclusive SMTP check",
                        serverInfo.getHostname(), serverInfo.getIpAddress(), serverInfo.getProvider());
                details.put("event", "inconclusive");
                details.put("status", "unknown");
                details.put("mx_count", mxRecordsWithWeights.size());
                
                final var result = ValidationResult.valid(getName(), details);
                cacheResult(cacheKey, result);
                return result;
            }
            
            if (!results.isEmpty()) {
                final var deliverableCount = results.stream()
                    .filter(SmtpValidationResult::isDeliverable)
                    .count();
                
                final var confidence = (double) deliverableCount / results.size();
                logger.debug("SMTP verification for {}: {} of {} attempts deliverable (confidence: {})", 
                        email, deliverableCount, results.size(), String.format("%.2f", confidence));
                
                final var isDeliverable = confidence >= 0.5;
                
                // Check if any results indicated catch-all
                final var catchAllResults = results.stream()
                    .filter(SmtpValidationResult::isCatchAll)
                    .count();
                    
                final var catchAllConfidence = (double) catchAllResults / results.size();
                
                // If we have catch-all indicators from the response itself
                if (catchAllConfidence > 0) {
                    logger.info("Email validation result for {}: CATCH-ALL (confidence: {}, MX: {})", 
                            email, String.format("%.2f", catchAllConfidence), primaryMxHost);
                            
                    final var details = createDetailsMap(true, "Catch-all domain",
                            serverInfo.getHostname(), serverInfo.getIpAddress(), serverInfo.getProvider());
                    details.put("confidence", catchAllConfidence);
                    details.put("event", "is_catchall");
                    details.put("status", "catch-all");
                    details.put("mx_count", mxRecordsWithWeights.size());
                    
                    final var result = ValidationResult.catchAll(getName(), "Catch-all domain", details);
                    cacheResult(cacheKey, result);
                    return result;
                }
                
                if (isDeliverable) {
                    final var details = createDetailsMap(false, null,
                            serverInfo.getHostname(), serverInfo.getIpAddress(), serverInfo.getProvider());
                    details.put("confidence", confidence);
                    details.put("event", "mailbox_exists");
                    details.put("mx_count", mxRecordsWithWeights.size());
                    
                    logger.info("Email validation result for {}: DELIVERABLE (confidence: {}, MX: {})", 
                            email, String.format("%.2f", confidence), primaryMxHost);
                    
                    final var result = ValidationResult.valid(getName(), details);
                    cacheResult(cacheKey, result);
                    return result;
                } else {
                    final var details = createDetailsMap(false, "Email not deliverable",
                            serverInfo.getHostname(), serverInfo.getIpAddress(), serverInfo.getProvider());
                    details.put("confidence", 1.0 - confidence);
                    details.put("event", "mailbox_does_not_exist");
                    details.put("mx_count", mxRecordsWithWeights.size());
                    
                    logger.info("Email validation result for {}: UNDELIVERABLE (confidence: {}, MX: {})", 
                            email, String.format("%.2f", 1.0 - confidence), primaryMxHost);
                    
                    final var result = ValidationResult.invalid(getName(), "Email not deliverable", details);
                    cacheResult(cacheKey, result);
                    return result;
                }
            }
            
            logger.info("No conclusive result for email {} after checking MX servers", email);
            final var details = createDetailsMap(false, "Inconclusive SMTP check",
                    primaryMxHost, getIpAddress(primaryMxHost), provider);
            details.put("event", "inconclusive");
            details.put("status", "unknown");
            details.put("mx_count", mxRecordsWithWeights.size());
            
            final var result = ValidationResult.valid(getName(), details);
            cacheResult(cacheKey, result);
            return result;
            
        } catch (final Exception e) {
            logger.warn("SMTP validation failed for email {}: {}", email, e.getMessage());
            final var details = createDetailsMap(false, "SMTP check error: " + e.getMessage(), "", "", "");
            details.put("event", "inconclusive");
            details.put("status", "unknown");
            return ValidationResult.valid(getName(), details);
        } finally {
            logger.info("Total validation time for {}: {}ms", email, System.currentTimeMillis() - totalStartTime);
        }
    }

    private boolean detectCatchAll(final String originalEmail, final String domain, final String mxHost) {
        try {
            logger.debug("Testing if domain {} is catch-all using server {}", domain, mxHost);
            
            // Use 3 different probe addresses with very random formats
            final String randomId1 = getRandomString(10);
            final String randomId2 = getRandomString(12);
            final String randomId3 = getRandomString(8);
            
            final String[] probeLocalParts = {
                "nonexistent-user-" + randomId1,
                "invalid.email." + randomId2, 
                "probe_" + randomId3 + "_test"
            };
            
            logger.debug("Catch-all test for domain {} using multiple probe addresses", domain);
            
            // Create futures for each probe
            List<CompletableFuture<SmtpValidationResult>> probeFutures = Arrays.stream(probeLocalParts)
                .map(probeLocalPart -> CompletableFuture.supplyAsync(() -> {
                    logger.debug("Starting SMTP verification for {}@{} on MX host {}", 
                        probeLocalPart, domain, mxHost);
                    return performOneSmtpVerification(probeLocalPart, domain, mxHost);
                }, smtpExecutor))
                .collect(Collectors.toList());
            
            // Wait for all probes to complete with timeout
            CompletableFuture.allOf(probeFutures.toArray(new CompletableFuture[0]))
                .get(5, TimeUnit.SECONDS);
            
            int acceptedCount = 0;
            boolean anyRejected = false;
            
            // Process results
            for (int i = 0; i < probeFutures.size(); i++) {
                SmtpValidationResult result = probeFutures.get(i).get();
                String probeLocalPart = probeLocalParts[i];
                
                logger.debug("Catch-all test result for probe {}: deliverable={}, response code={}, response={}", 
                    probeLocalPart, result.isDeliverable(), result.getResponseCode(), result.getFullResponse());
                
                if (result.isDeliverable()) {
                    acceptedCount++;
                } else if (!result.isTempError() && result.getResponseCode() >= 500) {
                    anyRejected = true;
                }
            }
            
            // Logic for determining catch-all status:
            // 1. If 2 or more probes are accepted, it's likely a catch-all
            // 2. If any are explicitly rejected with 5xx code, it's not a catch-all
            if (acceptedCount >= 2) {
                logger.debug("Domain {} IS catch-all: accepted {} of 3 probe emails", domain, acceptedCount);
                return true;
            }
            
            if (anyRejected) {
                logger.debug("Domain {} is NOT catch-all: explicitly rejected invalid emails", domain);
                return false;
            }
            
            logger.debug("Catch-all test for domain {} was inconclusive ({}/3 accepted), assuming not catch-all", 
                domain, acceptedCount);
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
        
        // Apply throttling before verification
        applyThrottling(domain);
        
        // Create futures for each verification attempt
        List<CompletableFuture<SmtpValidationResult>> verificationFutures = new ArrayList<>();
        
        for (int i = 0; i < VERIFICATION_ATTEMPTS; i++) {
            final int attempt = i;
            verificationFutures.add(CompletableFuture.supplyAsync(() -> {
                logger.debug("SMTP verification attempt #{} for {}@{} on MX host {}", 
                    attempt + 1, localPart, domain, mxHost);
                try {
                    return performOneSmtpVerification(localPart, domain, mxHost);
                } catch (Exception e) {
                    logger.debug("SMTP verification attempt #{} for {}@{} resulted in error: {}", 
                        attempt + 1, localPart, domain, e.getMessage());
                    
                    // Check if we should queue for retry
                    if (shouldQueueForRetry(e)) {
                        queueForRetry(localPart, domain, mxHost);
                    }
                    return new SmtpValidationResult(false, false, 0, true, e.getMessage(), mxHost);
                }
            }, smtpExecutor));
        }
        
        // Wait for all verifications to complete
        try {
            CompletableFuture.allOf(verificationFutures.toArray(new CompletableFuture[0]))
                .get(10, TimeUnit.SECONDS);
            
            // Collect results
            for (CompletableFuture<SmtpValidationResult> future : verificationFutures) {
                results.add(future.get());
            }
        } catch (Exception e) {
            logger.warn("Error during concurrent SMTP verification: {}", e.getMessage());
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
            
            // Enhanced response code analysis
            if (responseCode >= 200 && responseCode < 300) {
                // Good sign, likely deliverable
                isDeliverable = true;
                
                // Check for catch-all indicators in 2xx responses
                String fullResponseLower = fullResponse.toLowerCase();
                if (fullResponseLower.contains("catch-all") || 
                    fullResponseLower.contains("catchall") ||
                    fullResponseLower.contains("accept all") || 
                    fullResponseLower.contains("accepting all") ||
                    fullResponseLower.contains("any recipient") ||
                    fullResponseLower.contains("wildcard")) {
                    
                    isCatchAll = true;
                    logger.debug("Catch-all indicator found in server response: {}", fullResponse);
                }
                
                // Some servers have specific response formats for real vs. accepted-but-invalid emails
                // Look for "accepted" without "user" or "recipient" which may indicate generic acceptance
                if (!fullResponseLower.contains("user") && 
                    !fullResponseLower.contains("recipient") &&
                    !fullResponseLower.contains("mailbox") &&
                    (fullResponseLower.contains("accept") || fullResponseLower.contains("ok"))) {
                    
                    logger.debug("Potential catch-all pattern detected in response: {}", fullResponse);
                    isCatchAll = true;
                }
            }
            // For 4xx errors (temporary), generally not deliverable but need to be careful
            else if (responseCode >= 400 && responseCode < 500) {
                isDeliverable = false;
                isTempError = true;
                
                // Check for recognized 4xx errors that indicate invalid user
                // rather than temporary server issues
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
                
                // But 550 can be temporary in some cases
                isTempError = responseCode != 550 || 
                              fullResponse.toLowerCase().contains("try again") ||
                              fullResponse.toLowerCase().contains("try later") ||
                              fullResponse.toLowerCase().contains("unavailable") ||
                              fullResponse.toLowerCase().contains("temporarily");
            }
            
            // Create a more detailed result
            return new SmtpValidationResult(isDeliverable, isCatchAll, responseCode, isTempError, fullResponse, mxHost);
            
        } catch (final Exception e) {
            logger.debug("Error during SMTP check for {}@{} at {}: {}", localPart, domain, mxHost, e.getMessage());
            return new SmtpValidationResult(false, false, 0, true, e.getMessage(), mxHost);
        }
    }

    /**
     * Get MX records with their priority weights
     */
    private List<MxRecord> getMxRecordsWithWeights(final String domain) throws Exception {
        long startTime = System.currentTimeMillis();
        try {
            final var ctx = new javax.naming.directory.InitialDirContext();
            final var attrs = ctx.getAttributes("dns:/" + domain, new String[] {"MX"});
            final var attr = attrs.get("MX");
            
            if (attr == null || attr.size() == 0) {
                return new ArrayList<>();
            }
            
            final var mxRecords = new ArrayList<MxRecord>();
            for (var i = 0; i < attr.size(); i++) {
                final var mxRecord = (String) attr.get(i);
                String[] parts = mxRecord.split("\\s+");
                if (parts.length >= 2) {
                    int priority = Integer.parseInt(parts[0]);
                    String hostname = parts[1];
                    mxRecords.add(new MxRecord(hostname, priority));
                }
            }
            
            return mxRecords;
        } finally {
            logger.info("MX records lookup for {} took {}ms", domain, System.currentTimeMillis() - startTime);
        }
    }
    
    private String[] getMxRecords(final String domain) throws Exception {
        List<MxRecord> records = getMxRecordsWithWeights(domain);
        return records.stream()
            .sorted((a, b) -> Integer.compare(a.priority, b.priority))
            .map(record -> record.hostname)
            .toArray(String[]::new);
    }
    
    /**
     * Helper class to represent an MX record with hostname and priority
     */
    private static class MxRecord {
        final String hostname;
        final int priority;
        
        MxRecord(String hostname, int priority) {
            this.hostname = hostname;
            this.priority = priority;
        }
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

    /**
     * Apply throttling between verification attempts
     */
    private void applyThrottling(String domain) {
        try {
            // Small delay to reduce server load
            Thread.sleep(100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Check DNS records for a domain to determine overall email health
     */
    private Map<String, Object> checkDomainDnsRecords(String domain) {
        Map<String, Object> details = new HashMap<>();
        boolean hasDnsIssues = false;
        
        logger.debug("Starting concurrent DNS checks for domain: {}", domain);
        long startTime = System.currentTimeMillis();
        
        try {
            // Create CompletableFuture for each DNS check using our dedicated executor
            CompletableFuture<String> spfFuture = CompletableFuture.supplyAsync(() -> {
                logger.debug("Starting SPF check for domain: {}", domain);
                return getSpfRecord(domain);
            }, dnsExecutor);
            
            CompletableFuture<String> dmarcFuture = CompletableFuture.supplyAsync(() -> {
                logger.debug("Starting DMARC check for domain: {}", domain);
                return getDmarcRecord(domain);
            }, dnsExecutor);
            
            CompletableFuture<String> dkimDefaultFuture = CompletableFuture.supplyAsync(() -> {
                logger.debug("Starting DKIM check (default) for domain: {}", domain);
                return getDkimRecord("default", domain);
            }, dnsExecutor);
            
            CompletableFuture<String> dkimSelector1Future = CompletableFuture.supplyAsync(() -> {
                logger.debug("Starting DKIM check (selector1) for domain: {}", domain);
                return getDkimRecord("selector1", domain);
            }, dnsExecutor);
            
            // Wait for all futures to complete with timeout
            CompletableFuture.allOf(spfFuture, dmarcFuture, dkimDefaultFuture, dkimSelector1Future)
                .get(5, TimeUnit.SECONDS); // 5 second timeout for all DNS checks
            
            // Process SPF results
            String spfRecord = spfFuture.get();
            logger.debug("SPF check completed for domain {}: {}", domain, spfRecord != null ? "found" : "not found");
            
            if (spfRecord == null || spfRecord.isEmpty()) {
                details.put("spf_record", "missing");
                hasDnsIssues = true;
            } else {
                details.put("spf_record", "present");
                
                // Analyze SPF strictness
                if (spfRecord.contains("-all")) {
                    details.put("spf_policy", "strict");
                } else if (spfRecord.contains("~all")) {
                    details.put("spf_policy", "soft_fail");
                } else if (spfRecord.contains("?all")) {
                    details.put("spf_policy", "neutral");
                } else if (spfRecord.contains("+all")) {
                    details.put("spf_policy", "allow_all");
                    hasDnsIssues = true;
                }
            }
            
            // Process DMARC results
            String dmarcRecord = dmarcFuture.get();
            logger.debug("DMARC check completed for domain {}: {}", domain, dmarcRecord != null ? "found" : "not found");
            
            if (dmarcRecord == null || dmarcRecord.isEmpty()) {
                details.put("dmarc_record", "missing");
                hasDnsIssues = true;
            } else {
                details.put("dmarc_record", "present");
                
                // Analyze DMARC policy
                if (dmarcRecord.contains("p=reject")) {
                    details.put("dmarc_policy", "reject");
                } else if (dmarcRecord.contains("p=quarantine")) {
                    details.put("dmarc_policy", "quarantine");
                } else if (dmarcRecord.contains("p=none")) {
                    details.put("dmarc_policy", "none");
                    hasDnsIssues = true;
                }
            }
            
            // Process DKIM results
            String dkimDefaultRecord = dkimDefaultFuture.get();
            String dkimSelector1Record = dkimSelector1Future.get();
            logger.debug("DKIM checks completed for domain {}: default={}, selector1={}", 
                domain, dkimDefaultRecord != null, dkimSelector1Record != null);
            
            if (dkimDefaultRecord != null && !dkimDefaultRecord.isEmpty()) {
                details.put("dkim_record", "present");
            } else if (dkimSelector1Record != null && !dkimSelector1Record.isEmpty()) {
                details.put("dkim_record", "present");
            } else {
                details.put("dkim_record", "not_found");
            }
            
        } catch (TimeoutException e) {
            logger.warn("DNS checks timed out for domain {} after 5 seconds", domain);
            details.put("dns_check_error", "timeout");
        } catch (Exception e) {
            logger.warn("Error checking DNS records for domain {}: {}", domain, e.getMessage());
            details.put("dns_check_error", e.getMessage());
        }
        
        long endTime = System.currentTimeMillis();
        logger.debug("Completed DNS checks for domain {} in {}ms", domain, (endTime - startTime));
        
        details.put("has_dns_issues", hasDnsIssues);
        return details;
    }
    
    /**
     * Get SPF record for a domain
     */
    private String getSpfRecord(String domain) {
        try {
            final var ctx = new javax.naming.directory.InitialDirContext();
            final var attrs = ctx.getAttributes("dns:/" + domain, new String[] {"TXT"});
            final var attr = attrs.get("TXT");
            
            if (attr != null) {
                for (var i = 0; i < attr.size(); i++) {
                    String record = (String) attr.get(i);
                    if (record.contains("v=spf1")) {
                        return record;
                    }
                }
            }
        } catch (Exception e) {
            logger.debug("Error fetching SPF record for {}: {}", domain, e.getMessage());
        }
        
        return null;
    }
    
    /**
     * Get DMARC record for a domain
     */
    private String getDmarcRecord(String domain) {
        try {
            final var ctx = new javax.naming.directory.InitialDirContext();
            final var attrs = ctx.getAttributes("dns:/_dmarc." + domain, new String[] {"TXT"});
            final var attr = attrs.get("TXT");
            
            if (attr != null && attr.size() > 0) {
                String record = (String) attr.get(0);
                if (record.contains("v=DMARC1")) {
                    return record;
                }
            }
        } catch (Exception e) {
            logger.debug("Error fetching DMARC record for {}: {}", domain, e.getMessage());
        }
        
        return null;
    }
    
    /**
     * Get DKIM record for a domain and selector
     */
    private String getDkimRecord(String selector, String domain) {
        try {
            final var ctx = new javax.naming.directory.InitialDirContext();
            final var attrs = ctx.getAttributes("dns:/" + selector + "._domainkey." + domain, new String[] {"TXT"});
            final var attr = attrs.get("TXT");
            
            if (attr != null && attr.size() > 0) {
                String record = (String) attr.get(0);
                if (record.contains("v=DKIM1")) {
                    return record;
                }
            }
        } catch (Exception e) {
            logger.debug("Error fetching DKIM record for selector {} at domain {}: {}", 
                selector, domain, e.getMessage());
        }
        
        return null;
    }
    
    /**
     * Perform greylisting test - some servers will initially reject unknown recipients
     * but accept them on retry (or vice versa for real accounts)
     */
    private SmtpValidationResult performGreylistTest(String localPart, String domain, String mxHost) {
        logger.debug("Starting greylisting test for {}@{} on MX host {}", localPart, domain, mxHost);
        String email = localPart + "@" + domain;
        
        // First attempt
        applyThrottling(domain);
        SmtpValidationResult firstAttempt = performOneSmtpVerification(localPart, domain, mxHost);
        logger.debug("Greylisting test - first attempt for {}: deliverable={}, response={}", 
            email, firstAttempt.isDeliverable(), firstAttempt.getFullResponse());
            
        // If we got a definitive result (not temporary error), no need for greylisting
        if (!firstAttempt.isTempError()) {
            return firstAttempt;
        }
        
        // Try again after a delay for greylisting servers
        for (int i = 0; i < GREYLISTING_MAX_RETRIES; i++) {
            try {
                // Wait between retries
                Thread.sleep(GREYLISTING_RETRY_DELAY_MS);
                
                // Apply throttling before each retry
                applyThrottling(domain);
                
                // Next attempt
                SmtpValidationResult nextAttempt = performOneSmtpVerification(localPart, domain, mxHost);
                logger.debug("Greylisting test - attempt #{} for {}: deliverable={}, response={}", 
                    i+2, email, nextAttempt.isDeliverable(), nextAttempt.getFullResponse());
                
                // If we get a non-temporary response, return it
                if (!nextAttempt.isTempError()) {
                    return nextAttempt;
                }
                
                // If the response is different from the first attempt, that's significant
                if (nextAttempt.getResponseCode() != firstAttempt.getResponseCode() ||
                    !nextAttempt.getFullResponse().equals(firstAttempt.getFullResponse())) {
                    
                    logger.debug("Greylisting detected - different responses between attempts");
                    
                    // If we get a different result code, prefer whichever one is more likely deliverable
                    if (nextAttempt.isDeliverable() != firstAttempt.isDeliverable()) {
                        return nextAttempt.isDeliverable() ? nextAttempt : firstAttempt;
                    }
                }
                
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                logger.debug("Error during greylisting retry: {}", e.getMessage());
            }
        }
        
        // If we get here, greylisting test was inconclusive
        logger.debug("Greylisting test inconclusive for {}", email);
        return null;
    }

    /**
     * Determine if an exception should trigger a retry
     */
    private boolean shouldQueueForRetry(Exception e) {
        // Retry for connection issues
        if (e instanceof SocketTimeoutException || 
            e instanceof ConnectException ||
            e instanceof SocketException) {
            return true;
        }
        
        // Also retry for certain types of error messages
        String message = e.getMessage();
        if (message != null && (
            message.contains("timeout") ||
            message.contains("reset") ||
            message.contains("refused") ||
            message.contains("closed") ||
            message.contains("limit"))) {
            return true;
        }
        
        return false;
    }
    
    /**
     * Queue email for retry later
     */
    private void queueForRetry(String localPart, String domain, String mxHost) {
        // Log that we're queuing this email
        logger.debug("Queuing {}@{} for retry later", localPart, domain);
        
        // In a real implementation, this would add to a persistent queue
        // Here we just log it
    }

    // Add shutdown hook for the executor
    @PreDestroy
    public void cleanup() {
        dnsExecutor.shutdown();
        smtpExecutor.shutdown();
        try {
            if (!dnsExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                dnsExecutor.shutdownNow();
            }
            if (!smtpExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                smtpExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            dnsExecutor.shutdownNow();
            smtpExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
} 