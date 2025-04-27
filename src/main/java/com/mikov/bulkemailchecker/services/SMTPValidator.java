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
import java.util.concurrent.TimeUnit;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.Map;
import java.util.ArrayList;
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
    
    private static final boolean ENABLE_FAST_MODE = false;
    private static final boolean ENABLE_AGGRESSIVE_VERIFICATION = true;
    private static final int SOCKET_TIMEOUT_MS = 5000;
    private static final int CONNECTION_TIMEOUT_MS = 5000;
    private static final int VERIFICATION_ATTEMPTS = 2;
    private static final int SMTP_PORT = 25;
    private static final int GREYLISTING_RETRY_DELAY_MS = 3000;
    private static final int GREYLISTING_MAX_RETRIES = 2;
    private static final int MAX_CONNECTIONS_PER_DOMAIN = 3;
    
    private static final String[] INVALID_RESPONSE_SUBSTRINGS = {
        "does not exist", "no such user", "user unknown", "invalid recipient", 
        "recipient rejected", "address rejected", "not found", "mailbox unavailable",
        "no mailbox", "not a valid mailbox", "not our customer", "address unknown",
        "no such recipient", "bad address", "delivery failed", "recipient address rejected"
    };
    
    private final Map<String, CachedValidationResult> resultCache = new HashMap<>();

    private static final Random random = new Random();
    
    private static final ExecutorService dnsExecutor = Executors.newVirtualThreadPerTaskExecutor();
    private static final ExecutorService smtpExecutor = Executors.newVirtualThreadPerTaskExecutor();
    
    @Override
    public ValidationResult validate(final String email) {
        logger.info("Starting SMTP validation for email: {}", email);
        long totalStartTime = System.currentTimeMillis();
        
        try {
            // 1. Basic validation
            ValidationResult basicValidation = validateBasicEmailFormat(email);
            if (!basicValidation.isValid()) {
                return basicValidation;
            }
            
            // 2. Check cache
            final var cacheKey = email.toLowerCase();
            final var cachedResult = resultCache.get(cacheKey);
            if (cachedResult != null && !cachedResult.isExpired()) {
                logger.info("Using cached validation result for email: {}", email);
                return cachedResult.getResult();
            }
            
            // 3. Extract email parts
            final var parts = email.split("@", 2);
            final var localPart = parts[0];
            final var domain = parts[1].toLowerCase();
            
            // 4. Get MX records and DNS info
            final var mxInfo = getMxAndDnsInfo(domain);
            if (!mxInfo.isValid()) {
                return mxInfo.getValidationResult();
            }
            
            // 5. Perform SMTP validation
            final var validationResult = performSmtpValidation(localPart, domain, mxInfo);
            
            // 6. Cache and return result
            cacheResult(cacheKey, validationResult);
            return validationResult;
            
        } catch (final Exception e) {
            logger.warn("SMTP validation failed for email {}: {}", email, e.getMessage());
            return handleValidationError(email, e);
        } finally {
            logger.info("Total validation time for {}: {}ms", email, System.currentTimeMillis() - totalStartTime);
        }
    }
    
    private ValidationResult validateBasicEmailFormat(final String email) {
        if (email == null || email.isBlank()) {
            logger.info("Email is null or empty: {}", email);
            return ValidationResult.invalid(getName(), "Email is null or empty");
        }
        
        final var parts = email.split("@", 2);
        if (parts.length != 2) {
            logger.info("Invalid email format: {}", email);
            return ValidationResult.invalid(getName(), "Invalid email format");
        }
        
        return ValidationResult.valid(getName());
    }
    
    private MxAndDnsInfo getMxAndDnsInfo(final String domain) throws Exception {
        long mxStartTime = System.currentTimeMillis();
        final var mxRecordsWithWeights = getMxRecordsWithWeights(domain);
        logger.info("MX records lookup for {} took {}ms", domain, System.currentTimeMillis() - mxStartTime);
        
        if (mxRecordsWithWeights.isEmpty()) {
            logger.info("No MX records found for domain: {}", domain);
            return new MxAndDnsInfo(ValidationResult.invalid(getName(), "No MX records found"));
        }
        
        logger.debug("Found {} MX records for domain {}", mxRecordsWithWeights.size(), domain);
        
        long dnsStartTime = System.currentTimeMillis();
        Map<String, Object> dnsDetails = checkDomainDnsRecords(domain);
        logger.info("DNS checks for {} took {}ms", domain, System.currentTimeMillis() - dnsStartTime);
        
        mxRecordsWithWeights.sort(Comparator.comparingInt(a -> a.priority));
        final var mxHosts = mxRecordsWithWeights.stream()
            .map(record -> record.hostname)
            .toArray(String[]::new);
        
        final var provider = identifyProvider(mxHosts);
        final var primaryMxRecord = mxRecordsWithWeights.get(0);
        
        return new MxAndDnsInfo(mxRecordsWithWeights, dnsDetails, provider, primaryMxRecord);
    }
    
    private ValidationResult performSmtpValidation(final String localPart, final String domain, 
                                                 final MxAndDnsInfo mxInfo) {
        final var primaryMxHost = mxInfo.getPrimaryMxRecord().hostname;
        final var serverInfo = new SmtpServerInfo(primaryMxHost, getIpAddress(primaryMxHost), mxInfo.getProvider());
        
        // 1. Check for catch-all if not in fast mode
        if (!ENABLE_FAST_MODE) {
            final var catchAllResult = checkForCatchAll(localPart, domain, mxInfo.getMxRecords());
            if (catchAllResult != null) {
                return catchAllResult;
            }
        }
        
        // 2. Perform greylisting test if enabled
        if (ENABLE_AGGRESSIVE_VERIFICATION) {
            final var greylistResult = performGreylistTest(localPart, domain, primaryMxHost);
            if (greylistResult != null && !greylistResult.isTempError()) {
                return createValidationResultFromGreylist(greylistResult, serverInfo, mxInfo);
            }
        }
        
        // 3. Perform direct verification
        final var verificationResults = performDirectVerification(localPart, domain, primaryMxHost);
        return analyzeVerificationResults(verificationResults, serverInfo, mxInfo);
    }
    
    private ValidationResult checkForCatchAll(final String localPart, final String domain, 
                                            final List<MxRecord> mxRecords) {
        for (int i = 0; i < mxRecords.size() && i < 2; i++) {
            MxRecord mxRecord = mxRecords.get(i);
            logger.debug("Testing MX server {} (priority {}) for catch-all detection", 
                mxRecord.hostname, mxRecord.priority);
            
            if (detectCatchAll(localPart + "@" + domain, domain, mxRecord.hostname)) {
                logger.info("Domain {} detected as catch-all", domain);
                return createCatchAllResult(domain, mxRecord.hostname);
            }
        }
        return null;
    }
    
    private ValidationResult createCatchAllResult(final String domain, final String mxHost) {
        final var details = createDetailsMap(true, "Catch-all domain",
                mxHost, getIpAddress(mxHost), identifyProvider(new String[]{mxHost}));
        details.put("event", "is_catchall");
        details.put("status", "unknown");
        details.put("mx_count", 1);
        return ValidationResult.valid(getName(), details);
    }
    
    private ValidationResult createValidationResultFromGreylist(final SmtpValidationResult greylistResult,
                                                              final SmtpServerInfo serverInfo,
                                                              final MxAndDnsInfo mxInfo) {
        final var details = createDetailsMap(greylistResult.isCatchAll(), 
            greylistResult.isDeliverable() ? null : "Email not deliverable",
            serverInfo.getHostname(), serverInfo.getIpAddress(), serverInfo.getProvider());
        
        details.put("event", greylistResult.isDeliverable() ? "mailbox_exists" : "inconclusive");
        details.put("response_code", greylistResult.getResponseCode());
        details.put("full_response", greylistResult.getFullResponse());
        details.put("mx_count", mxInfo.getMxRecords().size());
        details.putAll(mxInfo.getDnsDetails());
        
        logger.info("Greylisting test for {}: {}", serverInfo.getHostname(), 
            greylistResult.isDeliverable() ? "DELIVERABLE" : "INCONCLUSIVE");
        
        return ValidationResult.valid(getName(), details);
    }
    
    private ValidationResult analyzeVerificationResults(final List<SmtpValidationResult> results,
                                                      final SmtpServerInfo serverInfo,
                                                      final MxAndDnsInfo mxInfo) {
        if (results.isEmpty()) {
            return createInconclusiveResult(serverInfo, mxInfo);
        }
        
        // Check for server restrictions
        if (isServerRestricted(results)) {
            return createServerRestrictedResult(serverInfo, mxInfo);
        }
        
        final var deliverableCount = results.stream()
            .filter(SmtpValidationResult::isDeliverable)
            .count();
        
        final var confidence = (double) deliverableCount / results.size();
        logger.debug("SMTP verification confidence: {} of {} attempts deliverable (confidence: {})", 
                deliverableCount, results.size(), String.format("%.2f", confidence));
        
        return createFinalValidationResult(results, confidence, serverInfo, mxInfo);
    }
    
    private boolean isServerRestricted(final List<SmtpValidationResult> results) {
        return results.stream()
            .allMatch(result -> result.getFullResponse() != null && 
                result.getFullResponse().contains("We do not authorize the use of this system"));
    }
    
    private ValidationResult createServerRestrictedResult(final SmtpServerInfo serverInfo,
                                                        final MxAndDnsInfo mxInfo) {
        logger.info("Email validation result: UNKNOWN (server restricted verification)");
        final var details = createDetailsMap(false, "Server restricted verification",
                serverInfo.getHostname(), serverInfo.getIpAddress(), serverInfo.getProvider());
        details.put("event", "server_restricted");
        details.put("status", "unknown");
        details.put("mx_count", mxInfo.getMxRecords().size());
        details.putAll(mxInfo.getDnsDetails());
        
        return ValidationResult.valid(getName(), details);
    }
    
    private ValidationResult createInconclusiveResult(final SmtpServerInfo serverInfo,
                                                    final MxAndDnsInfo mxInfo) {
        logger.info("No conclusive result after checking MX servers");
        final var details = createDetailsMap(false, "Inconclusive SMTP check",
                serverInfo.getHostname(), serverInfo.getIpAddress(), serverInfo.getProvider());
        details.put("event", "inconclusive");
        details.put("status", "unknown");
        details.put("mx_count", mxInfo.getMxRecords().size());
        
        return ValidationResult.valid(getName(), details);
    }
    
    private ValidationResult createFinalValidationResult(final List<SmtpValidationResult> results,
                                                       final double confidence,
                                                       final SmtpServerInfo serverInfo,
                                                       final MxAndDnsInfo mxInfo) {
        final var isDeliverable = confidence >= 0.5;
        final var details = createDetailsMap(false, isDeliverable ? null : "Email not deliverable",
                serverInfo.getHostname(), serverInfo.getIpAddress(), serverInfo.getProvider());
        
        details.put("confidence", isDeliverable ? confidence : 1.0 - confidence);
        details.put("event", isDeliverable ? "mailbox_exists" : "mailbox_does_not_exist");
        details.put("mx_count", mxInfo.getMxRecords().size());
        details.putAll(mxInfo.getDnsDetails());
        
        logger.info("Email validation result: {} (confidence: {}, MX: {})", 
                isDeliverable ? "DELIVERABLE" : "UNDELIVERABLE",
                String.format("%.2f", isDeliverable ? confidence : 1.0 - confidence),
                serverInfo.getHostname());
        
        return isDeliverable ? 
            ValidationResult.valid(getName(), details) :
            ValidationResult.invalid(getName(), "Email not deliverable", details);
    }
    
    private ValidationResult handleValidationError(final String email, final Exception e) {
        final var details = createDetailsMap(false, "SMTP check error: " + e.getMessage(), "", "", "");
        details.put("event", "inconclusive");
        details.put("status", "unknown");
        return ValidationResult.valid(getName(), details);
    }
    
    // Helper class to hold MX and DNS information
    private static class MxAndDnsInfo {
        private final List<MxRecord> mxRecords;
        private final Map<String, Object> dnsDetails;
        private final String provider;
        private final MxRecord primaryMxRecord;
        private final ValidationResult validationResult;
        
        public MxAndDnsInfo(ValidationResult validationResult) {
            this.validationResult = validationResult;
            this.mxRecords = null;
            this.dnsDetails = null;
            this.provider = null;
            this.primaryMxRecord = null;
        }
        
        public MxAndDnsInfo(List<MxRecord> mxRecords, Map<String, Object> dnsDetails, 
                          String provider, MxRecord primaryMxRecord) {
            this.mxRecords = mxRecords;
            this.dnsDetails = dnsDetails;
            this.provider = provider;
            this.primaryMxRecord = primaryMxRecord;
            this.validationResult = null;
        }
        
        public boolean isValid() {
            return validationResult == null;
        }
        
        public ValidationResult getValidationResult() {
            return validationResult;
        }
        
        public List<MxRecord> getMxRecords() {
            return mxRecords;
        }
        
        public Map<String, Object> getDnsDetails() {
            return dnsDetails;
        }
        
        public String getProvider() {
            return provider;
        }
        
        public MxRecord getPrimaryMxRecord() {
            return primaryMxRecord;
        }
    }

    private boolean detectCatchAll(final String originalEmail, final String domain, final String mxHost) {
        try {
            logger.debug("Testing if domain {} is catch-all using server {}", domain, mxHost);
            
            final String randomId1 = getRandomString(10);
            final String randomId2 = getRandomString(12);
            final String randomId3 = getRandomString(8);
            
            final String[] probeLocalParts = {
                "nonexistent-user-" + randomId1,
                "invalid.email." + randomId2, 
                "probe_" + randomId3 + "_test"
            };
            
            logger.debug("Catch-all test for domain {} using multiple probe addresses", domain);
            
            List<CompletableFuture<SmtpValidationResult>> probeFutures = Arrays.stream(probeLocalParts)
                .map(probeLocalPart -> CompletableFuture.supplyAsync(() -> {
                    logger.debug("Starting SMTP verification for {}@{} on MX host {}", 
                        probeLocalPart, domain, mxHost);
                    return performOneSmtpVerification(probeLocalPart, domain, mxHost);
                }, smtpExecutor))
                .collect(Collectors.toList());
            
            CompletableFuture.allOf(probeFutures.toArray(new CompletableFuture[0]))
                .get(5, TimeUnit.SECONDS);
            
            int acceptedCount = 0;
            boolean anyRejected = false;
            
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
        
        applyThrottling(domain);
        
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
                    
                    if (shouldQueueForRetry(e)) {
                        queueForRetry(localPart, domain, mxHost);
                    }
                    return new SmtpValidationResult(false, false, 0, true, e.getMessage(), mxHost);
                }
            }, smtpExecutor));
        }
        
        try {
            CompletableFuture.allOf(verificationFutures.toArray(new CompletableFuture[0]))
                .get(10, TimeUnit.SECONDS);
            
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
            
            final var response = in.readLine();
            final var responseCode = getResponseCode(response);
            
            // Check for server restriction message in the initial response
            if (response != null && response.contains("We do not authorize the use of this system")) {
                logger.debug("Server {} restricts verification: {}", mxHost, response);
                return new SmtpValidationResult(false, false, responseCode, false, response, mxHost);
            }
            
            if (responseCode != 220) {
                logger.debug("Unexpected greeting from {}: {}", mxHost, response);
                return new SmtpValidationResult(false, false, responseCode, true);
            }
            
            final var heloCmd = "HELO fake.com\r\n";
            out.print(heloCmd);
            out.flush();
            final var heloResponse = in.readLine();
            
            // Check for server restriction message in HELO response
            if (heloResponse != null && heloResponse.contains("We do not authorize the use of this system")) {
                logger.debug("Server {} restricts verification during HELO: {}", mxHost, heloResponse);
                return new SmtpValidationResult(false, false, getResponseCode(heloResponse), false, heloResponse, mxHost);
            }
            
            if (getResponseCode(heloResponse) != 250) {
                logger.debug("HELO rejected by {}: {}", mxHost, heloResponse);
                return new SmtpValidationResult(false, false, getResponseCode(heloResponse), true);
            }
            
            final var mailFromCmd = "MAIL FROM:<verify@fake.com>\r\n";
            out.print(mailFromCmd);
            out.flush();
            final var mailFromResponse = in.readLine();
            
            // Check for server restriction message in MAIL FROM response
            if (mailFromResponse != null && mailFromResponse.contains("We do not authorize the use of this system")) {
                logger.debug("Server {} restricts verification during MAIL FROM: {}", mxHost, mailFromResponse);
                return new SmtpValidationResult(false, false, getResponseCode(mailFromResponse), false, mailFromResponse, mxHost);
            }
            
            if (getResponseCode(mailFromResponse) != 250) {
                logger.debug("MAIL FROM rejected by {}: {}", mxHost, mailFromResponse);
                return new SmtpValidationResult(false, false, getResponseCode(mailFromResponse), true);
            }
            
            final var rcptToCmd = "RCPT TO:<" + localPart + "@" + domain + ">\r\n";
            out.print(rcptToCmd);
            out.flush();
            final var rcptToResponse = in.readLine();
            
            // Check for server restriction message in RCPT TO response
            if (rcptToResponse != null && rcptToResponse.contains("We do not authorize the use of this system")) {
                logger.debug("Server {} restricts verification during RCPT TO: {}", mxHost, rcptToResponse);
                return new SmtpValidationResult(false, false, getResponseCode(rcptToResponse), false, rcptToResponse, mxHost);
            }
            
            int rcptToResponseCode = getResponseCode(rcptToResponse);
            boolean isTempError = false;
            
            if (rcptToResponseCode >= 400 && rcptToResponseCode < 500) {
                isTempError = true;
            }
            
            out.print("QUIT\r\n");
            out.flush();
            
            try {
                in.readLine();
            } catch (Exception e) {
            }
            
            try {
                socket.close();
            } catch (Exception e) {
            }
            
            final var fullResponse = rcptToResponse != null ? rcptToResponse : "";
            
            boolean isDeliverable = false;
            boolean isCatchAll = false;
            
            if (rcptToResponseCode >= 200 && rcptToResponseCode < 300) {
                isDeliverable = true;
                
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
                
                if (!fullResponseLower.contains("user") && 
                    !fullResponseLower.contains("recipient") &&
                    !fullResponseLower.contains("mailbox") &&
                    (fullResponseLower.contains("accept") || fullResponseLower.contains("ok"))) {
                    
                    logger.debug("Potential catch-all pattern detected in response: {}", fullResponse);
                    isCatchAll = true;
                }
            }
            else if (rcptToResponseCode >= 400 && rcptToResponseCode < 500) {
                isDeliverable = false;
                isTempError = true;
                
                for (String invalidPattern : INVALID_RESPONSE_SUBSTRINGS) {
                    if (fullResponse.toLowerCase().contains(invalidPattern.toLowerCase())) {
                        isDeliverable = false;
                        isTempError = false;
                        break;
                    }
                }
            }
            else if (rcptToResponseCode >= 500) {
                isDeliverable = false;
                
                isTempError = rcptToResponseCode != 550 || 
                              fullResponse.toLowerCase().contains("try again") ||
                              fullResponse.toLowerCase().contains("try later") ||
                              fullResponse.toLowerCase().contains("unavailable") ||
                              fullResponse.toLowerCase().contains("temporarily");
            }
            
            return new SmtpValidationResult(isDeliverable, isCatchAll, rcptToResponseCode, isTempError, fullResponse, mxHost);
            
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
            final var env = new java.util.Hashtable<String, String>();
            env.put("com.sun.jndi.dns.timeout.initial", "2000");  // 2 second initial timeout 
            env.put("com.sun.jndi.dns.timeout.retries", "1");     // 1 retry
            final var ctx = new javax.naming.directory.InitialDirContext(env);
            
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
            return false;
        }
    }

    /**
     * Apply throttling between verification attempts
     */
    private void applyThrottling(String domain) {
        try {
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
            CompletableFuture<String> spfFuture = CompletableFuture.supplyAsync(() -> {
                logger.debug("Starting SPF check for domain: {}", domain);
                return getSpfRecord(domain);
            }, dnsExecutor).orTimeout(2, TimeUnit.SECONDS);
            
            CompletableFuture<String> dmarcFuture = CompletableFuture.supplyAsync(() -> {
                logger.debug("Starting DMARC check for domain: {}", domain);
                return getDmarcRecord(domain);
            }, dnsExecutor).orTimeout(2, TimeUnit.SECONDS);
            
            CompletableFuture<String> dkimDefaultFuture = CompletableFuture.supplyAsync(() -> {
                logger.debug("Starting DKIM check (default) for domain: {}", domain);
                return getDkimRecord("default", domain);
            }, dnsExecutor).orTimeout(2, TimeUnit.SECONDS);
            
            CompletableFuture<String> dkimSelector1Future = CompletableFuture.supplyAsync(() -> {
                logger.debug("Starting DKIM check (selector1) for domain: {}", domain);
                return getDkimRecord("selector1", domain);
            }, dnsExecutor).orTimeout(2, TimeUnit.SECONDS);
            
            // Process the futures independently to prevent one failure from affecting others
            String spfRecord = null;
            try {
                spfRecord = spfFuture.get(3, TimeUnit.SECONDS);
                logger.debug("SPF check completed for domain {}: {}", domain, spfRecord != null ? "found" : "not found");
            } catch (Exception e) {
                logger.debug("SPF lookup failed for domain {}: {}", domain, e.getMessage());
            }
            
            String dmarcRecord = null;
            try {
                dmarcRecord = dmarcFuture.get(3, TimeUnit.SECONDS);
                logger.debug("DMARC check completed for domain {}: {}", domain, dmarcRecord != null ? "found" : "not found");
            } catch (Exception e) {
                logger.debug("DMARC lookup failed for domain {}: {}", domain, e.getMessage());
            }
            
            String dkimDefaultRecord = null;
            try {
                dkimDefaultRecord = dkimDefaultFuture.get(3, TimeUnit.SECONDS);
            } catch (Exception e) {
                logger.debug("DKIM default lookup failed for domain {}: {}", domain, e.getMessage());
            }
            
            String dkimSelector1Record = null;
            try {
                dkimSelector1Record = dkimSelector1Future.get(3, TimeUnit.SECONDS);
                logger.debug("DKIM checks completed for domain {}: default={}, selector1={}", 
                    domain, dkimDefaultRecord != null, dkimSelector1Record != null);
            } catch (Exception e) {
                logger.debug("DKIM selector1 lookup failed for domain {}: {}", domain, e.getMessage());
            }
            
            // Process SPF results
            if (spfRecord == null || spfRecord.isEmpty()) {
                details.put("spf_record", "missing");
                hasDnsIssues = true;
            } else {
                details.put("spf_record", "present");
                
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
            if (dmarcRecord == null || dmarcRecord.isEmpty()) {
                details.put("dmarc_record", "missing");
                hasDnsIssues = true;
            } else {
                details.put("dmarc_record", "present");
                
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
            if (dkimDefaultRecord != null && !dkimDefaultRecord.isEmpty()) {
                details.put("dkim_record", "present");
            } else if (dkimSelector1Record != null && !dkimSelector1Record.isEmpty()) {
                details.put("dkim_record", "present");
            } else {
                details.put("dkim_record", "not_found");
            }
            
        } catch (Exception e) {
            logger.warn("Error during DNS checks for domain {}: {}", domain, e.getMessage());
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
            final var env = new java.util.Hashtable<String, String>();
            env.put("com.sun.jndi.dns.timeout.initial", "1000");  // 1 second initial timeout
            env.put("com.sun.jndi.dns.timeout.retries", "1");     // 1 retry
            final var ctx = new javax.naming.directory.InitialDirContext(env);
            
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
            final var env = new java.util.Hashtable<String, String>();
            env.put("com.sun.jndi.dns.timeout.initial", "1000");  // 1 second initial timeout
            env.put("com.sun.jndi.dns.timeout.retries", "1");     // 1 retry
            final var ctx = new javax.naming.directory.InitialDirContext(env);
            
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
            final var env = new java.util.Hashtable<String, String>();
            env.put("com.sun.jndi.dns.timeout.initial", "1000");  // 1 second initial timeout
            env.put("com.sun.jndi.dns.timeout.retries", "1");     // 1 retry
            final var ctx = new javax.naming.directory.InitialDirContext(env);
            
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
        
        applyThrottling(domain);
        SmtpValidationResult firstAttempt = performOneSmtpVerification(localPart, domain, mxHost);
        logger.debug("Greylisting test - first attempt for {}: deliverable={}, response={}", 
            email, firstAttempt.isDeliverable(), firstAttempt.getFullResponse());
            
        if (!firstAttempt.isTempError()) {
            return firstAttempt;
        }
        
        for (int i = 0; i < GREYLISTING_MAX_RETRIES; i++) {
            try {
                Thread.sleep(GREYLISTING_RETRY_DELAY_MS);
                
                applyThrottling(domain);
                
                SmtpValidationResult nextAttempt = performOneSmtpVerification(localPart, domain, mxHost);
                logger.debug("Greylisting test - attempt #{} for {}: deliverable={}, response={}", 
                    i+2, email, nextAttempt.isDeliverable(), nextAttempt.getFullResponse());
                
                if (!nextAttempt.isTempError()) {
                    return nextAttempt;
                }
                
                if (nextAttempt.getResponseCode() != firstAttempt.getResponseCode() ||
                    !nextAttempt.getFullResponse().equals(firstAttempt.getFullResponse())) {
                    
                    logger.debug("Greylisting detected - different responses between attempts");
                    
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
        
        logger.debug("Greylisting test inconclusive for {}", email);
        return null;
    }

    private boolean shouldQueueForRetry(Exception e) {
        if (e instanceof SocketTimeoutException || 
            e instanceof ConnectException ||
            e instanceof SocketException) {
            return true;
        }
        
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
    
    private void queueForRetry(String localPart, String domain, String mxHost) {
        logger.debug("Queuing {}@{} for retry later", localPart, domain);
    }

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