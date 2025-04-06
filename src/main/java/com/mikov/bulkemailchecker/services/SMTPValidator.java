package com.mikov.bulkemailchecker.services;

import com.mikov.bulkemailchecker.dtos.ValidationResult;
import com.mikov.bulkemailchecker.dtos.SmtpServerInfo;
import com.mikov.bulkemailchecker.dtos.SmtpValidationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.InputStreamReader;
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
import java.util.Comparator;
import java.util.Map;
import java.util.ArrayList;

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
    
    private static final int SMTP_PORT = 25;
    private static final int SOCKET_TIMEOUT_MS = 5000;
    private static final int VERIFICATION_ATTEMPTS = 2;

    private static final int MAX_CONNECTIONS_PER_DOMAIN = 3;
    private static final long DOMAIN_THROTTLE_MS = 2000;
    private static final long GLOBAL_THROTTLE_MS = 50;
    
    private static final int CACHE_MAX_SIZE = 2000;
    private static final long CACHE_EXPIRY_MINUTES = 60;
    
    private final ConcurrentHashMap<String, Long> domainLastCatchAllCheck = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Boolean> domainCatchAllStatus = new ConcurrentHashMap<>();
    private static final long CATCH_ALL_CACHE_EXPIRY_MS = TimeUnit.MINUTES.toMillis(30);
    
    private final ConcurrentHashMap<String, Semaphore> domainThrottlers = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, AtomicLong> lastDomainAccessTime = new ConcurrentHashMap<>();
    private final Semaphore globalThrottler = new Semaphore(5, true); // Max 5 concurrent SMTP connections
    private final AtomicLong lastGlobalAccessTime = new AtomicLong(0);
    
    private final ConcurrentHashMap<String, CachedValidationResult> resultCache = new ConcurrentHashMap<>();
    
    private static final Pattern DOMAIN_PATTERN = Pattern.compile("(?:[^.]+\\.)?([^.]+\\.[^.]+)$");
    private static final Map<Pattern, String> PROVIDER_PATTERNS = new HashMap<>();

    static {
        PROVIDER_PATTERNS.put(Pattern.compile(".*\\.google\\.com", Pattern.CASE_INSENSITIVE), "Google");
        PROVIDER_PATTERNS.put(Pattern.compile(".*\\.outlook\\.com", Pattern.CASE_INSENSITIVE), "Microsoft");
        PROVIDER_PATTERNS.put(Pattern.compile(".*\\.hotmail\\.com", Pattern.CASE_INSENSITIVE), "Microsoft");
        PROVIDER_PATTERNS.put(Pattern.compile(".*\\.live\\.com", Pattern.CASE_INSENSITIVE), "Microsoft");
        PROVIDER_PATTERNS.put(Pattern.compile(".*\\.office365\\.com", Pattern.CASE_INSENSITIVE), "Microsoft");
        PROVIDER_PATTERNS.put(Pattern.compile(".*\\.yahoo\\.com", Pattern.CASE_INSENSITIVE), "Yahoo");
        PROVIDER_PATTERNS.put(Pattern.compile(".*\\.yahoodns\\.net", Pattern.CASE_INSENSITIVE), "Yahoo");
        PROVIDER_PATTERNS.put(Pattern.compile(".*\\.aol\\.com", Pattern.CASE_INSENSITIVE), "AOL");
        PROVIDER_PATTERNS.put(Pattern.compile(".*\\.zoho\\.com", Pattern.CASE_INSENSITIVE), "Zoho");
        PROVIDER_PATTERNS.put(Pattern.compile(".*\\.protonmail\\.ch", Pattern.CASE_INSENSITIVE), "ProtonMail");
        PROVIDER_PATTERNS.put(Pattern.compile(".*\\.gmx\\.", Pattern.CASE_INSENSITIVE), "GMX");
        PROVIDER_PATTERNS.put(Pattern.compile(".*\\.yandex\\.", Pattern.CASE_INSENSITIVE), "Yandex");
    }

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
        
        if (resultCache.size() > CACHE_MAX_SIZE) {
            logger.debug("Cache size limit reached, cleaning up expired results");
            resultCache.entrySet().removeIf(entry -> entry.getValue().isExpired());
            
            if (resultCache.size() > CACHE_MAX_SIZE * 0.9) {
                logger.debug("Removing oldest cache entries");
                final var entries = new ArrayList<>(resultCache.entrySet());
                entries.sort(Comparator.comparing(e -> e.getValue().getTimestamp()));
                
                final var toRemove = (int) (CACHE_MAX_SIZE * 0.2);
                for (int i = 0; i < toRemove && i < entries.size(); i++) {
                    resultCache.remove(entries.get(i).getKey());
                }
            }
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
            
            final var isCatchAll = checkDomainIsCatchAll(email, domain, mxHost);
            
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
            
            logger.debug("Performing SMTP verification for {} using MX host {}", email, mxHost);
            final var results = performConsensusVerification(localPart, domain, mxHost);
            
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

    private boolean checkDomainIsCatchAll(final String email, final String domain, final String mxHost) {
        final String domainKey = domain.toLowerCase();
        final Long lastCheckTime = domainLastCatchAllCheck.get(domainKey);
        final long currentTime = System.currentTimeMillis();
        
        if (lastCheckTime != null &&
            currentTime - lastCheckTime < CATCH_ALL_CACHE_EXPIRY_MS && 
            domainCatchAllStatus.containsKey(domainKey)) {
            
            logger.debug("Using cached catch-all status for domain {}: {}", 
                    domain, domainCatchAllStatus.get(domainKey));
            return domainCatchAllStatus.get(domainKey);
        }
        
        final boolean isCatchAll = detectCatchAll(email, domain, mxHost);
        
        domainLastCatchAllCheck.put(domainKey, currentTime);
        domainCatchAllStatus.put(domainKey, isCatchAll);
        
        if (domainLastCatchAllCheck.size() > CACHE_MAX_SIZE) {
            final long expiryThreshold = currentTime - CATCH_ALL_CACHE_EXPIRY_MS;
            domainLastCatchAllCheck.entrySet().removeIf(entry -> entry.getValue() < expiryThreshold);
        }
        
        return isCatchAll;
    }

    private boolean detectCatchAll(final String originalEmail, final String domain, final String mxHost) {
        try {
            logger.debug("Testing if domain {} is catch-all using server {}", domain, mxHost);
            
            final var parts = originalEmail.split("@", 2);
            final var invalidLocalPart = generateInvalidLocalPart(parts[0]);
            
            logger.debug("Catch-all test for domain {} using original '{}' and probe '{}'", 
                    domain, parts[0], invalidLocalPart);
            
            final var result = checkEmailViaSMTP(invalidLocalPart, domain, mxHost);
            
            if (result.getFullResponse() != null && result.getFullResponse().equals("Connection throttled")) {
                logger.debug("Catch-all test throttled for domain {}, unable to determine", domain);
                return false;
            }
            
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

    private List<SmtpValidationResult> performConsensusVerification(
            final String localPart, final String domain, final String mxHost) {
        
        final var results = new ArrayList<SmtpValidationResult>();
        logger.debug("Starting SMTP verification for {}@{} on MX host {}", localPart, domain, mxHost);
        
        for (int i = 0; i < VERIFICATION_ATTEMPTS; i++) {
            logger.debug("SMTP verification attempt #{} for {}@{} on MX host {}", i+1, localPart, domain, mxHost);
            final var result = checkEmailViaSMTP(localPart, domain, mxHost);
            
            if (result.isTempError()) {
                logger.debug("SMTP verification attempt #{} for {}@{} resulted in temporary error: {}", 
                        i+1, localPart, domain, result.getFullResponse());
                
                if (result.getFullResponse() != null && 
                    (result.getFullResponse().contains("rate") || 
                     result.getFullResponse().contains("limit") || 
                     result.getFullResponse().contains("throttl") ||
                     result.getFullResponse().contains("resource"))) {
                    logger.warn("Rate limiting detected for domain {}, backing off", domain);
                    
                    try {
                        Thread.sleep((i + 1) * 2000);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }
            } else {
                logger.debug("SMTP verification attempt #{} for {}@{} result: deliverable={}, response code={}, response={}", 
                        i+1, localPart, domain, result.isDeliverable(), result.getResponseCode(), result.getFullResponse());
                results.add(result);
            }
            
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        
        logger.debug("Completed SMTP verification for {}@{}: {} results collected", 
                localPart, domain, results.size());
        return results;
    }

    private SmtpValidationResult checkEmailViaSMTP(final String localPart, final String domain, final String mxHost) {
        Socket socket = null;
        PrintWriter out = null;
        BufferedReader in = null;
        
        logger.debug("Connecting to SMTP server {} for {}@{}", mxHost, localPart, domain);
        
        if (!acquireConnectionPermit(mxHost)) {
            logger.debug("Connection to {} throttled due to rate limiting", mxHost);
            return new SmtpValidationResult(false, false, 0, true, "Connection throttled", mxHost);
        }
        
        try {
            socket = new Socket();
            socket.connect(new InetSocketAddress(mxHost, SMTP_PORT), SOCKET_TIMEOUT_MS);
            socket.setSoTimeout(SOCKET_TIMEOUT_MS);
            
            out = new PrintWriter(socket.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            
            final var response = in.readLine();
            logger.debug("SMTP Initial Server Response ({}): {}", mxHost, response);
            
            if (response == null || !response.startsWith("2")) {
                return new SmtpValidationResult(false, false, getResponseCode(response), true);
            }
            
            out.println("HELO example.com");
            logger.debug("SMTP Sent ({}): HELO example.com", mxHost);
            
            final var heloResponse = in.readLine();
            logger.debug("SMTP HELO Response ({}): {}", mxHost, heloResponse);
            
            if (heloResponse == null || !heloResponse.startsWith("2")) {
                return new SmtpValidationResult(false, false, getResponseCode(heloResponse), true);
            }
            
            out.println("MAIL FROM:<validator@example.com>");
            logger.debug("SMTP Sent ({}): MAIL FROM:<validator@example.com>", mxHost);
            
            final var mailFromResponse = in.readLine();
            logger.debug("SMTP MAIL FROM Response ({}): {}", mxHost, mailFromResponse);
            
            if (mailFromResponse == null || !mailFromResponse.startsWith("2")) {
                return new SmtpValidationResult(false, false, getResponseCode(mailFromResponse), true);
            }
            
            out.println("RCPT TO:<" + localPart + "@" + domain + ">");
            logger.debug("SMTP Sent ({}): RCPT TO:<{}@{}>", mxHost, localPart, domain);
            
            final var rcptToResponse = in.readLine();
            logger.debug("SMTP RCPT TO Response ({}): {}", mxHost, rcptToResponse);
            
            final var isDeliverable = rcptToResponse != null && rcptToResponse.startsWith("2");
            final var responseCode = getResponseCode(rcptToResponse);
            
            final var isTempError = responseCode >= 400 && responseCode < 500;
            
            out.println("QUIT");
            logger.debug("SMTP Sent ({}): QUIT", mxHost);
            
            final var fullResponse = rcptToResponse != null ? rcptToResponse : "";
            
            if (isDeliverable) {
                logger.debug("SMTP verification DELIVERABLE for {}@{} on {}", localPart, domain, mxHost);
            } else if (isTempError) {
                logger.debug("SMTP verification TEMPORARY ERROR for {}@{} on {}", localPart, domain, mxHost);
            } else {
                logger.debug("SMTP verification UNDELIVERABLE for {}@{} on {}", localPart, domain, mxHost);
            }
            
            return new SmtpValidationResult(isDeliverable, false, responseCode, isTempError, fullResponse, mxHost);
            
        } catch (final Exception e) {
            logger.debug("SMTP connection error for {}@{} on {}: {}", localPart, domain, mxHost, e.getMessage());
            return new SmtpValidationResult(false, false, 0, true, e.getMessage(), mxHost);
        } finally {
            try {
                if (out != null) out.close();
                if (in != null) in.close();
                if (socket != null) socket.close();
                logger.debug("SMTP connection closed for {}@{} on {}", localPart, domain, mxHost);
            } catch (final Exception e) {
            }
            
            releaseConnectionPermit(mxHost);
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

        for (final var entry : PROVIDER_PATTERNS.entrySet()) {
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
    
    private String extractBaseDomain(final String domain) {
        if (domain == null) return "";
        
        final var matcher = DOMAIN_PATTERN.matcher(domain.toLowerCase());
        if (matcher.find()) {
            return matcher.group(1);
        }
        return domain.toLowerCase();
    }

    private boolean acquireConnectionPermit(final String domain) {
        final var baseDomain = extractBaseDomain(domain);
        
        try {
            if (!globalThrottler.tryAcquire(5, TimeUnit.SECONDS)) {
                logger.warn("Global SMTP connection limit reached, throttling connections");
                return false;
            }
            
            try {
                final var lastAccessTime = lastDomainAccessTime.get(baseDomain);
                if (lastAccessTime != null) {
                    final var timeSinceLastAccess = System.currentTimeMillis() - lastAccessTime.get();
                    if (timeSinceLastAccess < DOMAIN_THROTTLE_MS / 2) {
                        try {
                            Thread.sleep(50); // Brief pause to give other threads a chance
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                        }
                    }
                }
                
                final var lastAccess = lastGlobalAccessTime.get();
                final var timeSinceLastAccess = System.currentTimeMillis() - lastAccess;
                if (timeSinceLastAccess < GLOBAL_THROTTLE_MS) {
                    Thread.sleep(GLOBAL_THROTTLE_MS - timeSinceLastAccess);
                }
                lastGlobalAccessTime.set(System.currentTimeMillis());
                
                final var domainSemaphore = domainThrottlers.computeIfAbsent(
                    baseDomain, k -> new Semaphore(MAX_CONNECTIONS_PER_DOMAIN, true)
                );
                
                if (!domainSemaphore.tryAcquire(10, TimeUnit.SECONDS)) {
                    logger.warn("Domain {} connection limit reached, throttling connections", baseDomain);
                    globalThrottler.release();
                    return false;
                }
                
                final var domainLastAccessTime = lastDomainAccessTime.computeIfAbsent(
                    baseDomain, k -> new AtomicLong(0)
                );
                
                final var lastDomainAccess = domainLastAccessTime.get();
                final var timeSinceLastDomainAccess = System.currentTimeMillis() - lastDomainAccess;
                
                final var domainDelay = baseDomain.contains("gmail.com") ||
                                        baseDomain.contains("yahoo.com") || 
                                        baseDomain.contains("outlook.com") ||
                                        baseDomain.contains("hotmail.com") ? 
                                        DOMAIN_THROTTLE_MS * 1.5 : DOMAIN_THROTTLE_MS;
                
                if (timeSinceLastDomainAccess < domainDelay) {
                    logger.debug("Enforcing {} ms delay for domain {}, waiting {} ms", 
                            domainDelay, baseDomain, domainDelay - timeSinceLastDomainAccess);
                    Thread.sleep((long)(domainDelay - timeSinceLastDomainAccess));
                }
                
                domainLastAccessTime.set(System.currentTimeMillis());
                
                return true;
            } catch (final Exception e) {
                globalThrottler.release();
                logger.warn("Error during connection throttling for domain {}: {}", domain, e.getMessage());
                return false;
            }
        } catch (final Exception e) {
            logger.warn("Error acquiring global throttler: {}", e.getMessage());
            return false;
        }
    }
    
    private void releaseConnectionPermit(final String domain) {
        final var baseDomain = extractBaseDomain(domain);
        final var domainSemaphore = domainThrottlers.get(baseDomain);
        if (domainSemaphore != null) {
            domainSemaphore.release();
        }
        globalThrottler.release();
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
            return System.currentTimeMillis() - timestamp > TimeUnit.MINUTES.toMillis(CACHE_EXPIRY_MINUTES);
        }
    }
} 