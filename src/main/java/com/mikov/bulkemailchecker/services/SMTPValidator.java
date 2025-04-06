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
import java.util.UUID;
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
    private static final int CATCH_ALL_PROBE_COUNT = 1;
    
    // Increased connection limits for better handling of concurrent requests
    private static final int MAX_CONNECTIONS_PER_DOMAIN = 3;  // Increased from 2
    private static final long DOMAIN_THROTTLE_MS = 2000;      // Reduced from 2500ms
    private static final long GLOBAL_THROTTLE_MS = 50;        // Reduced from 100ms
    
    private static final int CACHE_MAX_SIZE = 2000;           // Increased from 1000
    private static final long CACHE_EXPIRY_MINUTES = 60;      // Increased from 30
    
    // Domain grouping to reduce redundant SMTP connections
    private final ConcurrentHashMap<String, Long> domainLastCatchAllCheck = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Boolean> domainCatchAllStatus = new ConcurrentHashMap<>();
    private static final long CATCH_ALL_CACHE_EXPIRY_MS = TimeUnit.MINUTES.toMillis(30);
    
    // Domain-based rate limiting
    private final ConcurrentHashMap<String, Semaphore> domainThrottlers = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, AtomicLong> lastDomainAccessTime = new ConcurrentHashMap<>();
    private final Semaphore globalThrottler = new Semaphore(5, true); // Max 5 concurrent SMTP connections
    private final AtomicLong lastGlobalAccessTime = new AtomicLong(0);
    
    // Simple memory cache for validation results
    private final ConcurrentHashMap<String, CachedValidationResult> resultCache = new ConcurrentHashMap<>();
    
    // Domain extraction pattern to get base domain
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

    // List of providers that may have stricter rate limits or security
    // This ONLY affects throttling and catch-all detection, NOT validation logic
    private static final Set<String> RATE_LIMITED_PROVIDERS = new HashSet<>(Arrays.asList(
        "iphmx.com", "pphosted.com", "ppe-hosted.com", "messagelabs", "mimecast",
        "protection.outlook.com", "trustwave", "proofpoint", "google.com", "googlemail.com",
        "gmail.com", "aspmx.l.google.com", "mx.google.com", "alt1.aspmx.l.google.com", 
        "alt2.aspmx.l.google.com", "alt3.aspmx.l.google.com", "alt4.aspmx.l.google.com"
    ));
    
    // Common patterns that appear in accept-all domains
    private static final Set<String> ACCEPT_ALL_PATTERNS = new HashSet<>(Arrays.asList(
        ".mail.protection.outlook.com",
        ".protection.outlook.com",
        "pphosted.com",
        "messagelabs.com",
        "mimecast.com"
    ));
    
    private static final Random random = new Random();

    /**
     * Validate an email by checking MX records and SMTP server responses
     */
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
            
            // Check if catch-all, using the cached status when available
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
            
            // Domain is not catch-all, proceed with regular email validation
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

    /**
     * Method to check if a domain is catch-all, with result caching
     */
    private boolean checkDomainIsCatchAll(final String email, final String domain, final String mxHost) {
        final String domainKey = domain.toLowerCase();
        final Long lastCheckTime = domainLastCatchAllCheck.get(domainKey);
        final long currentTime = System.currentTimeMillis();
        
        // Use cached result if available and not expired
        if (lastCheckTime != null && 
            currentTime - lastCheckTime < CATCH_ALL_CACHE_EXPIRY_MS && 
            domainCatchAllStatus.containsKey(domainKey)) {
            
            logger.debug("Using cached catch-all status for domain {}: {}", 
                    domain, domainCatchAllStatus.get(domainKey));
            return domainCatchAllStatus.get(domainKey);
        }
        
        // Otherwise perform the actual check
        final boolean isCatchAll = detectCatchAll(email, domain, mxHost);
        
        // Cache the result
        domainLastCatchAllCheck.put(domainKey, currentTime);
        domainCatchAllStatus.put(domainKey, isCatchAll);
        
        // Manage cache size
        if (domainLastCatchAllCheck.size() > CACHE_MAX_SIZE) {
            // Clean up expired entries
            final long expiryThreshold = currentTime - CATCH_ALL_CACHE_EXPIRY_MS;
            domainLastCatchAllCheck.entrySet().removeIf(entry -> entry.getValue() < expiryThreshold);
        }
        
        return isCatchAll;
    }

    /**
     * Simple but effective catch-all detection method that tests if a deliberately
     * invalid version of the original email is accepted.
     */
    private boolean detectCatchAll(final String originalEmail, final String domain, final String mxHost) {
        try {
            logger.debug("Testing if domain {} is catch-all using server {}", domain, mxHost);
            
            // Generate invalid probe email by adding random suffix to the original local part
            final var parts = originalEmail.split("@", 2);
            final var invalidLocalPart = generateInvalidLocalPart(parts[0]);
            
            logger.debug("Catch-all test for domain {} using original '{}' and probe '{}'", 
                    domain, parts[0], invalidLocalPart);
            
            // Check if the server accepts this obviously invalid email
            final var result = checkEmailViaSMTP(invalidLocalPart, domain, mxHost);
            
            if (result.getFullResponse() != null && result.getFullResponse().equals("Connection throttled")) {
                logger.debug("Catch-all test throttled for domain {}, unable to determine", domain);
                return false; // Conservative approach: if throttled, assume not catch-all
            }
            
            logger.debug("Catch-all test result for probe {}: deliverable={}, response code={}, response={}", 
                    invalidLocalPart, result.isDeliverable(), result.getResponseCode(), result.getFullResponse());
            
            // If the invalid email is accepted, this is definitely a catch-all domain
            if (result.isDeliverable()) {
                logger.debug("Domain {} IS catch-all: accepted invalid email {}", domain, invalidLocalPart + "@" + domain);
                return true;
            }
            
            // If we get a definitive rejection with a 5xx code, not a catch-all
            if (!result.isDeliverable() && !result.isTempError() && result.getResponseCode() >= 500) {
                logger.debug("Domain {} is NOT catch-all: rejected invalid email {}", domain, invalidLocalPart + "@" + domain);
                return false;
            }
            
            // For ambiguous results (like temporary errors), err on the side of caution
            logger.debug("Catch-all test for domain {} was inconclusive, assuming not catch-all", domain);
            return false;

        } catch (final Exception e) {
            logger.warn("Error testing if domain {} is catch-all: {}", domain, e.getMessage());
            return false;
        }
    }
    
    /**
     * Creates an obviously invalid local part by adding random characters
     * to the original local part, ensuring it won't exist on any legitimate server.
     */
    private String generateInvalidLocalPart(final String originalLocalPart) {
        // Add a period and 8 random characters to the original local part
        // This ensures the probe email is related to the original but guaranteed to be invalid
        final var randomSuffix = getRandomString(8);
        return originalLocalPart + "." + randomSuffix;
    }
    
    /**
     * Generate a random string of specified length with lowercase letters
     */
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
    
    private boolean isDomainLikelyDeliverable(final String domain) {
        final var hasValidTld = domain.matches(".*\\.(com|org|net|io|co|edu|gov|mil|[a-z]{2})$");
        final var hasMultipleSegments = domain.split("\\.").length >= 2;
        final var looksRandom = domain.matches(".*[0-9]{4,}.*") || domain.length() > 30;
        return hasValidTld && hasMultipleSegments && !looksRandom;
    }
    
    private String identifyProviderFromDomain(final String domain) {
        if (domain.contains("gmail") || domain.contains("google")) {
            return "Google";
        } else if (domain.contains("outlook") || domain.contains("hotmail") || 
                   domain.contains("live") || domain.contains("office365") || 
                   domain.contains("microsoft")) {
            return "Microsoft";
        } else if (domain.contains("yahoo")) {
            return "Yahoo";
        } else if (domain.contains("protonmail")) {
            return "ProtonMail";
        } else if (domain.contains("zoho")) {
            return "Zoho";
        } else if (domain.contains("aol")) {
            return "AOL";
        } else if (domain.contains("gmx")) {
            return "GMX";
        } else if (domain.contains("yandex")) {
            return "Yandex";
        }
        
        final var parts = domain.split("\\.");
        if (parts.length >= 2) {
            return parts[parts.length - 2].substring(0, 1).toUpperCase() + 
                   parts[parts.length - 2].substring(1);
        }
        
        return "Unknown";
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
                Thread.sleep(1000); // Always wait 1 second between verification attempts
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        
        logger.debug("Completed SMTP verification for {}@{}: {} results collected", 
                localPart, domain, results.size());
        return results;
    }

    private String generateRandomUser(final String domain) {
        final var timestamp = String.valueOf(System.currentTimeMillis());
        final var domainHash = Integer.toHexString(domain.hashCode()).substring(0, 4);
        final var uuid = UUID.randomUUID().toString().substring(0, 8);
        
        return "nonexistent-user-" + uuid + "-" + timestamp + "-" + domainHash + "-zxygkwtpqs";
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
    
    private boolean isRateLimitedProvider(final String mxHost) {
        if (mxHost == null) return false;
        
        final var lowerHost = mxHost.toLowerCase();
        
        if (RATE_LIMITED_PROVIDERS.stream().anyMatch(lowerHost::contains)) {
            return true;
        }
        
        if (lowerHost.contains("google") || lowerHost.contains("gmail") || 
            lowerHost.contains("googlemail") || lowerHost.contains("aspmx")) {
            return true;
        }
        
        if (lowerHost.contains("protection") || lowerHost.contains("gateway") || 
            lowerHost.contains("filter") || lowerHost.contains("secure") ||
            lowerHost.contains("mail.protection")) {
            return true;
        }
        
        return false;
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
    
    /**
     * More efficient throttling that prioritizes access for domains without recent connections
     */
    private boolean acquireConnectionPermit(final String domain) {
        final var baseDomain = extractBaseDomain(domain);
        
        try {
            if (!globalThrottler.tryAcquire(5, TimeUnit.SECONDS)) {
                logger.warn("Global SMTP connection limit reached, throttling connections");
                return false;
            }
            
            try {
                // Prioritize domains that haven't been accessed recently
                final var lastAccessTime = lastDomainAccessTime.get(baseDomain);
                if (lastAccessTime != null) {
                    final var timeSinceLastAccess = System.currentTimeMillis() - lastAccessTime.get();
                    // If this domain was accessed very recently, give other domains a chance first
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
                
                // Use more targeted throttling based on domain usage patterns
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

    /**
     * Perform cleanup of throttling data structures periodically
     */
    public void cleanupThrottlingData() {
        final long currentTime = System.currentTimeMillis();
        final long expiryThreshold = currentTime - TimeUnit.MINUTES.toMillis(5);
        
        // Clean up domains that haven't been accessed in 5 minutes
        lastDomainAccessTime.entrySet().removeIf(entry -> 
            entry.getValue().get() < expiryThreshold
        );
        
        // Remove semaphores for unused domains
        domainThrottlers.entrySet().removeIf(entry -> 
            !lastDomainAccessTime.containsKey(entry.getKey())
        );
    }
} 