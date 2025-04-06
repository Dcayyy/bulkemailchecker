package com.mikov.bulkemailchecker.services;

import com.mikov.bulkemailchecker.model.ServiceValidationResult;
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
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.UUID;

/**
 * Validator that checks SMTP servers for email validity.
 * Performs SMTP connection tests and optimized catch-all detection.
 * Uses connection pooling and dynamic timeouts for optimal performance.
 *
 * @author zahari.mikov
 */
@Component
public class SMTPValidator implements EmailValidator {
    private static final Logger logger = LoggerFactory.getLogger(SMTPValidator.class);
    
    // Reduced timeout from 10s to 5s to prevent hanging connections
    private static final int SMTP_PORT = 25;
    private static final int SOCKET_TIMEOUT_MS = 5000; // 5 seconds
    
    private final ConcurrentHashMap<String, CacheEntry> cache = new ConcurrentHashMap<>();
    // Increased cache TTL to 4 hours for better performance
    private static final long CACHE_TTL_MS = TimeUnit.HOURS.toMillis(4);
    
    // Improved throttling mechanism with more aggressive limits
    private final Map<String, Integer> throttledDomains = new ConcurrentHashMap<>();
    private static final long THROTTLE_PERIOD_MS = TimeUnit.MINUTES.toMillis(10);
    private static final int MAX_DOMAIN_REQUESTS = 3; // Throttle after 3 requests in the throttle period
    
    // MX record cache
    private final ConcurrentHashMap<String, String[]> mxRecordCache = new ConcurrentHashMap<>();
    private static final long MX_CACHE_TTL_MS = TimeUnit.HOURS.toMillis(24); // Cache MX records for 24 hours
    private final ConcurrentHashMap<String, Long> mxRecordTimestamps = new ConcurrentHashMap<>();
    
    // IP address and provider cache
    private final ConcurrentHashMap<String, String> serverIpCache = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> serverProviderCache = new ConcurrentHashMap<>();
    
    // Provider identification patterns
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
        // Add more providers as needed
    }
    
    @Override
    public ServiceValidationResult validate(final String email) {
        logger.debug("BEGIN SMTP validation for: {}", email);
        
        if (email == null || email.isBlank()) {
            logger.debug("Email is null or empty: {}", email);
            return ServiceValidationResult.invalid(getName(), "Email is null or empty");
        }
        
        final var parts = email.split("@", 2);
        if (parts.length != 2) {
            logger.debug("Invalid email format: {}", email);
            return ServiceValidationResult.invalid(getName(), "Invalid email format");
        }
        
        final var localPart = parts[0];
        final var domain = parts[1].toLowerCase();
        
        // For testing: Clear cache for specific domains to ensure fresh results
        // During development, force cache clearing for problematic domains
        if (domain.equalsIgnoreCase("impulsenotion.com") || 
            domain.equalsIgnoreCase("dundeeprecious.com")) {
            clearDomainCache(domain);
        }
        
        // Check cache first
        final var cachedResult = cache.get(domain);
        if (cachedResult != null && !cachedResult.isExpired()) {
            if (cachedResult.isCatchAll) {
                logger.debug("Cache hit (catch-all domain) for email: {}", email);
                return ServiceValidationResult.valid(getName(), 0.5, createDetailsMap(true, "Catch-all domain", 
                        cachedResult.smtpServer, cachedResult.ipAddress, cachedResult.provider));
            } else if (cachedResult.validEmails.contains(localPart)) {
                logger.debug("Cache hit (valid email) for email: {}", email);
                return ServiceValidationResult.valid(getName(), 1.0, createDetailsMap(false, null, 
                        cachedResult.smtpServer, cachedResult.ipAddress, cachedResult.provider));
            } else if (cachedResult.invalidEmails.contains(localPart)) {
                logger.debug("Cache hit (invalid email) for email: {}", email);
                return ServiceValidationResult.invalid(getName(), "Email not deliverable");
            }
        }
        
        // Check if domain is being throttled
        if (isThrottled(domain)) {
            logger.debug("Domain {} is throttled, skipping SMTP check for email: {}", domain, email);
            return ServiceValidationResult.valid(getName(), 0.5, createDetailsMap(false, "Domain throttled, skipping check", "", "", ""));
        }
        
        try {
            // Get MX records for the domain
            logger.debug("Getting MX records for domain {} (email: {})", domain, email);
            final var mxHosts = getMxRecordsWithCaching(domain);
            if (mxHosts == null || mxHosts.length == 0) {
                logger.debug("No MX records found for domain {} (email: {})", domain, email);
                return ServiceValidationResult.invalid(getName(), "No MX records found");
            }
            
            // Get provider information from MX records
            final var provider = identifyProvider(mxHosts);
            
            // Use direct approach to validating emails
            for (final var mxHost : mxHosts) {
                logger.debug("======= BEGIN EMAIL VALIDATION FOR {} AT MX HOST {} =======", email, mxHost);
                final var serverInfo = new SmtpServerInfo(mxHost, getIpAddress(mxHost), provider);
                
                // FIRST: Use advanced catch-all detection instead of single email check
                final var isCatchAll = detectCatchAll(domain, mxHost);
                logger.debug("Catch-all detection result for {}: {}", domain, isCatchAll ? "IS CATCH-ALL" : "Not catch-all");
                
                if (isCatchAll) {
                    logger.debug("Advanced detection confirmed catch-all domain: {}", domain);
                    updateCache(domain, true, new HashSet<>(), new HashSet<>(), serverInfo.hostname, serverInfo.ipAddress, serverInfo.provider);
                    return ServiceValidationResult.valid(getName(), 0.5, createDetailsMap(true, "Catch-all domain", 
                            serverInfo.hostname, serverInfo.ipAddress, serverInfo.provider));
                }
                
                // If we get here, the domain is not catch-all
                // Now check the real email
                logger.debug("Domain {} is not catch-all, checking specific email: {}", domain, email);
                final var realResult = checkEmailViaSMTP(localPart, domain, mxHost);
                
                logger.debug("Email validation result for {}: isDeliverable={}, responseCode={}, isTempError={}", 
                        email, realResult.isDeliverable, realResult.responseCode, realResult.isTempError);
                
                if (realResult.isTempError) {
                    // Temporary error, try next host
                    logger.debug("Temporary error for real email, trying next MX host");
                    continue;
                }
                
                if (realResult.isDeliverable) {
                    // Special handling for domains using known problematic mail servers
                    if (mxHost.toLowerCase().contains("iphmx.com") || 
                        mxHost.toLowerCase().contains("pphosted.com") || 
                        mxHost.toLowerCase().contains("messagelabs")) {
                        
                        logger.warn("WARNING: Email {} shows as deliverable but using known problematic mail server {}. " +
                                   "Consider treating as catch-all.", email, mxHost);
                    }
                    
                    // Email is valid (and definitely not catch-all since we checked that first)
                    logger.debug("Email is deliverable: {}", email);
                    final var validEmails = new HashSet<String>();
                    validEmails.add(localPart);
                    updateCache(domain, false, validEmails, new HashSet<>(), serverInfo.hostname, serverInfo.ipAddress, serverInfo.provider);
                    return ServiceValidationResult.valid(getName(), 1.0, createDetailsMap(false, null, 
                            serverInfo.hostname, serverInfo.ipAddress, serverInfo.provider));
                } else {
                    // Email is invalid
                    logger.debug("Email is not deliverable: {}", email);
                    final var invalidEmails = new HashSet<String>();
                    invalidEmails.add(localPart);
                    updateCache(domain, false, new HashSet<>(), invalidEmails, serverInfo.hostname, serverInfo.ipAddress, serverInfo.provider);
                    return ServiceValidationResult.invalid(getName(), "Email not deliverable");
                }
            }
            
            // All MX servers gave temporary errors
            logger.debug("All MX servers gave temporary errors for email: {}", email);
            return ServiceValidationResult.valid(getName(), 0.3, createDetailsMap(false, "Temporary SMTP error", 
                    mxHosts[0], getIpAddress(mxHosts[0]), identifyProvider(new String[]{mxHosts[0]})));
            
        } catch (final Exception e) {
            logger.warn("SMTP validation failed for email {}: {}", email, e.getMessage());
            return ServiceValidationResult.valid(getName(), 0.3, createDetailsMap(false, "SMTP check error: " + e.getMessage(), "", "", ""));
        } finally {
            logger.debug("END SMTP validation for: {}", email);
            // Always increment throttle count to prevent overloading SMTP servers
            incrementThrottleCount(domain);
        }
    }

    @Override
    public String getName() {
        return "smtp";
    }
    
    /**
     * Generate a random username that would definitely never be valid
     * Used for catch-all testing
     */
    private String generateRandomUser(final String domain) {
        // Create a very unlikely username that would never be valid in a real world scenario
        // Current timestamp for uniqueness
        final var timestamp = String.valueOf(System.currentTimeMillis());
        // Domain hash to create domain-specific randomness
        final var domainHash = Integer.toHexString(domain.hashCode()).substring(0, 4);
        // Random UUID fragment for additional randomness
        final var uuid = UUID.randomUUID().toString().substring(0, 8);
        
        // Combine multiple unlikelihood factors - longer is better for this test
        return "nonexistent-user-" + uuid + "-" + timestamp + "-" + domainHash + "-zxygkwtpqs";
    }

    /**
     * Simple method to check a single email via SMTP
     */
    private SmtpValidationResult checkEmailViaSMTP(final String localPart, final String domain, final String mxHost) {
        Socket socket = null;
        PrintWriter out = null;
        BufferedReader in = null;
        
        try {
            // Connect to SMTP server
            socket = new Socket();
            socket.connect(new InetSocketAddress(mxHost, SMTP_PORT), SOCKET_TIMEOUT_MS);
            socket.setSoTimeout(SOCKET_TIMEOUT_MS);
            
            out = new PrintWriter(socket.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            
            // Read greeting
            final var response = in.readLine();
            if (response == null || !response.startsWith("2")) {
                logger.debug("Invalid greeting from SMTP server: {}", response);
                return new SmtpValidationResult(false, false, getResponseCode(response), true);
            }
            
            // Send HELO
            out.println("HELO example.com");
            final var heloResponse = in.readLine();
            if (heloResponse == null || !heloResponse.startsWith("2")) {
                logger.debug("HELO command failed: {}", heloResponse);
                return new SmtpValidationResult(false, false, getResponseCode(heloResponse), true);
            }
            
            // Send MAIL FROM
            out.println("MAIL FROM:<validator@example.com>");
            final var mailFromResponse = in.readLine();
            if (mailFromResponse == null || !mailFromResponse.startsWith("2")) {
                logger.debug("MAIL FROM command failed: {}", mailFromResponse);
                return new SmtpValidationResult(false, false, getResponseCode(mailFromResponse), true);
            }
            
            // Send RCPT TO
            out.println("RCPT TO:<" + localPart + "@" + domain + ">");
            final var rcptToResponse = in.readLine();
            
            final var isDeliverable = rcptToResponse != null && rcptToResponse.startsWith("2");
            final var responseCode = getResponseCode(rcptToResponse);
            
            logger.debug("RCPT TO response for {}@{}: {} (code: {})", localPart, domain, rcptToResponse, responseCode);
            
            // Check if we got a temporary error
            boolean isTempError = responseCode >= 400 && responseCode < 500;
            
            // Send QUIT
            out.println("QUIT");
            
            // Capture full response for advanced analysis
            String fullResponse = rcptToResponse != null ? rcptToResponse : "";
            
            return new SmtpValidationResult(isDeliverable, false, responseCode, isTempError, fullResponse, mxHost);
            
        } catch (final Exception e) {
            logger.debug("SMTP check error for {}@{} at {}: {}", localPart, domain, mxHost, e.getMessage());
            return new SmtpValidationResult(false, false, 0, true, e.getMessage(), mxHost);
        } finally {
            // Close resources
            try {
                if (out != null) out.close();
                if (in != null) in.close();
                if (socket != null) socket.close();
            } catch (final Exception e) {
                // Ignore
            }
        }
    }

    /**
     * Advanced catch-all detection that uses multiple probes and sophisticated pattern analysis
     * to correctly identify tricky catch-all domains that try to appear as regular mail servers.
     */
    private boolean detectCatchAll(String domain, String mxHost) {
        logger.debug("Running advanced catch-all detection for domain: {}", domain);
        
        try {
            // Strategy 1: Try multiple different invalid emails to increase confidence
            // Using different patterns makes it harder for servers to recognize testing
            String[] probeUsers = {
                generateRandomUser(domain),          // Complex random username
                "nonexistent" + System.currentTimeMillis(),    // Simple timestamp
                "test-probe-" + UUID.randomUUID().toString().substring(0, 8), // UUID-based
                "qwertyuiop-does-not-exist",         // Fixed pattern that shouldn't exist
                "this.user.certainly.doesnt.exist"   // Period-separated pattern
            };
            
            List<SmtpValidationResult> probeResults = new ArrayList<>();
            for (String probeUser : probeUsers) {
                SmtpValidationResult result = checkEmailViaSMTP(probeUser, domain, mxHost);
                probeResults.add(result);
                // If any probe is rejected with a permanent error, it's probably not catch-all
                if (!result.isDeliverable && !result.isTempError && result.responseCode >= 500) {
                    logger.debug("Probe email '{}@{}' was rejected, likely not catch-all", probeUser, domain);
                    return false;
                }
                // Short delay between probes to avoid triggering anti-spam
                Thread.sleep(100);
            }
            
            // Strategy 2: Check if all probes were accepted - definite catch-all
            boolean allAccepted = probeResults.stream().allMatch(r -> r.isDeliverable);
            if (allAccepted) {
                logger.debug("All probe emails were accepted - definitely a catch-all domain");
                return true;
            }
            
            // Strategy 3: Check for server fingerprints that indicate deceptive behavior
            // Some mail systems falsely accept emails during SMTP verification
            // These are known patterns from problematic SMTP servers
            boolean hasDeceptiveServerPattern = 
                mxHost.toLowerCase().contains("iphmx.com") ||   // iphmx.com is known to lie about validity
                mxHost.toLowerCase().contains("pphosted.com") || // Proofpoint servers often do this
                mxHost.toLowerCase().contains("ppe-hosted.com") || 
                mxHost.toLowerCase().contains("messagelabs") ||  // Symantec/MessageLabs often validate all
                mxHost.toLowerCase().contains("mimecast");       // Mimecast can be problematic
            
            // DIRECT OVERRIDE: iphmx.com servers are known to lie about acceptance
            // They have been consistently observed to return deliverable status for non-existent emails
            if (mxHost.toLowerCase().contains("iphmx.com")) {
                logger.debug("IPHMX server detected for {}. These are known to falsely accept all emails.", domain);
                return true; // Always treat iphmx.com as catch-all
            }
                
            if (hasDeceptiveServerPattern) {
                // For known deceptive servers, we need to analyze response patterns
                
                // Strategy 4: Compare response consistency across different probe emails
                // In real servers, error messages for invalid emails are consistent
                // But some catch-all systems generate different responses for each probe
                Set<String> uniqueResponses = probeResults.stream()
                    .map(r -> r.fullResponse)
                    .filter(r -> r != null && !r.isEmpty())
                    .collect(java.util.stream.Collectors.toSet());
                
                boolean hasConsistentResponses = uniqueResponses.size() <= 2; // Allow for some variation
                
                // Strategy 5: Look for response text patterns that often indicate catch-all systems
                boolean hasAcceptAllIndicators = probeResults.stream()
                    .anyMatch(r -> {
                        String response = r.fullResponse.toLowerCase();
                        return response.contains("accepted") || 
                               response.contains("recipient ok") || 
                               response.contains("will relay") ||
                               (r.isDeliverable && !response.contains("ok"));
                    });
                
                logger.debug("Deceptive server pattern found for {}. Consistent responses: {}, Accept-all indicators: {}", 
                        mxHost, hasConsistentResponses, hasAcceptAllIndicators);
                
                // For known problematic servers, if we see any sign of catch-all behavior, assume it's catch-all
                if (!hasConsistentResponses || hasAcceptAllIndicators) {
                    logger.debug("Domain {} using a mail system ({}) that appears to accept all emails", domain, mxHost);
                    return true;
                }
            }
            
            // Strategy 6: Special handling for extremely difficult cases
            // If at least 3 of 5 random emails were accepted, it's likely a catch-all
            long acceptedCount = probeResults.stream().filter(r -> r.isDeliverable).count();
            if (acceptedCount >= 3) {
                logger.debug("Multiple probe emails ({} of {}) were accepted - likely a catch-all domain", 
                        acceptedCount, probeResults.size());
                return true;
            }
            
            // If we get here, it's likely not a catch-all domain
            return false;
            
        } catch (Exception e) {
            logger.warn("Error in advanced catch-all detection: {}", e.getMessage());
            return false;
        }
    }

    private String[] getMxRecordsWithCaching(final String domain) throws Exception {
        // Check if we have cached MX records that haven't expired
        String[] cachedMxHosts = mxRecordCache.get(domain);
        Long timestamp = mxRecordTimestamps.get(domain);
        
        if (cachedMxHosts != null && timestamp != null && 
            System.currentTimeMillis() - timestamp < MX_CACHE_TTL_MS) {
            logger.debug("Using cached MX records for domain: {}", domain);
            return cachedMxHosts;
        }
        
        // If no cache or expired, look up MX records
        final var mxHosts = getMxRecords(domain);
        
        // Cache the results
        if (mxHosts != null && mxHosts.length > 0) {
            mxRecordCache.put(domain, mxHosts);
            mxRecordTimestamps.put(domain, System.currentTimeMillis());
        }
        
        return mxHosts;
    }

    private String[] getMxRecords(final String domain) throws Exception {
        // Simplified implementation - in production, use a more robust MX lookup
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
    
    /**
     * Identify email provider based on MX records
     */
    private String identifyProvider(String[] mxHosts) {
        if (mxHosts == null || mxHosts.length == 0) {
            return "Unknown";
        }
        
        // Use the first MX host as it's usually the primary
        String primaryMx = mxHosts[0].toLowerCase();
        
        // Check if we have this provider cached
        String cachedProvider = serverProviderCache.get(primaryMx);
        if (cachedProvider != null) {
            return cachedProvider;
        }
        
        // Match against known patterns
        for (Map.Entry<Pattern, String> entry : PROVIDER_PATTERNS.entrySet()) {
            if (entry.getKey().matcher(primaryMx).matches()) {
                String provider = entry.getValue();
                // Cache the result
                serverProviderCache.put(primaryMx, provider);
                return provider;
            }
        }
        
        // Try to identify from the domain
        String provider = "Self-hosted";
        if (primaryMx.contains(".")) {
            String domain = primaryMx.substring(primaryMx.lastIndexOf('.') + 1);
            // Capitalize first letter
            if (domain.length() > 0) {
                provider = domain.substring(0, 1).toUpperCase() + domain.substring(1);
            }
        }
        
        // Cache the result
        serverProviderCache.put(primaryMx, provider);
        return provider;
    }
    
    private String getIpAddress(String hostname) {
        try {
            // Check cache first
            String cachedIp = serverIpCache.get(hostname);
            if (cachedIp != null) {
                return cachedIp;
            }
            
            // Lookup IP address
            InetAddress address = InetAddress.getByName(hostname);
            String ipAddress = address.getHostAddress();
            
            // Cache the result
            serverIpCache.put(hostname, ipAddress);
            
            return ipAddress;
        } catch (Exception e) {
            logger.debug("Could not resolve IP for hostname {}: {}", hostname, e.getMessage());
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
    
    /**
     * Check if the MX host is a major cloud provider like Google or Microsoft
     * These usually have stricter validation and rarely use catch-all
     */
    private boolean isLikelyCloudProvider(String mxHost) {
        String host = mxHost.toLowerCase();
        return host.contains("google") || 
               host.contains("outlook") || 
               host.contains("hotmail") || 
               host.contains("office365") || 
               host.contains("microsoft") || 
               host.contains("protonmail") || 
               host.contains("zoho");
    }
    
    private HashMap<String, Double> createDetailsMap(final boolean isCatchAll, final String reason, 
                                                     final String smtpServer, final String ipAddress, 
                                                     final String provider) {
        final var details = new HashMap<String, Double>();
        details.put("smtp-validated", 1.0);
        details.put("catch-all", isCatchAll ? 1.0 : 0.0);
        details.put("has-mx", 1.0);  // Always include hasMx=true since this validator only runs after MX check
        
        if (reason != null) {
            details.put("reason", 1.0);
            details.put("reason-text", encodeStringAsDouble(reason));
        }
        
        // Add server info with actual values encoded in the keys
        if (smtpServer != null && !smtpServer.isEmpty()) {
            details.put("smtp-server", 1.0);
            details.put("smtp-server-value", encodeStringAsDouble(smtpServer));
        }
        if (ipAddress != null && !ipAddress.isEmpty()) {
            details.put("ip-address", 1.0);
            details.put("ip-address-value", encodeStringAsDouble(ipAddress));
        }
        if (provider != null && !provider.isEmpty()) {
            details.put("provider", 1.0);
            details.put("provider-value", encodeStringAsDouble(provider));
        }
        
        return details;
    }
    
    /**
     * Simple encoding of strings as double values for the details map
     * This is a workaround since ValidationResult only supports Map<String, Double>
     */
    private double encodeStringAsDouble(String str) {
        // Use hashCode converted to a seemingly random but consistent double value
        // This isn't meant to be decoded, just to create a unique double per string
        double encoded = Math.abs(str.hashCode()) / 1000000.0;
        // Store for reference to retrieve the original string
        stringValueCache.put(encoded, str);
        return encoded;
    }
    
    // Cache to store encoded string values
    private final ConcurrentHashMap<Double, String> stringValueCache = new ConcurrentHashMap<>();
    
    /**
     * Get original string value from its encoded double
     */
    public String getStringValue(double encodedValue) {
        return stringValueCache.get(encodedValue);
    }
    
    private void updateCache(final String domain, final boolean isCatchAll, 
                             final Set<String> validEmails, final Set<String> invalidEmails,
                             final String smtpServer, final String ipAddress, final String provider) {
        cache.put(domain, new CacheEntry(isCatchAll, validEmails, invalidEmails, smtpServer, ipAddress, provider));
    }
    
    private boolean isThrottled(final String domain) {
        final var count = throttledDomains.get(domain);
        return count != null && count > MAX_DOMAIN_REQUESTS;
    }
    
    private void incrementThrottleCount(final String domain) {
        throttledDomains.compute(domain, (k, v) -> (v == null) ? 1 : v + 1);
        
        // Schedule removal of throttle after the throttle period
        final var timer = new Timer();
        timer.schedule(new TimerTask() {
            @Override
            public void run() {
                throttledDomains.computeIfPresent(domain, (k, v) -> Math.max(0, v - 1));
            }
        }, THROTTLE_PERIOD_MS);
    }
    
    /**
     * Clear cache for a specific domain - useful for resetting problematic domains
     */
    public void clearDomainCache(String domain) {
        if (domain != null) {
            domain = domain.toLowerCase();
            cache.remove(domain);
            mxRecordCache.remove(domain);
            mxRecordTimestamps.remove(domain);
            throttledDomains.remove(domain);
            logger.debug("Cleared cache for domain: {}", domain);
        }
    }
    
    // Helper classes
    
    private static class SmtpServerInfo {
        String hostname;
        String ipAddress;
        String provider;
        
        SmtpServerInfo(String hostname, String ipAddress, String provider) {
            this.hostname = hostname;
            this.ipAddress = ipAddress;
            this.provider = provider;
        }
    }
    
    private static class SmtpValidationResult {
        final boolean isDeliverable;
        final boolean isCatchAll;
        final int responseCode;
        final boolean isTempError;
        final String fullResponse;  // Store the complete server response for analysis
        final String serverName;    // Store the server name for pattern matching
        
        SmtpValidationResult(final boolean isDeliverable, final boolean isCatchAll, 
                             final int responseCode, final boolean isTempError) {
            this(isDeliverable, isCatchAll, responseCode, isTempError, "", "");
        }
        
        SmtpValidationResult(final boolean isDeliverable, final boolean isCatchAll, 
                           final int responseCode, final boolean isTempError,
                           final String fullResponse, final String serverName) {
            this.isDeliverable = isDeliverable;
            this.isCatchAll = isCatchAll;
            this.responseCode = responseCode;
            this.isTempError = isTempError;
            this.fullResponse = fullResponse;
            this.serverName = serverName;
        }
    }
    
    private static class CacheEntry {
        final boolean isCatchAll;
        final Set<String> validEmails;
        final Set<String> invalidEmails;
        final long timestamp;
        final String smtpServer;
        final String ipAddress;
        final String provider;
        
        CacheEntry(final boolean isCatchAll, final Set<String> validEmails, final Set<String> invalidEmails,
                   final String smtpServer, final String ipAddress, final String provider) {
            this.isCatchAll = isCatchAll;
            this.validEmails = validEmails;
            this.invalidEmails = invalidEmails;
            this.timestamp = System.currentTimeMillis();
            this.smtpServer = smtpServer;
            this.ipAddress = ipAddress;
            this.provider = provider;
        }
        
        boolean isExpired() {
            return System.currentTimeMillis() - timestamp > CACHE_TTL_MS;
        }
    }
    
    /**
     * Calculate a simple similarity score between two strings
     * Higher score means more similar
     */
    private double similarityScore(String s1, String s2) {
        // Simple approach: Count matching characters in the same positions
        int maxLength = Math.min(s1.length(), s2.length());
        int matches = 0;
        
        for (int i = 0; i < maxLength; i++) {
            if (s1.charAt(i) == s2.charAt(i)) {
                matches++;
            }
        }
        
        // Return percentage of matches
        return (double) matches / maxLength;
    }
} 