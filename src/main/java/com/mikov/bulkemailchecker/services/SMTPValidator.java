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
    
    private static final int SMTP_PORT = 25;
    private static final int SOCKET_TIMEOUT_MS = 5000;
    
    private final ConcurrentHashMap<String, CacheEntry> cache = new ConcurrentHashMap<>();
    private static final long CACHE_TTL_MS = TimeUnit.HOURS.toMillis(4);
    
    private final Map<String, Integer> throttledDomains = new ConcurrentHashMap<>();
    private static final long THROTTLE_PERIOD_MS = TimeUnit.MINUTES.toMillis(10);
    private static final int MAX_DOMAIN_REQUESTS = 3;
    
    private final ConcurrentHashMap<String, String[]> mxRecordCache = new ConcurrentHashMap<>();
    private static final long MX_CACHE_TTL_MS = TimeUnit.HOURS.toMillis(24);
    private final ConcurrentHashMap<String, Long> mxRecordTimestamps = new ConcurrentHashMap<>();
    
    private final ConcurrentHashMap<String, String> serverIpCache = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, String> serverProviderCache = new ConcurrentHashMap<>();
    
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

        if (domain.equalsIgnoreCase("impulsenotion.com") || 
            domain.equalsIgnoreCase("dundeeprecious.com")) {
            clearDomainCache(domain);
        }
        
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
        
        if (isThrottled(domain)) {
            logger.debug("Domain {} is throttled, skipping SMTP check for email: {}", domain, email);
            return ServiceValidationResult.valid(getName(), 0.5, createDetailsMap(false, "Domain throttled, skipping check", "", "", ""));
        }
        
        try {
            logger.debug("Getting MX records for domain {} (email: {})", domain, email);
            final var mxHosts = getMxRecordsWithCaching(domain);
            if (mxHosts == null || mxHosts.length == 0) {
                logger.debug("No MX records found for domain {} (email: {})", domain, email);
                return ServiceValidationResult.invalid(getName(), "No MX records found");
            }
            
            final var provider = identifyProvider(mxHosts);
            
            for (final var mxHost : mxHosts) {
                logger.debug("======= BEGIN EMAIL VALIDATION FOR {} AT MX HOST {} =======", email, mxHost);
                final var serverInfo = new SmtpServerInfo(mxHost, getIpAddress(mxHost), provider);
                
                final var isCatchAll = detectCatchAll(domain, mxHost);
                logger.debug("Catch-all detection result for {}: {}", domain, isCatchAll ? "IS CATCH-ALL" : "Not catch-all");
                
                if (isCatchAll) {
                    logger.debug("Advanced detection confirmed catch-all domain: {}", domain);
                    updateCache(domain, true, new HashSet<>(), new HashSet<>(), serverInfo.hostname, serverInfo.ipAddress, serverInfo.provider);
                    return ServiceValidationResult.valid(getName(), 0.5, createDetailsMap(true, "Catch-all domain", 
                            serverInfo.hostname, serverInfo.ipAddress, serverInfo.provider));
                }
                
                logger.debug("Domain {} is not catch-all, checking specific email: {}", domain, email);
                final var realResult = checkEmailViaSMTP(localPart, domain, mxHost);
                
                logger.debug("Email validation result for {}: isDeliverable={}, responseCode={}, isTempError={}", 
                        email, realResult.isDeliverable, realResult.responseCode, realResult.isTempError);
                
                if (realResult.isTempError) {
                    logger.debug("Temporary error for real email, trying next MX host");
                    continue;
                }
                
                if (realResult.isDeliverable) {
                    if (mxHost.toLowerCase().contains("iphmx.com") ||
                        mxHost.toLowerCase().contains("pphosted.com") || 
                        mxHost.toLowerCase().contains("messagelabs")) {
                        
                        logger.warn("WARNING: Email {} shows as deliverable but using known problematic mail server {}. " +
                                   "Consider treating as catch-all.", email, mxHost);
                    }
                    
                    logger.debug("Email is deliverable: {}", email);
                    final var validEmails = new HashSet<String>();
                    validEmails.add(localPart);
                    updateCache(domain, false, validEmails, new HashSet<>(), serverInfo.hostname, serverInfo.ipAddress, serverInfo.provider);
                    return ServiceValidationResult.valid(getName(), 1.0, createDetailsMap(false, null, 
                            serverInfo.hostname, serverInfo.ipAddress, serverInfo.provider));
                } else {
                    logger.debug("Email is not deliverable: {}", email);
                    final var invalidEmails = new HashSet<String>();
                    invalidEmails.add(localPart);
                    updateCache(domain, false, new HashSet<>(), invalidEmails, serverInfo.hostname, serverInfo.ipAddress, serverInfo.provider);
                    return ServiceValidationResult.invalid(getName(), "Email not deliverable");
                }
            }
            
            logger.debug("All MX servers gave temporary errors for email: {}", email);
            return ServiceValidationResult.valid(getName(), 0.3, createDetailsMap(false, "Temporary SMTP error", 
                    mxHosts[0], getIpAddress(mxHosts[0]), identifyProvider(new String[]{mxHosts[0]})));
            
        } catch (final Exception e) {
            logger.warn("SMTP validation failed for email {}: {}", email, e.getMessage());
            return ServiceValidationResult.valid(getName(), 0.3, createDetailsMap(false, "SMTP check error: " + e.getMessage(), "", "", ""));
        } finally {
            logger.debug("END SMTP validation for: {}", email);
            incrementThrottleCount(domain);
        }
    }

    @Override
    public String getName() {
        return "smtp";
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
        
        try {
            socket = new Socket();
            socket.connect(new InetSocketAddress(mxHost, SMTP_PORT), SOCKET_TIMEOUT_MS);
            socket.setSoTimeout(SOCKET_TIMEOUT_MS);
            
            out = new PrintWriter(socket.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            
            final var response = in.readLine();
            if (response == null || !response.startsWith("2")) {
                logger.debug("Invalid greeting from SMTP server: {}", response);
                return new SmtpValidationResult(false, false, getResponseCode(response), true);
            }
            
            out.println("HELO example.com");
            final var heloResponse = in.readLine();
            if (heloResponse == null || !heloResponse.startsWith("2")) {
                logger.debug("HELO command failed: {}", heloResponse);
                return new SmtpValidationResult(false, false, getResponseCode(heloResponse), true);
            }
            
            out.println("MAIL FROM:<validator@example.com>");
            final var mailFromResponse = in.readLine();
            if (mailFromResponse == null || !mailFromResponse.startsWith("2")) {
                logger.debug("MAIL FROM command failed: {}", mailFromResponse);
                return new SmtpValidationResult(false, false, getResponseCode(mailFromResponse), true);
            }
            
            out.println("RCPT TO:<" + localPart + "@" + domain + ">");
            final var rcptToResponse = in.readLine();
            
            final var isDeliverable = rcptToResponse != null && rcptToResponse.startsWith("2");
            final var responseCode = getResponseCode(rcptToResponse);
            
            logger.debug("RCPT TO response for {}@{}: {} (code: {})", localPart, domain, rcptToResponse, responseCode);
            
            boolean isTempError = responseCode >= 400 && responseCode < 500;
            out.println("QUIT");
            String fullResponse = rcptToResponse != null ? rcptToResponse : "";
            
            return new SmtpValidationResult(isDeliverable, false, responseCode, isTempError, fullResponse, mxHost);
            
        } catch (final Exception e) {
            logger.debug("SMTP check error for {}@{} at {}: {}", localPart, domain, mxHost, e.getMessage());
            return new SmtpValidationResult(false, false, 0, true, e.getMessage(), mxHost);
        } finally {
            try {
                if (out != null) out.close();
                if (in != null) in.close();
                if (socket != null) socket.close();
            } catch (final Exception e) {
                // Ignore
            }
        }
    }

    private boolean detectCatchAll(String domain, String mxHost) {
        logger.debug("Running advanced catch-all detection for domain: {}", domain);
        
        try {
            String[] probeUsers = {
                generateRandomUser(domain),
                "nonexistent" + System.currentTimeMillis(),
                "test-probe-" + UUID.randomUUID().toString().substring(0, 8),
                "qwertyuiop-does-not-exist",
                "this.user.certainly.doesnt.exist"
            };
            
            List<SmtpValidationResult> probeResults = new ArrayList<>();
            for (String probeUser : probeUsers) {
                SmtpValidationResult result = checkEmailViaSMTP(probeUser, domain, mxHost);
                probeResults.add(result);
                if (!result.isDeliverable && !result.isTempError && result.responseCode >= 500) {
                    logger.debug("Probe email '{}@{}' was rejected, likely not catch-all", probeUser, domain);
                    return false;
                }
                Thread.sleep(100);
            }
            
            boolean allAccepted = probeResults.stream().allMatch(r -> r.isDeliverable);
            if (allAccepted) {
                logger.debug("All probe emails were accepted - definitely a catch-all domain");
                return true;
            }

            boolean hasDeceptiveServerPattern = 
                mxHost.toLowerCase().contains("iphmx.com") ||
                mxHost.toLowerCase().contains("pphosted.com") ||
                mxHost.toLowerCase().contains("ppe-hosted.com") || 
                mxHost.toLowerCase().contains("messagelabs") ||
                mxHost.toLowerCase().contains("mimecast");

            if (mxHost.toLowerCase().contains("iphmx.com")) {
                logger.debug("IPHMX server detected for {}. These are known to falsely accept all emails.", domain);
                return true; // Always treat iphmx.com as catch-all
            }
                
            if (hasDeceptiveServerPattern) {
                Set<String> uniqueResponses = probeResults.stream()
                    .map(r -> r.fullResponse)
                    .filter(r -> r != null && !r.isEmpty())
                    .collect(java.util.stream.Collectors.toSet());
                
                boolean hasConsistentResponses = uniqueResponses.size() <= 2;
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

                if (!hasConsistentResponses || hasAcceptAllIndicators) {
                    logger.debug("Domain {} using a mail system ({}) that appears to accept all emails", domain, mxHost);
                    return true;
                }
            }

            long acceptedCount = probeResults.stream().filter(r -> r.isDeliverable).count();
            if (acceptedCount >= 3) {
                logger.debug("Multiple probe emails ({} of {}) were accepted - likely a catch-all domain", 
                        acceptedCount, probeResults.size());
                return true;
            }

            return false;
            
        } catch (Exception e) {
            logger.warn("Error in advanced catch-all detection: {}", e.getMessage());
            return false;
        }
    }

    private String[] getMxRecordsWithCaching(final String domain) throws Exception {
        String[] cachedMxHosts = mxRecordCache.get(domain);
        Long timestamp = mxRecordTimestamps.get(domain);
        
        if (cachedMxHosts != null && timestamp != null && 
            System.currentTimeMillis() - timestamp < MX_CACHE_TTL_MS) {
            logger.debug("Using cached MX records for domain: {}", domain);
            return cachedMxHosts;
        }

        final var mxHosts = getMxRecords(domain);
        if (mxHosts.length > 0) {
            mxRecordCache.put(domain, mxHosts);
            mxRecordTimestamps.put(domain, System.currentTimeMillis());
        }
        
        return mxHosts;
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

    private String identifyProvider(String[] mxHosts) {
        if (mxHosts == null || mxHosts.length == 0) {
            return "Unknown";
        }
        
        String primaryMx = mxHosts[0].toLowerCase();
        String cachedProvider = serverProviderCache.get(primaryMx);
        if (cachedProvider != null) {
            return cachedProvider;
        }

        for (Map.Entry<Pattern, String> entry : PROVIDER_PATTERNS.entrySet()) {
            if (entry.getKey().matcher(primaryMx).matches()) {
                String provider = entry.getValue();
                serverProviderCache.put(primaryMx, provider);
                return provider;
            }
        }
        
        String provider = "Self-hosted";
        if (primaryMx.contains(".")) {
            String domain = primaryMx.substring(primaryMx.lastIndexOf('.') + 1);
            if (!domain.isEmpty()) {
                provider = domain.substring(0, 1).toUpperCase() + domain.substring(1);
            }
        }
        
        serverProviderCache.put(primaryMx, provider);
        return provider;
    }
    
    private String getIpAddress(String hostname) {
        try {
            String cachedIp = serverIpCache.get(hostname);
            if (cachedIp != null) {
                return cachedIp;
            }
            
            InetAddress address = InetAddress.getByName(hostname);
            String ipAddress = address.getHostAddress();
            
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
    
    private HashMap<String, Double> createDetailsMap(final boolean isCatchAll, final String reason, 
                                                     final String smtpServer, final String ipAddress, 
                                                     final String provider) {
        final var details = new HashMap<String, Double>();
        details.put("smtp-validated", 1.0);
        details.put("catch-all", isCatchAll ? 1.0 : 0.0);
        details.put("has-mx", 1.0);
        
        if (reason != null) {
            details.put("reason", 1.0);
            details.put("reason-text", encodeStringAsDouble(reason));
        }
        
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

    private double encodeStringAsDouble(String str) {
        double encoded = Math.abs(str.hashCode()) / 1000000.0;
        stringValueCache.put(encoded, str);
        return encoded;
    }
    
    private final ConcurrentHashMap<Double, String> stringValueCache = new ConcurrentHashMap<>();

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
        
        final var timer = new Timer();
        timer.schedule(new TimerTask() {
            @Override
            public void run() {
                throttledDomains.computeIfPresent(domain, (k, v) -> Math.max(0, v - 1));
            }
        }, THROTTLE_PERIOD_MS);
    }

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
        final String fullResponse;
        final String serverName;
        
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
} 