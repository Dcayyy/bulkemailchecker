package com.mikov.bulkemailchecker.services;

import com.mikov.bulkemailchecker.dtos.ValidationResult;
import com.mikov.bulkemailchecker.dtos.SmtpServerInfo;
import com.mikov.bulkemailchecker.dtos.SmtpValidationResult;
import com.mikov.bulkemailchecker.dtos.SmtpCacheEntry;
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
    
    private final ConcurrentHashMap<String, SmtpCacheEntry> cache = new ConcurrentHashMap<>();
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
    public ValidationResult validate(final String email) {
        // Only log email being checked
        logger.info("Checking email: {}", email);
        
        if (email == null || email.isBlank()) {
            return ValidationResult.invalid(getName(), "Email is null or empty");
        }
        
        final var parts = email.split("@", 2);
        if (parts.length != 2) {
            return ValidationResult.invalid(getName(), "Invalid email format");
        }
        
        final var localPart = parts[0];
        final var domain = parts[1].toLowerCase();

        if (domain.equalsIgnoreCase("impulsenotion.com") || 
            domain.equalsIgnoreCase("dundeeprecious.com")) {
            clearDomainCache(domain);
        }
        
        final var cachedResult = cache.get(domain);
        if (cachedResult != null && !cachedResult.isExpired()) {
            if (cachedResult.isCatchAll()) {
                return ValidationResult.valid(getName(), 0.5, createDetailsMap(true, "Catch-all domain", 
                        cachedResult.getSmtpServer(), cachedResult.getIpAddress(), cachedResult.getProvider()));
            } else if (cachedResult.getValidEmails().contains(localPart)) {
                return ValidationResult.valid(getName(), 1.0, createDetailsMap(false, null, 
                        cachedResult.getSmtpServer(), cachedResult.getIpAddress(), cachedResult.getProvider()));
            } else if (cachedResult.getInvalidEmails().contains(localPart)) {
                return ValidationResult.invalid(getName(), "Email not deliverable");
            }
        }
        
        if (isThrottled(domain)) {
            return ValidationResult.valid(getName(), 0.5, createDetailsMap(false, "Domain throttled, skipping check", "", "", ""));
        }
        
        try {
            final var mxHosts = getMxRecordsWithCaching(domain);
            if (mxHosts == null || mxHosts.length == 0) {
                return ValidationResult.invalid(getName(), "No MX records found");
            }
            
            final var provider = identifyProvider(mxHosts);
            
            for (final var mxHost : mxHosts) {
                final var serverInfo = new SmtpServerInfo(mxHost, getIpAddress(mxHost), provider);
                
                final var isCatchAll = detectCatchAll(domain, mxHost);
                
                if (isCatchAll) {
                    updateCache(domain, true, new HashSet<>(), new HashSet<>(), serverInfo.getHostname(), serverInfo.getIpAddress(), serverInfo.getProvider());
                    return ValidationResult.valid(getName(), 0.5, createDetailsMap(true, "Catch-all domain", 
                            serverInfo.getHostname(), serverInfo.getIpAddress(), serverInfo.getProvider()));
                }
                
                final var realResult = checkEmailViaSMTP(localPart, domain, mxHost);
                
                if (realResult.isTempError()) {
                    continue;
                }
                
                if (realResult.isDeliverable()) {
                    if (mxHost.toLowerCase().contains("iphmx.com") ||
                        mxHost.toLowerCase().contains("pphosted.com") || 
                        mxHost.toLowerCase().contains("messagelabs")) {
                        
                        logger.warn("Email {} using problematic mail server {}", email, mxHost);
                    }
                    
                    // Log the validation result
                    logger.info("Email validation result for {}: DELIVERABLE", email);
                    
                    final var validEmails = new HashSet<String>();
                    validEmails.add(localPart);
                    updateCache(domain, false, validEmails, new HashSet<>(), serverInfo.getHostname(), serverInfo.getIpAddress(), serverInfo.getProvider());
                    return ValidationResult.valid(getName(), 1.0, createDetailsMap(false, null, 
                            serverInfo.getHostname(), serverInfo.getIpAddress(), serverInfo.getProvider()));
                } else {
                    // Log the validation result
                    logger.info("Email validation result for {}: NOT DELIVERABLE", email);
                    
                    final var invalidEmails = new HashSet<String>();
                    invalidEmails.add(localPart);
                    updateCache(domain, false, new HashSet<>(), invalidEmails, serverInfo.getHostname(), serverInfo.getIpAddress(), serverInfo.getProvider());
                    return ValidationResult.invalid(getName(), "Email not deliverable");
                }
            }
            
            return ValidationResult.valid(getName(), 0.3, createDetailsMap(false, "Temporary SMTP error", 
                    mxHosts[0], getIpAddress(mxHosts[0]), identifyProvider(new String[]{mxHosts[0]})));
            
        } catch (final Exception e) {
            logger.warn("SMTP validation failed for email {}: {}", email, e.getMessage());
            return ValidationResult.valid(getName(), 0.3, createDetailsMap(false, "SMTP check error: " + e.getMessage(), "", "", ""));
        } finally {
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
                return new SmtpValidationResult(false, false, getResponseCode(response), true);
            }
            
            out.println("HELO example.com");
            final var heloResponse = in.readLine();
            if (heloResponse == null || !heloResponse.startsWith("2")) {
                return new SmtpValidationResult(false, false, getResponseCode(heloResponse), true);
            }
            
            out.println("MAIL FROM:<validator@example.com>");
            final var mailFromResponse = in.readLine();
            if (mailFromResponse == null || !mailFromResponse.startsWith("2")) {
                return new SmtpValidationResult(false, false, getResponseCode(mailFromResponse), true);
            }
            
            out.println("RCPT TO:<" + localPart + "@" + domain + ">");
            final var rcptToResponse = in.readLine();
            
            final var isDeliverable = rcptToResponse != null && rcptToResponse.startsWith("2");
            final var responseCode = getResponseCode(rcptToResponse);
            
            boolean isTempError = responseCode >= 400 && responseCode < 500;
            out.println("QUIT");
            String fullResponse = rcptToResponse != null ? rcptToResponse : "";
            
            return new SmtpValidationResult(isDeliverable, false, responseCode, isTempError, fullResponse, mxHost);
            
        } catch (final Exception e) {
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
                if (!result.isDeliverable() && !result.isTempError() && result.getResponseCode() >= 500) {
                    return false;
                }
                Thread.sleep(100);
            }
            
            boolean allAccepted = probeResults.stream().allMatch(r -> r.isDeliverable());
            if (allAccepted) {
                return true;
            }

            boolean hasDeceptiveServerPattern = 
                mxHost.toLowerCase().contains("iphmx.com") ||
                mxHost.toLowerCase().contains("pphosted.com") ||
                mxHost.toLowerCase().contains("ppe-hosted.com") || 
                mxHost.toLowerCase().contains("messagelabs") ||
                mxHost.toLowerCase().contains("mimecast");

            if (mxHost.toLowerCase().contains("iphmx.com")) {
                return true; // Always treat iphmx.com as catch-all
            }
                
            if (hasDeceptiveServerPattern) {
                Set<String> uniqueResponses = probeResults.stream()
                    .map(r -> r.getFullResponse())
                    .filter(r -> r != null && !r.isEmpty())
                    .collect(java.util.stream.Collectors.toSet());
                
                boolean hasConsistentResponses = uniqueResponses.size() <= 2;
                boolean hasAcceptAllIndicators = probeResults.stream()
                    .anyMatch(r -> {
                        String response = r.getFullResponse().toLowerCase();
                        return response.contains("accepted") || 
                               response.contains("recipient ok") || 
                               response.contains("will relay") ||
                               (r.isDeliverable() && !response.contains("ok"));
                    });

                if (!hasConsistentResponses || hasAcceptAllIndicators) {
                    return true;
                }
            }

            long acceptedCount = probeResults.stream().filter(r -> r.isDeliverable()).count();
            if (acceptedCount >= 3) {
                return true;
            }

            return false;
            
        } catch (Exception e) {
            return false;
        }
    }

    private String[] getMxRecordsWithCaching(final String domain) throws Exception {
        String[] cachedMxHosts = mxRecordCache.get(domain);
        Long timestamp = mxRecordTimestamps.get(domain);
        
        if (cachedMxHosts != null && timestamp != null && 
            System.currentTimeMillis() - timestamp < MX_CACHE_TTL_MS) {
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
        cache.put(domain, new SmtpCacheEntry(isCatchAll, validEmails, invalidEmails, smtpServer, ipAddress, provider));
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
        }
    }
} 