package com.mikov.bulkemailchecker.dtos;

import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Cache entry for SMTP validation results.
 * 
 * @author zahari.mikov
 */
public class SmtpCacheEntry {
    private static final long CACHE_TTL_MS = TimeUnit.HOURS.toMillis(4);
    
    private final boolean catchAll;
    private final Set<String> validEmails;
    private final Set<String> invalidEmails;
    private final long timestamp;
    private final String smtpServer;
    private final String ipAddress;
    private final String provider;
    
    public SmtpCacheEntry(final boolean catchAll, final Set<String> validEmails, final Set<String> invalidEmails,
               final String smtpServer, final String ipAddress, final String provider) {
        this.catchAll = catchAll;
        this.validEmails = validEmails;
        this.invalidEmails = invalidEmails;
        this.timestamp = System.currentTimeMillis();
        this.smtpServer = smtpServer;
        this.ipAddress = ipAddress;
        this.provider = provider;
    }
    
    public boolean isExpired() {
        return System.currentTimeMillis() - timestamp > CACHE_TTL_MS;
    }
    
    public boolean isCatchAll() {
        return catchAll;
    }
    
    public Set<String> getValidEmails() {
        return validEmails;
    }
    
    public Set<String> getInvalidEmails() {
        return invalidEmails;
    }
    
    public long getTimestamp() {
        return timestamp;
    }
    
    public String getSmtpServer() {
        return smtpServer;
    }
    
    public String getIpAddress() {
        return ipAddress;
    }
    
    public String getProvider() {
        return provider;
    }
} 