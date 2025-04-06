package com.mikov.bulkemailchecker.dtos;

import com.mikov.bulkemailchecker.model.EmailVerificationResponse;
import java.util.concurrent.TimeUnit;

/**
 * Cache entry for email verification responses.
 * 
 * @author zahari.mikov
 */
public class EmailCacheEntry {
    private static final long CACHE_TTL_MS = TimeUnit.MINUTES.toMillis(30);
    
    private final long timestamp;
    private final EmailVerificationResponse response;
    
    public EmailCacheEntry(final EmailVerificationResponse response) {
        this.timestamp = System.currentTimeMillis();
        this.response = response;
    }
    
    public boolean isExpired() {
        return System.currentTimeMillis() - timestamp > CACHE_TTL_MS;
    }
    
    public EmailVerificationResponse getResponse() {
        return response;
    }
    
    public long getTimestamp() {
        return timestamp;
    }
} 