package com.mikov.bulkemailchecker.cache;

import com.mikov.bulkemailchecker.model.EmailProviderResult;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class MxRecordCache {
    private final Map<String, CacheEntry> cache = new ConcurrentHashMap<>();
    private final long ttl;
    private final int maxSize;

    public MxRecordCache(long ttl, int maxSize) {
        this.ttl = ttl;
        this.maxSize = maxSize;
    }

    public EmailProviderResult get(String domain) {
        CacheEntry entry = cache.get(domain);
        if (entry != null && !isExpired(entry)) {
            return entry.result;
        }
        return null;
    }

    public void put(String domain, EmailProviderResult result) {
        if (cache.size() >= maxSize) {
            cleanup();
        }
        cache.put(domain, new CacheEntry(result, System.currentTimeMillis()));
    }

    private boolean isExpired(CacheEntry entry) {
        return System.currentTimeMillis() - entry.timestamp > ttl;
    }

    private void cleanup() {
        cache.entrySet().removeIf(entry -> isExpired(entry.getValue()));
        if (cache.size() >= maxSize) {
            cache.clear();
        }
    }

    private static class CacheEntry {
        private final EmailProviderResult result;
        private final long timestamp;

        public CacheEntry(EmailProviderResult result, long timestamp) {
            this.result = result;
            this.timestamp = timestamp;
        }
    }
} 