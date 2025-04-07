package com.mikov.bulkemailchecker.model;

import com.mikov.bulkemailchecker.dtos.ValidationResult;
import java.util.Map;

/**
 * Stores the result of an email verification with timestamp information
 */
public class VerificationResult {
    private final String email;
    private final ValidationResult result;
    private final long timestamp;
    private final long processingTimeMs;
    
    public VerificationResult(String email, ValidationResult result, long processingTimeMs) {
        this.email = email;
        this.result = result;
        this.timestamp = System.currentTimeMillis();
        this.processingTimeMs = processingTimeMs;
    }
    
    public String getEmail() {
        return email;
    }
    
    public ValidationResult getResult() {
        return result;
    }
    
    public long getTimestamp() {
        return timestamp;
    }
    
    public long getProcessingTimeMs() {
        return processingTimeMs;
    }
    
    public Map<String, Object> toMap() {
        Map<String, Object> map = result.getDetails();
        map.put("email", email);
        map.put("valid", result.isValid());
        map.put("timestamp", timestamp);
        map.put("processingTime", processingTimeMs);
        return map;
    }
} 