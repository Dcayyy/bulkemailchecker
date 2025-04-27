package com.mikov.bulkemailchecker.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.UUID;

/**
 * Model for WebSocket email verification requests
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class EmailVerificationRequest {
    
    /**
     * Unique session ID to track this websocket verification session
     */
    private String sessionId = UUID.randomUUID().toString();
    
    /**
     * Single email to verify
     */
    private String email;
    
    /**
     * List of emails for batch verification
     */
    private List<String> emails;
    
    /**
     * Neverbounce API key
     */
    private String neverbounceApiKey;
} 