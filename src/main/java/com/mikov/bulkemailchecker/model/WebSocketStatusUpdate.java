package com.mikov.bulkemailchecker.model;

import com.mikov.bulkemailchecker.model.EmailVerificationResponse;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * Model for WebSocket verification status updates
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class WebSocketStatusUpdate {
    
    /**
     * The session ID this update is for
     */
    private String sessionId;
    
    /**
     * Type of update
     */
    private UpdateType type;
    
    /**
     * Overall progress (0-100)
     */
    private int progress;
    
    /**
     * Status message
     */
    private String message;
    
    /**
     * Results for completed verifications
     */
    private List<EmailVerificationResponse> results;
    
    /**
     * Single result for individual email verification
     */
    private EmailVerificationResponse result;
    
    /**
     * Possible status update types
     */
    public enum UpdateType {
        // Session started
        STARTED,
        
        // Progress update
        PROGRESS,
        
        // Individual result available
        RESULT,
        
        // All processing complete
        COMPLETED,
        
        // Error occurred
        ERROR
    }
} 