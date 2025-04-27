package com.mikov.bulkemailchecker.model;

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

    private String sessionId;
    private UpdateType type;
    private int progress;
    private String message;
    private List<EmailVerificationResponse> results;
    private EmailVerificationResponse result;
    public enum UpdateType {
        STARTED,
        PROGRESS,
        RESULT,
        COMPLETED,
        ERROR
    }
} 