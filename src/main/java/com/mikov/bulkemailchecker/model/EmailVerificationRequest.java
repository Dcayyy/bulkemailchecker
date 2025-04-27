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

    private String sessionId = UUID.randomUUID().toString();
    private String email;
    private List<String> emails;
    private String neverbounceApiKey;
} 