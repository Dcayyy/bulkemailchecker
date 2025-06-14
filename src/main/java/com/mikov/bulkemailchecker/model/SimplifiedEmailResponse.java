package com.mikov.bulkemailchecker.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Getter;

/**
 * Simplified response model for email verification API with only the essential fields.
 */
@Getter
@JsonInclude(JsonInclude.Include.NON_NULL)
public class SimplifiedEmailResponse {

    private final String email;
    private final Boolean valid;
    private final String status;
    private final String createdAt;

    private SimplifiedEmailResponse(String email, Boolean valid, String status, String createdAt) {
        this.email = email;
        this.valid = valid;
        this.status = status;
        this.createdAt = createdAt;
    }

    public static SimplifiedEmailResponse from(EmailVerificationResponse response) {
        String simplifiedStatus;
        
        if (response.getStatus() != null && response.getStatus().equals("catch-all")) {
            simplifiedStatus = "catch-all";
        } else if (response.getStatus() != null && response.getStatus().equals("error")) {
            simplifiedStatus = response.getMessage();
        } else if (response.getValid() != null && response.getValid()) {
            simplifiedStatus = "deliverable";
        } else {
            simplifiedStatus = "undeliverable";
        }
        
        return new SimplifiedEmailResponse(
            response.getEmail(),
            response.getValid(),
            simplifiedStatus,
            response.getCreatedAt()
        );
    }
} 