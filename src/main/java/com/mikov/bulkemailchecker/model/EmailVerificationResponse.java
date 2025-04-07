package com.mikov.bulkemailchecker.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;

import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

/**
 * Response model for email verification API
 */
@Getter
@JsonInclude(JsonInclude.Include.NON_NULL)
public class EmailVerificationResponse {

    private final String email;
    private final Boolean valid;
    private final String status;
    private final String resultCode;
    private final String message;
    private final Boolean hasMx;
    private final Boolean disposable;
    private final Boolean role;
    private final Boolean subAddressing;
    private final Boolean free;
    private final Boolean spam;
    private final String country;
    private final String smtpServer;
    private final String ipAddress;
    private final String additionalInfo;
    private final String event;
    private final String createdAt;
    private final Long responseTime;
    
    // New fields for retry mechanism
    private final String verificationId;
    private final String retryStatus;
    private final Long retryAfter;

    private EmailVerificationResponse(Builder builder) {
        this.email = builder.email;
        this.valid = builder.valid;
        this.status = builder.status;
        this.resultCode = builder.resultCode;
        this.message = builder.message;
        this.hasMx = builder.hasMx;
        this.disposable = builder.disposable;
        this.role = builder.role;
        this.subAddressing = builder.subAddressing;
        this.free = builder.free;
        this.spam = builder.spam;
        this.country = builder.country;
        this.smtpServer = builder.smtpServer;
        this.ipAddress = builder.ipAddress;
        this.additionalInfo = builder.additionalInfo;
        this.event = builder.event;
        this.createdAt = builder.createdAt;
        this.responseTime = builder.responseTime;
        this.verificationId = builder.verificationId;
        this.retryStatus = builder.retryStatus;
        this.retryAfter = builder.retryAfter;
    }
    
    /**
     * Create a response for a rate-limited email that is pending verification
     * @param email The email address
     * @param message Message explaining the pending status
     * @return EmailVerificationResponse with pending status
     */
    public static EmailVerificationResponse createPendingResponse(String email, String message) {
        return new Builder(email)
                .withStatus("pending")
                .withResultCode("pending")
                .withMessage(message)
                .withValid(null)
                .withVerificationId(UUID.randomUUID().toString())
                .withRetryStatus("queued")
                .withRetryAfter(System.currentTimeMillis() + 10000) // 10 seconds
                .build();
    }

    public static class Builder {
        private final String email;
        private Boolean valid;
        private String status;
        private String resultCode;
        private String message;
        private Boolean hasMx;
        private Boolean disposable;
        private Boolean role;
        private Boolean subAddressing;
        private Boolean free;
        private Boolean spam;
        private String country;
        private String smtpServer;
        private String ipAddress;
        private String additionalInfo;
        private String event;
        private String createdAt;
        private Long responseTime;
        private String verificationId;
        private String retryStatus;
        private Long retryAfter;

        public Builder(String email) {
            this.email = email;
        }

        public Builder withValid(Boolean valid) {
            this.valid = valid;
            return this;
        }

        public Builder withStatus(String status) {
            this.status = status;
            return this;
        }

        public Builder withResultCode(String resultCode) {
            this.resultCode = resultCode;
            return this;
        }

        public Builder withMessage(String message) {
            this.message = message;
            return this;
        }

        public Builder withHasMx(Boolean hasMx) {
            this.hasMx = hasMx;
            return this;
        }

        public Builder withDisposable(Boolean disposable) {
            this.disposable = disposable;
            return this;
        }

        public Builder withRole(Boolean role) {
            this.role = role;
            return this;
        }

        public Builder withSubAddressing(Boolean subAddressing) {
            this.subAddressing = subAddressing;
            return this;
        }

        public Builder withFree(Boolean free) {
            this.free = free;
            return this;
        }

        public Builder withSpam(Boolean spam) {
            this.spam = spam;
            return this;
        }

        public Builder withCountry(String country) {
            this.country = country;
            return this;
        }

        public Builder withSmtpServer(String smtpServer) {
            this.smtpServer = smtpServer;
            return this;
        }

        public Builder withIpAddress(String ipAddress) {
            this.ipAddress = ipAddress;
            return this;
        }

        public Builder withAdditionalInfo(String additionalInfo) {
            this.additionalInfo = additionalInfo;
            return this;
        }

        public Builder withEvent(String event) {
            this.event = event;
            return this;
        }

        public Builder withCreatedAt(String createdAt) {
            this.createdAt = createdAt;
            return this;
        }

        public Builder withResponseTime(Long responseTime) {
            this.responseTime = responseTime;
            return this;
        }
        
        public Builder withVerificationId(String verificationId) {
            this.verificationId = verificationId;
            return this;
        }
        
        public Builder withRetryStatus(String retryStatus) {
            this.retryStatus = retryStatus;
            return this;
        }
        
        public Builder withRetryAfter(Long retryAfter) {
            this.retryAfter = retryAfter;
            return this;
        }

        public EmailVerificationResponse build() {
            return new EmailVerificationResponse(this);
        }
    }
} 