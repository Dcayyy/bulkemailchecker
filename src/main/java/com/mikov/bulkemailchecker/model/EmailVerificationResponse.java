package com.mikov.bulkemailchecker.model;

import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

/**
 * Response model for email verification that matches BulkEmailChecker format
 * 
 * @author zahari.mikov
 */
public class EmailVerificationResponse {
    private final long id;
    private final String email;
    private final String status;
    private final boolean valid;
    private final String domain;
    private final String localPart;
    private final String resultCode;
    private final String message;
    private final String additionalInfo;
    private final boolean subAddressing;
    private final boolean disposable;
    private final boolean role;
    private final boolean free;
    private final boolean spam;
    private final boolean hasMx;
    private final String smtpServer;
    private final String ipAddress;
    private final String country;
    private final String checkedAt;
    private final long responseTime;
    private final String createdAt;
    private final int retries;
    
    private EmailVerificationResponse(final Builder builder) {
        this.id = builder.id;
        this.email = builder.email;
        this.status = builder.status;
        this.valid = builder.valid;
        this.domain = builder.domain;
        this.localPart = builder.localPart;
        this.resultCode = builder.resultCode;
        this.message = builder.message;
        this.additionalInfo = builder.additionalInfo;
        this.subAddressing = builder.subAddressing;
        this.disposable = builder.disposable;
        this.role = builder.role;
        this.free = builder.free;
        this.spam = builder.spam;
        this.hasMx = builder.hasMx;
        this.smtpServer = builder.smtpServer;
        this.ipAddress = builder.ipAddress;
        this.country = builder.country;
        this.checkedAt = builder.checkedAt;
        this.responseTime = builder.responseTime;
        this.createdAt = builder.createdAt;
        this.retries = builder.retries;
    }
    
    public static class Builder {
        private long id = System.currentTimeMillis();
        private String email;
        private String status = "unknown";
        private boolean valid = false;
        private String domain;
        private String localPart;
        private String resultCode = "verification_failed";
        private String message = "Failed to verify email";
        private String additionalInfo = "";
        private boolean subAddressing = false;
        private boolean disposable = false;
        private boolean role = false;
        private boolean free = false;
        private boolean spam = false;
        private boolean hasMx = false;
        private String smtpServer = "";
        private String ipAddress = "";
        private String country = "";
        private String checkedAt = OffsetDateTime.now().format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
        private long responseTime = 0;
        private String createdAt = OffsetDateTime.now().toString();
        private int retries = 0;
        
        public Builder(final String email) {
            this.email = email;
            if (email != null && email.contains("@")) {
                final var parts = email.split("@", 2);
                this.localPart = parts[0];
                this.domain = parts[1];
            }
        }
        
        public Builder withId(final long id) {
            this.id = id;
            return this;
        }
        
        public Builder withStatus(final String status) {
            this.status = status;
            return this;
        }
        
        public Builder withValid(final boolean valid) {
            this.valid = valid;
            return this;
        }
        
        public Builder withResultCode(final String resultCode) {
            this.resultCode = resultCode;
            return this;
        }
        
        public Builder withMessage(final String message) {
            this.message = message;
            return this;
        }
        
        public Builder withHasMx(final boolean hasMx) {
            this.hasMx = hasMx;
            return this;
        }
        
        public Builder withSmtpServer(final String smtpServer) {
            this.smtpServer = smtpServer;
            return this;
        }
        
        public Builder withIpAddress(final String ipAddress) {
            this.ipAddress = ipAddress;
            return this;
        }
        
        public Builder withResponseTime(final long responseTime) {
            this.responseTime = responseTime;
            return this;
        }
        
        public Builder withRetries(final int retries) {
            this.retries = retries;
            return this;
        }
        
        public Builder withDisposable(final boolean disposable) {
            this.disposable = disposable;
            return this;
        }
        
        public Builder withRole(final boolean role) {
            this.role = role;
            return this;
        }
        
        public Builder withSubAddressing(final boolean subAddressing) {
            this.subAddressing = subAddressing;
            return this;
        }
        
        public Builder withFree(final boolean free) {
            this.free = free;
            return this;
        }
        
        public Builder withSpam(final boolean spam) {
            this.spam = spam;
            return this;
        }
        
        public Builder withAdditionalInfo(final String additionalInfo) {
            this.additionalInfo = additionalInfo;
            return this;
        }
        
        public Builder withCountry(final String country) {
            this.country = country;
            return this;
        }
        
        public Builder withCheckedAt(final String checkedAt) {
            this.checkedAt = checkedAt;
            return this;
        }
        
        public Builder withCreatedAt(final String createdAt) {
            this.createdAt = createdAt;
            return this;
        }
        
        public EmailVerificationResponse build() {
            return new EmailVerificationResponse(this);
        }
    }
    
    // Getters
    public long getId() {
        return id;
    }
    
    public String getEmail() {
        return email;
    }
    
    public String getStatus() {
        return status;
    }
    
    public boolean isValid() {
        return valid;
    }
    
    public String getDomain() {
        return domain;
    }
    
    public String getLocalPart() {
        return localPart;
    }
    
    public String getResultCode() {
        return resultCode;
    }
    
    public String getMessage() {
        return message;
    }
    
    public String getAdditionalInfo() {
        return additionalInfo;
    }
    
    public boolean isSubAddressing() {
        return subAddressing;
    }
    
    public boolean isDisposable() {
        return disposable;
    }
    
    public boolean isRole() {
        return role;
    }
    
    public boolean isFree() {
        return free;
    }
    
    public boolean isSpam() {
        return spam;
    }
    
    public boolean isHasMx() {
        return hasMx;
    }
    
    public String getSmtpServer() {
        return smtpServer;
    }
    
    public String getIpAddress() {
        return ipAddress;
    }
    
    public String getCountry() {
        return country;
    }
    
    public String getCheckedAt() {
        return checkedAt;
    }
    
    public long getResponseTime() {
        return responseTime;
    }
    
    public String getCreatedAt() {
        return createdAt;
    }
    
    public int getRetries() {
        return retries;
    }
} 