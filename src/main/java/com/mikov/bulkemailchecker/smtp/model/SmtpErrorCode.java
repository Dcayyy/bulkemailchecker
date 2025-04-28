package com.mikov.bulkemailchecker.smtp.model;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum SmtpErrorCode {
    // Success codes
    SUCCESS(200, false),
    MAILBOX_EXISTS(250, false),
    
    // Temporary errors
    GREYLISTING(451, true),
    TEMPORARY_FAILURE(451, true),
    CONNECTION_ERROR(421, true),
    
    // Permanent errors
    MAILBOX_DOES_NOT_EXIST(550, false),
    INVALID_DOMAIN(550, false),
    ACCESS_DENIED(550, false),
    NO_MX_RECORDS(550, false),
    DNS_ISSUES(550, false),
    
    // Special cases
    CATCH_ALL(250, false),
    INCONCLUSIVE(550, false);

    private final int code;
    private final boolean temporary;

    public int getCode() {
        return code;
    }

    public String getMessage() {
        return this.name();
    }

    public static SmtpErrorCode fromResponseCode(int responseCode, String responseMessage) {
        // Check for catch-all first
        if (responseMessage != null && responseMessage.toLowerCase().contains("catch-all")) {
            return CATCH_ALL;
        }

        // Check for greylisting
        if (responseCode == 451 || (responseMessage != null && responseMessage.toLowerCase().contains("greylist"))) {
            return GREYLISTING;
        }

        // Map standard SMTP response codes
        switch (responseCode) {
            case 250:
                return MAILBOX_EXISTS;
            case 450:
                return TEMPORARY_FAILURE;
            case 421:
                return CONNECTION_ERROR;
            case 550:
                return MAILBOX_DOES_NOT_EXIST;
            case 252:
                return INCONCLUSIVE;
            default:
                return SUCCESS;
        }
    }

    public boolean requiresNeverBounceVerification() {
        return this == CATCH_ALL || 
               this == INCONCLUSIVE;
    }

    public boolean isTemporary() {
        return temporary;
    }

    public boolean isPermanentError() {
        return this == MAILBOX_DOES_NOT_EXIST || 
               this == INVALID_DOMAIN || 
               this == ACCESS_DENIED ||
               this == NO_MX_RECORDS ||
               this == DNS_ISSUES;
    }

    public static SmtpErrorCode fromCode(int code) {
        for (SmtpErrorCode errorCode : values()) {
            if (errorCode.getCode() == code) {
                return errorCode;
            }
        }
        return INCONCLUSIVE;
    }

    public boolean isTemporaryError() {
        return isTemporary();
    }
} 