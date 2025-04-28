package com.mikov.bulkemailchecker.smtp.model;

public enum SmtpErrorCode {
    // Success codes
    SUCCESS(200, "Success"),
    MAILBOX_EXISTS(201, "Mailbox exists"),
    
    // Temporary errors
    GREYLISTING(451, "Greylisting detected"),
    TEMPORARY_FAILURE(450, "Temporary failure"),
    SERVER_BUSY(421, "Server busy"),
    
    // Permanent errors
    MAILBOX_DOES_NOT_EXIST(550, "Mailbox does not exist"),
    INVALID_DOMAIN(550, "Invalid domain"),
    ACCESS_DENIED(550, "Access denied"),
    
    // Special cases
    CATCH_ALL(250, "Catch-all domain"),
    INCONCLUSIVE(252, "Inconclusive result"),
    SERVER_RESTRICTED(550, "Server restricted");

    private final int code;
    private final String message;

    SmtpErrorCode(int code, String message) {
        this.code = code;
        this.message = message;
    }

    public int getCode() {
        return code;
    }

    public String getMessage() {
        return message;
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

        // Check for server restrictions
        if (responseMessage != null && responseMessage.toLowerCase().contains("restricted")) {
            return SERVER_RESTRICTED;
        }

        // Map standard SMTP response codes
        switch (responseCode) {
            case 250:
                return MAILBOX_EXISTS;
            case 450:
                return TEMPORARY_FAILURE;
            case 421:
                return SERVER_BUSY;
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
               this == INCONCLUSIVE || 
               this == SERVER_RESTRICTED;
    }

    public boolean isTemporaryError() {
        return this == GREYLISTING || 
               this == TEMPORARY_FAILURE || 
               this == SERVER_BUSY;
    }

    public boolean isPermanentError() {
        return this == MAILBOX_DOES_NOT_EXIST || 
               this == INVALID_DOMAIN || 
               this == ACCESS_DENIED;
    }
} 