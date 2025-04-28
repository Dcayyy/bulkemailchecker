package com.mikov.bulkemailchecker.smtp.model;

import lombok.Builder;
import lombok.Data;

import java.util.HashMap;
import java.util.Map;

@Data
@Builder
public class SmtpResult {
    private final String mxHost;
    private final String ipAddress;
    private final String responseMessage;
    private final boolean deliverable;
    private final boolean temporaryError;
    private final boolean permanentError;
    private final int responseCode;
    private final String errorMessage;
    private final SmtpErrorCode errorCode;
    private final Map<String, Object> details;

    public static SmtpResult fromResponse(String mxHost, String ipAddress, String responseMessage,
                                        boolean deliverable, boolean temporaryError, boolean permanentError,
                                        int responseCode, String errorMessage) {
        SmtpErrorCode errorCode = SmtpErrorCode.fromResponseCode(responseCode, responseMessage);
        Map<String, Object> details = new HashMap<>();
        
        if (errorCode == SmtpErrorCode.CATCH_ALL) {
            details.put("event", "is_catchall");
        } else if (errorCode == SmtpErrorCode.INCONCLUSIVE) {
            details.put("event", "inconclusive");
        } else if (errorCode == SmtpErrorCode.SERVER_RESTRICTED) {
            details.put("event", "server_restricted");
        } else if (errorCode == SmtpErrorCode.GREYLISTING) {
            details.put("greylisting_detected", true);
        }

        return SmtpResult.builder()
                .mxHost(mxHost)
                .ipAddress(ipAddress)
                .responseMessage(responseMessage)
                .deliverable(deliverable)
                .temporaryError(temporaryError)
                .permanentError(permanentError)
                .responseCode(responseCode)
                .errorMessage(errorMessage)
                .errorCode(errorCode)
                .details(details)
                .build();
    }

    public boolean requiresNeverBounceVerification() {
        return errorCode != null && errorCode.requiresNeverBounceVerification();
    }

    public boolean isTemporaryError() {
        return errorCode != null && errorCode.isTemporaryError();
    }

    public boolean isPermanentError() {
        return errorCode != null && errorCode.isPermanentError();
    }
} 