package com.mikov.bulkemailchecker.smtp.model;

import lombok.Builder;
import lombok.Getter;

import java.util.HashMap;
import java.util.Map;

@Getter
@Builder
public class SmtpResult {
    private final String mxHost;
    private final String ipAddress;
    private final boolean isDeliverable;
    private final boolean isCatchAll;
    private final boolean isTempError;
    private final int responseCode;
    private final String responseMessage;
    private final SmtpErrorCode errorCode;
    private final Map<String, Object> details;

    public static SmtpResult fromResponse(String mxHost, String provider, String ipAddress, 
                                        boolean isDeliverable, boolean isCatchAll, 
                                        boolean isTempError, int responseCode, String responseMessage) {
        Map<String, Object> details = new HashMap<>();
        details.put("provider", provider);
        
        return SmtpResult.builder()
                .mxHost(mxHost)
                .ipAddress(ipAddress)
                .isDeliverable(isDeliverable)
                .isCatchAll(isCatchAll)
                .isTempError(isTempError)
                .responseCode(responseCode)
                .responseMessage(responseMessage)
                .errorCode(SmtpErrorCode.fromCode(responseCode))
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