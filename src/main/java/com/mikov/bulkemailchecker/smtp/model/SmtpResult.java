package com.mikov.bulkemailchecker.smtp.model;

import lombok.Builder;
import lombok.Getter;

import java.util.HashMap;
import java.util.Map;

@Getter
@Builder
public class SmtpResult {
    private final boolean deliverable;
    private final boolean catchAll;
    private final boolean tempError;
    private final int responseCode;
    private final String fullResponse;
    private final String mxHost;
    private final String provider;
    private final String ipAddress;
    @Builder.Default
    private final Map<String, Object> details = new HashMap<>();

    public static SmtpResult fromResponse(String mxHost, String provider, String ipAddress, 
                                        boolean deliverable, boolean catchAll, boolean tempError,
                                        int responseCode, String fullResponse) {
        return SmtpResult.builder()
            .mxHost(mxHost)
            .provider(provider)
            .ipAddress(ipAddress)
            .deliverable(deliverable)
            .catchAll(catchAll)
            .tempError(tempError)
            .responseCode(responseCode)
            .fullResponse(fullResponse)
            .build();
    }
} 