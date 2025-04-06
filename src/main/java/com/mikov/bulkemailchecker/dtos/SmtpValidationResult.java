package com.mikov.bulkemailchecker.dtos;

/**
 * Results of SMTP validation for an email address.
 * 
 * @author zahari.mikov
 */
public class SmtpValidationResult {
    private final boolean deliverable;
    private final boolean catchAll;
    private final int responseCode;
    private final boolean tempError;
    private final String fullResponse;
    private final String serverName;
    
    public SmtpValidationResult(final boolean deliverable, final boolean catchAll, 
                             final int responseCode, final boolean tempError) {
        this(deliverable, catchAll, responseCode, tempError, "", "");
    }
    
    public SmtpValidationResult(final boolean deliverable, final boolean catchAll, 
                           final int responseCode, final boolean tempError,
                           final String fullResponse, final String serverName) {
        this.deliverable = deliverable;
        this.catchAll = catchAll;
        this.responseCode = responseCode;
        this.tempError = tempError;
        this.fullResponse = fullResponse;
        this.serverName = serverName;
    }
    
    public boolean isDeliverable() {
        return deliverable;
    }
    
    public boolean isCatchAll() {
        return catchAll;
    }
    
    public int getResponseCode() {
        return responseCode;
    }
    
    public boolean isTempError() {
        return tempError;
    }
    
    public String getFullResponse() {
        return fullResponse;
    }
    
    public String getServerName() {
        return serverName;
    }
} 