package com.mikov.bulkemailchecker.model;

import java.util.List;

/**
 * Request model for bulk email verification
 */
public class BulkEmailVerificationRequest {
    private List<String> emails;
    
    public BulkEmailVerificationRequest() {
        // Default constructor for Jackson
    }
    
    public BulkEmailVerificationRequest(List<String> emails) {
        this.emails = emails;
    }
    
    public List<String> getEmails() {
        return emails;
    }
    
    public void setEmails(List<String> emails) {
        this.emails = emails;
    }
} 