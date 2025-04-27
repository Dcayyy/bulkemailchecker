package com.mikov.bulkemailchecker.model;

public class EmailProviderResult {
    private String result;
    private String provider;

    public EmailProviderResult(String result, String provider) {
        this.result = result;
        this.provider = provider;
    }

    public String getResult() {
        return result;
    }

    public String getProvider() {
        return provider;
    }
} 