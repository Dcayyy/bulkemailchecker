package com.mikov.bulkemailchecker.smtp.model;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class SmtpConfig {
    private final int socketTimeout;
    private final int connectionTimeout;
    private final int verificationAttempts;
    private final int greylistingRetryDelay;
    private final int greylistingMaxRetries;
    private final boolean enableFastMode;
    private final boolean enableAggressiveVerification;
    private final String fromEmail;

    public static SmtpConfig getDefault() {
        return SmtpConfig.builder()
            .socketTimeout(5000)
            .connectionTimeout(5000)
            .verificationAttempts(2)
            .greylistingRetryDelay(3000)
            .greylistingMaxRetries(2)
            .enableFastMode(false)
            .enableAggressiveVerification(true)
            .fromEmail("verify@fake.com")
            .build();
    }
} 