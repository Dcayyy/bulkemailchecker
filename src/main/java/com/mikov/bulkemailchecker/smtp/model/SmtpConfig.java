package com.mikov.bulkemailchecker.smtp.model;

import com.mikov.bulkemailchecker.smtp.core.ProxyManager;
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
    private final int timeout;
    private final ProxyManager proxyManager;

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
            .timeout(30000)
            .proxyManager(new ProxyManager())
            .build();
    }
} 