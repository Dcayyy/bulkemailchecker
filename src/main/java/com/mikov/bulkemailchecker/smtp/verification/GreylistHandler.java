package com.mikov.bulkemailchecker.smtp.verification;

import com.mikov.bulkemailchecker.smtp.model.SmtpConfig;
import com.mikov.bulkemailchecker.smtp.model.SmtpResult;

import java.util.concurrent.TimeUnit;

public class GreylistHandler {
    private final SmtpVerifier verifier;
    private final SmtpConfig config;

    public GreylistHandler(SmtpVerifier verifier, SmtpConfig config) {
        this.verifier = verifier;
        this.config = config;
    }

    public SmtpResult handle(String localPart, String domain) throws Exception {
        SmtpResult firstAttempt = verifier.verify(localPart, domain);
        if (!firstAttempt.isTemporaryError()) {
            return firstAttempt;
        }

        for (int i = 0; i < config.getGreylistingMaxRetries(); i++) {
            TimeUnit.MILLISECONDS.sleep(config.getGreylistingRetryDelay());
            
            SmtpResult nextAttempt = verifier.verify(localPart, domain);
            if (!nextAttempt.isTemporaryError()) {
                return nextAttempt;
            }

            if (nextAttempt.getResponseCode() != firstAttempt.getResponseCode() ||
                !nextAttempt.getResponseMessage().equals(firstAttempt.getResponseMessage())) {
                return nextAttempt.isDeliverable() ? nextAttempt : firstAttempt;
            }
        }

        return firstAttempt;
    }
} 