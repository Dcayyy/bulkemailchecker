package com.mikov.bulkemailchecker.smtp.verification;

import com.mikov.bulkemailchecker.smtp.core.SmtpClient;
import com.mikov.bulkemailchecker.smtp.model.SmtpConfig;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Random;

@Slf4j
@Component
@RequiredArgsConstructor
public class CatchAllDetector {
    private final SmtpConfig config;
    private static final int MAX_RETRIES = 3;
    private static final int RETRY_DELAY_MS = 1000;

    public boolean detect(String domain, String mxHost) {
        SmtpClient client = null;
        int retryCount = 0;

        while (retryCount < MAX_RETRIES) {
            try {
                client = new SmtpClient(mxHost, config.getProxyManager());
                client.connect();
                
                String response = client.sendCommand("HELO " + domain);
                if (!response.startsWith("250")) {
                    return false;
                }

                response = client.sendCommand("MAIL FROM: <check@" + domain + ">");
                if (!response.startsWith("250")) {
                    return false;
                }

                // Generate a random email address that is unlikely to exist
                String randomEmail = generateRandomEmail(domain);
                response = client.sendCommand("RCPT TO: <" + randomEmail + ">");
                
                // If the server accepts a random email, it's likely a catch-all
                return response.startsWith("250");

            } catch (Exception e) {
                log.error("Error detecting catch-all for domain {}: {}", domain, e.getMessage());
                retryCount++;
                if (retryCount < MAX_RETRIES) {
                    try {
                        Thread.sleep(RETRY_DELAY_MS);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                    }
                    continue;
                }
                return false;
            } finally {
                if (client != null) {
                    try {
                        client.disconnect();
                    } catch (Exception e) {
                        log.warn("Error disconnecting from SMTP server: {}", e.getMessage());
                    }
                }
            }
        }
        return false;
    }

    private String generateRandomEmail(String domain) {
        Random random = new Random();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 10; i++) {
            sb.append((char) ('a' + random.nextInt(26)));
        }
        sb.append('@').append(domain);
        return sb.toString();
    }
} 