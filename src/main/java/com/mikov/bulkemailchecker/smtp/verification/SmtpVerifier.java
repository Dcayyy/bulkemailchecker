package com.mikov.bulkemailchecker.smtp.verification;

import com.mikov.bulkemailchecker.smtp.core.SmtpClient;
import com.mikov.bulkemailchecker.smtp.core.SmtpResponse;
import com.mikov.bulkemailchecker.smtp.core.commands.HeloCommand;
import com.mikov.bulkemailchecker.smtp.core.commands.MailFromCommand;
import com.mikov.bulkemailchecker.smtp.core.commands.RcptToCommand;
import com.mikov.bulkemailchecker.smtp.model.SmtpConfig;
import com.mikov.bulkemailchecker.smtp.model.SmtpResult;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.util.concurrent.TimeUnit;

@Slf4j
@Component
@RequiredArgsConstructor
public class SmtpVerifier {
    private final SmtpClient client;
    private final SmtpConfig config;

    public SmtpResult verify(String localPart, String domain) throws Exception {
        log.debug("Starting SMTP verification for {}@{}", localPart, domain);
        
        for (int attempt = 0; attempt < config.getVerificationAttempts(); attempt++) {
            try {
                if (attempt > 0) {
                    log.debug("Retrying SMTP verification for {}@{} (attempt {}/{})", 
                        localPart, domain, attempt + 1, config.getVerificationAttempts());
                    TimeUnit.MILLISECONDS.sleep(1000);
                }

                SmtpResponse heloResponse = client.executeCommand(new HeloCommand("fake.com"));
                if (!heloResponse.isSuccess()) {
                    if (heloResponse.isTemporaryFailure() && attempt < config.getVerificationAttempts() - 1) {
                        continue;
                    }
                    log.warn("HELO command failed for {}@{}: {}", localPart, domain, heloResponse.getMessage());
                    return createErrorResult(heloResponse);
                }

                SmtpResponse mailFromResponse = client.executeCommand(new MailFromCommand(config.getFromEmail()));
                if (!mailFromResponse.isSuccess()) {
                    if (mailFromResponse.isTemporaryFailure() && attempt < config.getVerificationAttempts() - 1) {
                        continue;
                    }
                    log.warn("MAIL FROM command failed for {}@{}: {}", localPart, domain, mailFromResponse.getMessage());
                    return createErrorResult(mailFromResponse);
                }

                SmtpResponse rcptToResponse = client.executeCommand(new RcptToCommand(localPart + "@" + domain));
                if (rcptToResponse.isTemporaryFailure() && attempt < config.getVerificationAttempts() - 1) {
                    continue;
                }
                
                boolean isDeliverable = rcptToResponse.isSuccess();
                boolean isCatchAll = isDeliverable && isCatchAllResponse(rcptToResponse);
                
                String provider = identifyProvider(client.getHost());
                String ipAddress = getIpAddress(client.getHost());

                log.debug("SMTP verification completed for {}@{}: deliverable={}, catchAll={}", 
                    localPart, domain, isDeliverable, isCatchAll);

                return SmtpResult.fromResponse(
                    client.getHost(),
                    provider,
                    ipAddress,
                    isDeliverable,
                    isCatchAll,
                    rcptToResponse.isTempError(),
                    rcptToResponse.getCode(),
                    rcptToResponse.getMessage()
                );

            } catch (Exception e) {
                log.error("SMTP verification attempt {} failed for {}@{}: {}", 
                    attempt + 1, localPart, domain, e.getMessage());
                if (attempt == config.getVerificationAttempts() - 1) {
                    return SmtpResult.fromResponse(
                        client.getHost(),
                        null,
                        null,
                        false,
                        false,
                        true,
                        0,
                        e.getMessage()
                    );
                }
            }
        }

        log.error("All SMTP verification attempts failed for {}@{}", localPart, domain);
        return SmtpResult.fromResponse(
            client.getHost(),
            null,
            null,
            false,
            false,
            true,
            0,
            "All verification attempts failed"
        );
    }

    private SmtpResult createErrorResult(SmtpResponse response) {
        return SmtpResult.fromResponse(
            client.getHost(),
            null,
            null,
            false,
            false,
            response.isTempError(),
            response.getCode(),
            response.getMessage()
        );
    }

    private boolean isCatchAllResponse(SmtpResponse response) {
        String lowerResponse = response.getMessage().toLowerCase();
        return lowerResponse.contains("catch-all") ||
               lowerResponse.contains("catchall") ||
               lowerResponse.contains("accept all") ||
               lowerResponse.contains("accepting all") ||
               lowerResponse.contains("any recipient") ||
               lowerResponse.contains("wildcard") ||
               (!lowerResponse.contains("user") &&
                !lowerResponse.contains("recipient") &&
                !lowerResponse.contains("mailbox") &&
                (lowerResponse.contains("accept") || lowerResponse.contains("ok")));
    }

    private String identifyProvider(String mxHost) {
        String lowerHost = mxHost.toLowerCase();
        if (lowerHost.contains(".google.com")) return "Google";
        if (lowerHost.contains(".outlook.com") || lowerHost.contains(".hotmail.com") || 
            lowerHost.contains(".live.com") || lowerHost.contains(".office365.com")) return "Microsoft";
        if (lowerHost.contains(".yahoo.com") || lowerHost.contains(".yahoodns.net")) return "Yahoo";
        if (lowerHost.contains(".aol.com")) return "AOL";
        if (lowerHost.contains(".zoho.com")) return "Zoho";
        if (lowerHost.contains(".protonmail.ch")) return "ProtonMail";
        if (lowerHost.contains(".gmx.")) return "GMX";
        if (lowerHost.contains(".yandex.")) return "Yandex";
        
        if (lowerHost.contains(".")) {
            String domain = lowerHost.substring(lowerHost.lastIndexOf('.') + 1);
            if (!domain.isEmpty()) {
                return domain.substring(0, 1).toUpperCase() + domain.substring(1);
            }
        }
        
        return "Self-hosted";
    }

    private String getIpAddress(String hostname) {
        try {
            return InetAddress.getByName(hostname).getHostAddress();
        } catch (Exception e) {
            log.warn("Failed to resolve IP address for {}: {}", hostname, e.getMessage());
            return "";
        }
    }
} 