package com.mikov.bulkemailchecker.smtp.verification;

import com.mikov.bulkemailchecker.smtp.core.SmtpClient;
import com.mikov.bulkemailchecker.smtp.core.SmtpResponse;
import com.mikov.bulkemailchecker.smtp.core.commands.HeloCommand;
import com.mikov.bulkemailchecker.smtp.core.commands.MailFromCommand;
import com.mikov.bulkemailchecker.smtp.core.commands.RcptToCommand;
import com.mikov.bulkemailchecker.smtp.model.SmtpConfig;
import com.mikov.bulkemailchecker.smtp.model.SmtpResult;

import java.net.InetAddress;

public class SmtpVerifier {
    private final SmtpClient client;
    private final SmtpConfig config;

    public SmtpVerifier(SmtpClient client) {
        this(client, SmtpConfig.getDefault());
    }

    public SmtpVerifier(SmtpClient client, SmtpConfig config) {
        this.client = client;
        this.config = config;
    }

    public SmtpResult verify(String localPart, String domain) throws Exception {
        try {
            SmtpResponse heloResponse = client.executeCommand(new HeloCommand("fake.com"));
            if (!heloResponse.isSuccess()) {
                return createErrorResult(heloResponse);
            }

            SmtpResponse mailFromResponse = client.executeCommand(new MailFromCommand(config.getFromEmail()));
            if (!mailFromResponse.isSuccess()) {
                return createErrorResult(mailFromResponse);
            }

            SmtpResponse rcptToResponse = client.executeCommand(new RcptToCommand(localPart + "@" + domain));
            
            boolean isDeliverable = rcptToResponse.isSuccess();
            boolean isCatchAll = isDeliverable && isCatchAllResponse(rcptToResponse);
            
            String provider = identifyProvider(client.getHost());
            String ipAddress = getIpAddress(client.getHost());

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
            return "";
        }
    }
} 