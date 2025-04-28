package com.mikov.bulkemailchecker.smtp;

import com.mikov.bulkemailchecker.smtp.core.SmtpClient;
import com.mikov.bulkemailchecker.smtp.dns.DnsRecordChecker;
import com.mikov.bulkemailchecker.smtp.dns.MxResolver;
import com.mikov.bulkemailchecker.smtp.model.SmtpConfig;
import com.mikov.bulkemailchecker.smtp.model.SmtpResult;
import com.mikov.bulkemailchecker.smtp.verification.CatchAllDetector;
import com.mikov.bulkemailchecker.smtp.verification.GreylistHandler;
import com.mikov.bulkemailchecker.smtp.verification.SmtpVerifier;

import java.util.List;
import java.util.Map;

public class SmtpValidator {
    private final SmtpConfig config;
    private final MxResolver mxResolver;
    private final DnsRecordChecker dnsChecker;
    private final CatchAllDetector catchAllDetector;

    public SmtpValidator(SmtpConfig config) {
        this.config = config;
        this.mxResolver = new MxResolver();
        this.dnsChecker = new DnsRecordChecker();
        this.catchAllDetector = new CatchAllDetector();
    }

    public SmtpResult validate(String email) throws Exception {
        String[] parts = email.split("@", 2);
        if (parts.length != 2) {
            throw new IllegalArgumentException("Invalid email format");
        }

        String localPart = parts[0];
        String domain = parts[1].toLowerCase();

        List<MxResolver.MxRecord> mxRecords = mxResolver.resolve(domain);
        if (mxRecords.isEmpty()) {
            throw new IllegalArgumentException("No MX records found for domain: " + domain);
        }

        Map<String, Object> dnsDetails = dnsChecker.checkRecords(domain);
        String mxHost = mxRecords.get(0).hostname();

        if (!config.isEnableFastMode()) {
            boolean isCatchAll = catchAllDetector.detect(domain, mxHost);
            if (isCatchAll) {
                return createCatchAllResult(mxHost, dnsDetails);
            }
        }

        SmtpClient client = new SmtpClient(mxHost);
        SmtpVerifier verifier = new SmtpVerifier(client, config);
        GreylistHandler greylistHandler = new GreylistHandler(verifier, config);

        try {
            client.connect();
            SmtpResult result = config.isEnableAggressiveVerification() ?
                greylistHandler.handle(localPart, domain) :
                verifier.verify(localPart, domain);

            result.getDetails().putAll(dnsDetails);
            return result;

        } finally {
            client.disconnect();
        }
    }

    private SmtpResult createCatchAllResult(String mxHost, Map<String, Object> dnsDetails) {
        String provider = identifyProvider(mxHost);
        String ipAddress = getIpAddress(mxHost);

        SmtpResult result = SmtpResult.fromResponse(
            mxHost,
            provider,
            ipAddress,
            true,
            true,
            false,
            250,
            "Catch-all domain"
        );

        result.getDetails().putAll(dnsDetails);
        return result;
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
            return java.net.InetAddress.getByName(hostname).getHostAddress();
        } catch (Exception e) {
            return "";
        }
    }
} 