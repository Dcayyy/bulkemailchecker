package com.mikov.bulkemailchecker.smtp;

import com.mikov.bulkemailchecker.smtp.core.SmtpClient;
import com.mikov.bulkemailchecker.smtp.core.SmtpResponse;
import com.mikov.bulkemailchecker.smtp.core.commands.HeloCommand;
import com.mikov.bulkemailchecker.smtp.core.commands.MailFromCommand;
import com.mikov.bulkemailchecker.smtp.core.commands.RcptToCommand;
import com.mikov.bulkemailchecker.smtp.dns.DnsRecordChecker;
import com.mikov.bulkemailchecker.smtp.dns.MxResolver;
import com.mikov.bulkemailchecker.smtp.model.SmtpConfig;
import com.mikov.bulkemailchecker.smtp.model.SmtpErrorCode;
import com.mikov.bulkemailchecker.smtp.model.SmtpResult;
import com.mikov.bulkemailchecker.smtp.verification.CatchAllDetector;
import com.mikov.bulkemailchecker.smtp.verification.GreylistHandler;
import com.mikov.bulkemailchecker.smtp.verification.SmtpVerifier;
import com.mikov.bulkemailchecker.smtp.core.ProxyManager;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Slf4j
@Component
@RequiredArgsConstructor
public class SmtpValidator {
    private final SmtpConfig config;
    private final MxResolver mxResolver;
    private final DnsRecordChecker dnsChecker;
    private final CatchAllDetector catchAllDetector;
    private final GreylistHandler greylistHandler;
    private final SmtpVerifier smtpVerifier;
    private final ProxyManager proxyManager;
    private static final int MAX_RETRIES = 3;
    private static final int RETRY_DELAY_MS = 1000;

    public SmtpResult validate(String email) {
        log.info("Starting SMTP validation for email: {}", email);
        
        String[] parts = email.split("@");
        if (parts.length != 2) {
            return createErrorResult("Invalid email format", SmtpErrorCode.INVALID_DOMAIN);
        }

        String domain = parts[1];
        String localPart = parts[0];

        // First check DNS records
        Map<String, Object> dnsDetails = dnsChecker.checkRecords(domain);
        if (dnsDetails.containsKey("has_dns_issues") && Boolean.TRUE.equals(dnsDetails.get("has_dns_issues"))) {
            log.warn("DNS issues detected for domain {}: {}", domain, dnsDetails);
            return createErrorResult("DNS configuration issues", SmtpErrorCode.DNS_ISSUES, dnsDetails);
        }

        // Resolve MX records
        List<MxResolver.MxRecord> mxRecords;
        String mxHost = null;
        try {
            mxRecords = mxResolver.resolve(domain);
            if (mxRecords.isEmpty()) {
                return createErrorResult("No MX records found", SmtpErrorCode.NO_MX_RECORDS);
            }
            mxHost = mxRecords.get(0).hostname(); // Get the highest priority MX record
        } catch (Exception e) {
            log.error("Error resolving MX records for {}: {}", domain, e.getMessage());
            return createErrorResult(e.getMessage(), SmtpErrorCode.CONNECTION_ERROR);
        }

        // Check for catch-all domain
        boolean isCatchAll = catchAllDetector.detect(domain, mxHost);
        if (isCatchAll) {
            log.info("Catch-all domain detected for {}", email);
            Map<String, Object> details = new HashMap<>();
            details.put("event", "is_catchall");
            return createErrorResult("Catch-all domain detected", SmtpErrorCode.CATCH_ALL, details);
        }

        // Create SMTP client and verifier
        SmtpClient client = new SmtpClient(mxHost, proxyManager);
        
        try {
            client.connect();
            
            // Handle greylisting
            SmtpResult result = greylistHandler.handle(localPart, domain);
            if (result != null) {
                return result;
            }

            // Perform SMTP verification
            result = smtpVerifier.verify(localPart, domain);
            
            // Add DNS details to the result
            if (result.getDetails() != null) {
                result.getDetails().putAll(dnsDetails);
            }
            
            return result;

        } catch (Exception e) {
            log.error("Error during SMTP validation for {}: {}", email, e.getMessage());
            return createErrorResult(e.getMessage(), SmtpErrorCode.CONNECTION_ERROR);
        } finally {
            try {
                client.disconnect();
            } catch (Exception e) {
                log.warn("Error disconnecting from SMTP server: {}", e.getMessage());
            }
        }
    }

    private SmtpResult createErrorResult(String message, SmtpErrorCode errorCode) {
        return createErrorResult(message, errorCode, new HashMap<>());
    }

    private SmtpResult createErrorResult(String message, SmtpErrorCode errorCode, Map<String, Object> details) {
        return SmtpResult.builder()
                .mxHost(null)
                .ipAddress(null)
                .isDeliverable(false)
                .isCatchAll(false)
                .isTempError(errorCode.isTemporary())
                .responseCode(errorCode.getCode())
                .responseMessage(message)
                .errorCode(errorCode)
                .details(details)
                .build();
    }
} 