package com.mikov.bulkemailchecker.smtp.verification;

import com.mikov.bulkemailchecker.smtp.core.SmtpClient;
import com.mikov.bulkemailchecker.smtp.model.SmtpResult;

import java.util.List;
import java.util.Random;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class CatchAllDetector {
    private static final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
    private static final Random random = new Random();

    public boolean detect(String domain, String mxHost) {
        try {
            List<CompletableFuture<SmtpResult>> probeFutures = createProbeEmails(domain, mxHost);
            CompletableFuture.allOf(probeFutures.toArray(new CompletableFuture[0]))
                .get(5, TimeUnit.SECONDS);

            int acceptedCount = 0;
            boolean anyRejected = false;

            for (CompletableFuture<SmtpResult> future : probeFutures) {
                SmtpResult result = future.get();
                if (result.isDeliverable()) {
                    acceptedCount++;
                } else if (!result.isTemporaryError() && result.getResponseCode() >= 500) {
                    anyRejected = true;
                }
            }

            return acceptedCount >= 2 && !anyRejected;

        } catch (Exception e) {
            return false;
        }
    }

    private List<CompletableFuture<SmtpResult>> createProbeEmails(String domain, String mxHost) {
        String randomId1 = generateRandomString(10);
        String randomId2 = generateRandomString(12);
        String randomId3 = generateRandomString(8);

        String[] probeLocalParts = {
            "nonexistent-user-" + randomId1,
            "invalid.email." + randomId2,
            "probe_" + randomId3 + "_test"
        };

        return List.of(
            verifyProbeEmail(probeLocalParts[0], domain, mxHost),
            verifyProbeEmail(probeLocalParts[1], domain, mxHost),
            verifyProbeEmail(probeLocalParts[2], domain, mxHost)
        );
    }

    private CompletableFuture<SmtpResult> verifyProbeEmail(String localPart, String domain, String mxHost) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                SmtpClient client = new SmtpClient(mxHost);
                client.connect();
                
                SmtpResult result = new SmtpVerifier(client).verify(localPart, domain);
                client.disconnect();
                
                return result;
            } catch (Exception e) {
                return SmtpResult.fromResponse(mxHost, null, null, false, false, true, 0, e.getMessage());
            }
        }, executor);
    }

    private String generateRandomString(int length) {
        String allowedChars = "abcdefghijklmnopqrstuvwxyz";
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(allowedChars.charAt(random.nextInt(allowedChars.length())));
        }
        return sb.toString();
    }
} 