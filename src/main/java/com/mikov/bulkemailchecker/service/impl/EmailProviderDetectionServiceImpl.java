package com.mikov.bulkemailchecker.service.impl;

import com.mikov.bulkemailchecker.cache.MxRecordCache;
import com.mikov.bulkemailchecker.config.DnsConfig;
import com.mikov.bulkemailchecker.model.EmailProviderResult;
import com.mikov.bulkemailchecker.service.EmailProviderDetectionService;
import com.mikov.bulkemailchecker.util.GoogleIpChecker;
import org.springframework.stereotype.Service;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.MXRecord;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Semaphore;
import java.util.regex.Pattern;

@Service
public class EmailProviderDetectionServiceImpl implements EmailProviderDetectionService {
    private final Resolver googleResolver;
    private final Resolver cloudflareResolver;
    private final MxRecordCache mxRecordCache;
    private final GoogleIpChecker googleIpChecker;
    private final Semaphore semaphore;

    public EmailProviderDetectionServiceImpl(
            Resolver googleResolver,
            Resolver cloudflareResolver,
            MxRecordCache mxRecordCache,
            GoogleIpChecker googleIpChecker) {
        this.googleResolver = googleResolver;
        this.cloudflareResolver = cloudflareResolver;
        this.mxRecordCache = mxRecordCache;
        this.googleIpChecker = googleIpChecker;
        this.semaphore = new Semaphore(DnsConfig.MAX_CONCURRENT_LOOKUPS);
    }

    @Override
    public EmailProviderResult detectEmailProvider(String email) {
        if (email == null || email.isEmpty()) {
            return new EmailProviderResult("Not Google", "invalid");
        }

        String emailRegex = "^[^\\s@]+@([^\\s@]+)$";
        Pattern pattern = Pattern.compile(emailRegex);
        var matcher = pattern.matcher(email);
        
        if (!matcher.matches()) {
            return new EmailProviderResult("Not Google", "invalid");
        }

        String domain = matcher.group(1).toLowerCase();

        EmailProviderResult cachedResult = mxRecordCache.get(domain);
        if (cachedResult != null) {
            return cachedResult;
        }

        try {
            semaphore.acquire();
            try {
                List<Record> mxRecords = getMxRecords(domain);
                if (mxRecords.isEmpty()) {
                    return new EmailProviderResult("Not Google", "unknown");
                }

                boolean isGoogle = checkGoogleMxRecords(mxRecords);
                EmailProviderResult result = new EmailProviderResult(
                    isGoogle ? "Google" : "Not Google",
                    isGoogle ? "google" : "other"
                );

                mxRecordCache.put(domain, result);
                return result;
            } finally {
                semaphore.release();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new EmailProviderResult("Not Google", "error");
        } catch (Exception e) {
            return new EmailProviderResult("Not Google", "error");
        }
    }

    private List<Record> getMxRecords(String domain) throws ExecutionException, InterruptedException {
        List<CompletableFuture<Record[]>> futures = new ArrayList<>();

        futures.add(CompletableFuture.supplyAsync(() -> {
            try {
                return new Lookup(domain, Type.MX).run();
            } catch (TextParseException e) {
                return new Record[0];
            }
        }));

        // Google resolver
        futures.add(CompletableFuture.supplyAsync(() -> {
            try {
                Lookup lookup = new Lookup(domain, Type.MX);
                lookup.setResolver(googleResolver);
                return lookup.run();
            } catch (TextParseException e) {
                return new Record[0];
            }
        }));

        // Cloudflare resolver
        futures.add(CompletableFuture.supplyAsync(() -> {
            try {
                Lookup lookup = new Lookup(domain, Type.MX);
                lookup.setResolver(cloudflareResolver);
                return lookup.run();
            } catch (TextParseException e) {
                return new Record[0];
            }
        }));

        CompletableFuture<Void> allFutures = CompletableFuture.allOf(
            futures.toArray(new CompletableFuture[0])
        );

        allFutures.get();

        Set<Record> uniqueRecords = new HashSet<>();
        for (CompletableFuture<Record[]> future : futures) {
            Record[] records = future.get();
            if (records != null) {
                uniqueRecords.addAll(Arrays.asList(records));
            }
        }

        return new ArrayList<>(uniqueRecords);
    }

    private boolean checkGoogleMxRecords(List<Record> mxRecords) {
        for (Record record : mxRecords) {
            if (record instanceof MXRecord mx) {
                String host = mx.getTarget().toString().toLowerCase();

                if (googleIpChecker.getGoogleMxPatterns().stream()
                    .anyMatch(pattern -> pattern.matcher(host).matches())) {
                    return true;
                }

                try {
                    InetAddress[] addresses = InetAddress.getAllByName(host);
                    for (InetAddress address : addresses) {
                        if (googleIpChecker.isGoogleIp(address.getHostAddress())) {
                            return true;
                        }
                    }
                } catch (UnknownHostException e) {
                    continue;
                }
            }
        }
        return false;
    }
} 