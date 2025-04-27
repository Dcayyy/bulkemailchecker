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
public final class EmailProviderDetectionServiceImpl implements EmailProviderDetectionService {
    private final Resolver googleResolver;
    private final Resolver cloudflareResolver;
    private final MxRecordCache mxRecordCache;
    private final GoogleIpChecker googleIpChecker;
    private final Semaphore semaphore;
    private static final String EMAIL_REGEX = "^[^\\s@]+@([^\\s@]+)$";
    private static final Pattern EMAIL_PATTERN = Pattern.compile(EMAIL_REGEX);

    public EmailProviderDetectionServiceImpl(
            final Resolver googleResolver,
            final Resolver cloudflareResolver,
            final MxRecordCache mxRecordCache,
            final GoogleIpChecker googleIpChecker) {
        this.googleResolver = googleResolver;
        this.cloudflareResolver = cloudflareResolver;
        this.mxRecordCache = mxRecordCache;
        this.googleIpChecker = googleIpChecker;
        this.semaphore = new Semaphore(DnsConfig.MAX_CONCURRENT_LOOKUPS);
    }

    @Override
    public EmailProviderResult detectEmailProvider(final String email) {
        if (email == null || email.isEmpty()) {
            return new EmailProviderResult("Not Google", "invalid");
        }

        final var matcher = EMAIL_PATTERN.matcher(email);
        
        if (!matcher.matches()) {
            return new EmailProviderResult("Not Google", "invalid");
        }

        final var domain = matcher.group(1).toLowerCase();

        final var cachedResult = mxRecordCache.get(domain);
        if (cachedResult != null) {
            return cachedResult;
        }

        try {
            semaphore.acquire();
            try {
                final var mxRecords = getMxRecords(domain);
                if (mxRecords.isEmpty()) {
                    return new EmailProviderResult("Not Google", "unknown");
                }

                final var isGoogle = checkGoogleMxRecords(mxRecords);
                final var result = new EmailProviderResult(
                    isGoogle ? "Google" : "Not Google",
                    isGoogle ? "google" : "other"
                );

                mxRecordCache.put(domain, result);
                return result;
            } finally {
                semaphore.release();
            }
        } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
            return new EmailProviderResult("Not Google", "error");
        } catch (final Exception e) {
            return new EmailProviderResult("Not Google", "error");
        }
    }

    private List<Record> getMxRecords(final String domain) throws ExecutionException, InterruptedException {
        final var futures = new ArrayList<CompletableFuture<Record[]>>();

        futures.add(CompletableFuture.supplyAsync(() -> {
            try {
                return new Lookup(domain, Type.MX).run();
            } catch (final TextParseException e) {
                return new Record[0];
            }
        }));

        // Google resolver
        futures.add(CompletableFuture.supplyAsync(() -> {
            try {
                final var lookup = new Lookup(domain, Type.MX);
                lookup.setResolver(googleResolver);
                return lookup.run();
            } catch (final TextParseException e) {
                return new Record[0];
            }
        }));

        // Cloudflare resolver
        futures.add(CompletableFuture.supplyAsync(() -> {
            try {
                final var lookup = new Lookup(domain, Type.MX);
                lookup.setResolver(cloudflareResolver);
                return lookup.run();
            } catch (final TextParseException e) {
                return new Record[0];
            }
        }));

        final var allFutures = CompletableFuture.allOf(
            futures.toArray(new CompletableFuture[0])
        );

        allFutures.get();

        final var uniqueRecords = new HashSet<Record>();
        for (final var future : futures) {
            final var records = future.get();
            if (records != null) {
                uniqueRecords.addAll(Arrays.asList(records));
            }
        }

        return new ArrayList<>(uniqueRecords);
    }

    private boolean checkGoogleMxRecords(final List<Record> mxRecords) {
        for (final var record : mxRecords) {
            if (record instanceof MXRecord mx) {
                final var host = mx.getTarget().toString().toLowerCase();

                if (googleIpChecker.getGoogleMxPatterns().stream()
                    .anyMatch(pattern -> pattern.matcher(host).matches())) {
                    return true;
                }

                try {
                    final var addresses = InetAddress.getAllByName(host);
                    for (final var address : addresses) {
                        if (googleIpChecker.isGoogleIp(address.getHostAddress())) {
                            return true;
                        }
                    }
                } catch (final UnknownHostException e) {
                    continue;
                }
            }
        }
        return false;
    }
} 