package com.mikov.bulkemailchecker.util;

import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

@Component
public class GoogleIpChecker {
    private static final List<String> GOOGLE_IP_CIDR_BLOCKS = Arrays.asList(
        "64.18.0.0/20",      // Google
        "64.233.160.0/19",   // Google
        "66.102.0.0/20",     // Google
        "66.249.80.0/20",    // Google
        "72.14.192.0/18",    // Google
        "74.125.0.0/16",     // Google
        "108.177.8.0/21",    // Google
        "173.194.0.0/16",    // Google
        "209.85.128.0/17",   // Google
        "216.58.192.0/19",   // Google
        "216.239.32.0/19"    // Google
    );

    private static final List<Pattern> GOOGLE_MX_PATTERNS = Arrays.asList(
        Pattern.compile("^aspmx\\.l\\.google\\.com$", Pattern.CASE_INSENSITIVE),
        Pattern.compile("^alt[0-9]?\\.aspmx\\.l\\.google\\.com$", Pattern.CASE_INSENSITIVE),
        Pattern.compile("^aspmx[0-9]\\.googlemail\\.com$", Pattern.CASE_INSENSITIVE),
        Pattern.compile("^alt[0-9]\\.aspmx\\.l\\.googlemail\\.com$", Pattern.CASE_INSENSITIVE),
        Pattern.compile("^smtp\\.google\\.com$", Pattern.CASE_INSENSITIVE),
        Pattern.compile("^gmail-smtp-in\\.l\\.google\\.com$", Pattern.CASE_INSENSITIVE),
        Pattern.compile("^mx\\.google\\.com$", Pattern.CASE_INSENSITIVE),
        Pattern.compile("^gmr-smtp-in\\.l\\.google\\.com$", Pattern.CASE_INSENSITIVE),
        Pattern.compile("^.*googlemail\\.com$", Pattern.CASE_INSENSITIVE),
        Pattern.compile("^.*google-mail\\.com$", Pattern.CASE_INSENSITIVE)
    );

    public List<Pattern> getGoogleMxPatterns() {
        return GOOGLE_MX_PATTERNS;
    }

    public boolean isGoogleIp(String ip) {
        if (ip == null || !ip.contains(".")) {
            return false;
        }

        // First check against known Google IP ranges
        if (isGoogleIpByCidr(ip)) {
            return true;
        }

        // Then check if the hostname contains Google-related terms
        try {
            String hostname = InetAddress.getByName(ip).getHostName();
            return GOOGLE_MX_PATTERNS.stream()
                .anyMatch(pattern -> pattern.matcher(hostname).matches()) ||
                hostname.contains("google") ||
                hostname.contains("googlemail");
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isGoogleIpByCidr(String ip) {
        try {
            InetAddress ipAddress = InetAddress.getByName(ip);
            for (String cidr : GOOGLE_IP_CIDR_BLOCKS) {
                if (isInRange(ipAddress, cidr)) {
                    return true;
                }
            }
        } catch (Exception e) {
            return false;
        }
        return false;
    }

    private boolean isInRange(InetAddress ipAddress, String cidr) {
        String[] parts = cidr.split("/");
        String ip = parts[0];
        int prefix = Integer.parseInt(parts[1]);

        byte[] ipBytes = ipAddress.getAddress();
        byte[] rangeBytes;
        try {
            rangeBytes = InetAddress.getByName(ip).getAddress();
        } catch (UnknownHostException e) {
            return false;
        }

        int mask = ~((1 << (32 - prefix)) - 1);
        int ipInt = ((ipBytes[0] & 0xFF) << 24) |
                   ((ipBytes[1] & 0xFF) << 16) |
                   ((ipBytes[2] & 0xFF) << 8) |
                   (ipBytes[3] & 0xFF);
        int rangeInt = ((rangeBytes[0] & 0xFF) << 24) |
                      ((rangeBytes[1] & 0xFF) << 16) |
                      ((rangeBytes[2] & 0xFF) << 8) |
                      (rangeBytes[3] & 0xFF);

        return (ipInt & mask) == (rangeInt & mask);
    }
} 