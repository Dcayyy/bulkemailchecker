package com.mikov.bulkemailchecker.smtp.model;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class ProxyConfig {
    private final String host;
    private final int port;
    private final String username;
    private final String password;
    private final String location;
    private final ProxyType type;
    private boolean isAvailable;
    private int successCount;
    private int failureCount;

    public enum ProxyType {
        SOCKS5
    }

    public double getSuccessRate() {
        int total = successCount + failureCount;
        return total > 0 ? (double) successCount / total : 0.0;
    }

    public void markSuccess() {
        successCount++;
        isAvailable = true;
    }

    public void markFailure() {
        failureCount++;
        if (failureCount >= 3) {
            isAvailable = false;
        }
    }

    public void resetAvailability() {
        isAvailable = true;
    }
} 