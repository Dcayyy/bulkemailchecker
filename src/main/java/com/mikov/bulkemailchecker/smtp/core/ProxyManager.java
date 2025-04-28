package com.mikov.bulkemailchecker.smtp.core;

import com.mikov.bulkemailchecker.smtp.model.ProxyConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

@Slf4j
@Component
public class ProxyManager {
    private final List<ProxyConfig> proxies;
    private final AtomicInteger currentIndex;

    public ProxyManager() {
        this.proxies = new ArrayList<>();
        this.currentIndex = new AtomicInteger(0);
        initializeProxies();
    }

    private void initializeProxies() {
        // US Proxy - Piscataway
        proxies.add(ProxyConfig.builder()
                .host("38.153.152.244")
                .port(9594)
                .username("ggfjvdzt")
                .password("t4320kxmjwc7")
                .location("Piscataway, US")
                .type(ProxyConfig.ProxyType.SOCKS5)
                .isAvailable(true)
                .build());

        // UK Proxy - London
        proxies.add(ProxyConfig.builder()
                .host("86.38.234.176")
                .port(6630)
                .username("ggfjvdzt")
                .password("t4320kxmjwc7")
                .location("London, UK")
                .type(ProxyConfig.ProxyType.SOCKS5)
                .isAvailable(true)
                .build());

        // US Proxy - Los Angeles
        proxies.add(ProxyConfig.builder()
                .host("173.211.0.148")
                .port(6641)
                .username("ggfjvdzt")
                .password("t4320kxmjwc7")
                .location("Los Angeles, US")
                .type(ProxyConfig.ProxyType.SOCKS5)
                .isAvailable(true)
                .build());

        // US Proxy - Dallas
        proxies.add(ProxyConfig.builder()
                .host("216.10.27.159")
                .port(6837)
                .username("ggfjvdzt")
                .password("t4320kxmjwc7")
                .location("Dallas, US")
                .type(ProxyConfig.ProxyType.SOCKS5)
                .isAvailable(true)
                .build());

        // US Proxy - Dallas (2)
        proxies.add(ProxyConfig.builder()
                .host("154.36.110.199")
                .port(6853)
                .username("ggfjvdzt")
                .password("t4320kxmjwc7")
                .location("Dallas, US")
                .type(ProxyConfig.ProxyType.SOCKS5)
                .isAvailable(true)
                .build());

        // Germany Proxy - Frankfurt
        proxies.add(ProxyConfig.builder()
                .host("45.151.162.198")
                .port(6600)
                .username("ggfjvdzt")
                .password("t4320kxmjwc7")
                .location("Frankfurt, DE")
                .type(ProxyConfig.ProxyType.SOCKS5)
                .isAvailable(true)
                .build());
    }

    public synchronized ProxyConfig getNextAvailableProxy() {
        List<ProxyConfig> availableProxies = proxies.stream()
                .filter(ProxyConfig::isAvailable)
                .collect(Collectors.toList());

        if (availableProxies.isEmpty()) {
            log.warn("No available proxies found, resetting all proxies");
            resetAllProxies();
            availableProxies = new ArrayList<>(proxies);
        }

        // Sort proxies by success rate (descending)
        availableProxies.sort((p1, p2) -> Double.compare(p2.getSuccessRate(), p1.getSuccessRate()));

        // Get the next proxy in the sorted list
        int index = currentIndex.getAndIncrement() % availableProxies.size();
        return availableProxies.get(index);
    }

    public void markProxySuccess(ProxyConfig proxy) {
        proxy.markSuccess();
        log.debug("Proxy {} marked as successful. Success rate: {}", proxy.getHost(), proxy.getSuccessRate());
    }

    public void markProxyFailure(ProxyConfig proxy) {
        proxy.markFailure();
        log.warn("Proxy {} marked as failed. Success rate: {}", proxy.getHost(), proxy.getSuccessRate());
        
        // If this proxy has failed 3 times, try to find another available proxy
        if (!proxy.isAvailable()) {
            log.info("Proxy {} has been blacklisted, finding alternative proxy", proxy.getHost());
        }
    }

    private void resetAllProxies() {
        proxies.forEach(ProxyConfig::resetAvailability);
        currentIndex.set(0);
    }

    public List<ProxyConfig> getProxyStats() {
        return Collections.unmodifiableList(proxies);
    }
} 