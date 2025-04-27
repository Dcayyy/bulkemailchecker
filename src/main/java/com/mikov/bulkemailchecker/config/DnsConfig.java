package com.mikov.bulkemailchecker.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SimpleResolver;

import java.net.InetAddress;
import java.net.UnknownHostException;

@Configuration
public class DnsConfig {
    
    public static final String GOOGLE_DNS = "8.8.8.8";
    public static final String CLOUDFLARE_DNS = "1.1.1.1";
    public static final int RESOLVER_TIMEOUT = 3000;
    public static final long CACHE_TTL = 3600000; // 1 hour
    public static final int MAX_CACHE_SIZE = 1000;
    public static final int MAX_CONCURRENT_LOOKUPS = 5;

    @Bean
    public Resolver googleResolver() throws UnknownHostException {
        final InetAddress dnsServer = InetAddress.getByName(GOOGLE_DNS);
        final Resolver resolver = new SimpleResolver(dnsServer);
        resolver.setTimeout(RESOLVER_TIMEOUT);
        return resolver;
    }

    @Bean
    public Resolver cloudflareResolver() throws UnknownHostException {
        final InetAddress dnsServer = InetAddress.getByName(CLOUDFLARE_DNS);
        final Resolver resolver = new SimpleResolver(dnsServer);
        resolver.setTimeout(RESOLVER_TIMEOUT);
        return resolver;
    }
} 