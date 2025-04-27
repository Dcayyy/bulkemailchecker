package com.mikov.bulkemailchecker.config;

import com.mikov.bulkemailchecker.cache.MxRecordCache;
import com.mikov.bulkemailchecker.util.GoogleIpChecker;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class EmailProviderConfig {

    @Bean
    public MxRecordCache mxRecordCache() {
        return new MxRecordCache(DnsConfig.CACHE_TTL, DnsConfig.MAX_CACHE_SIZE);
    }

    @Bean
    public GoogleIpChecker googleIpChecker() {
        return new GoogleIpChecker();
    }
} 