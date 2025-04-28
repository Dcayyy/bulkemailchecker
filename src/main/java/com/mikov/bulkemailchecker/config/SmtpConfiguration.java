package com.mikov.bulkemailchecker.config;

import com.mikov.bulkemailchecker.smtp.core.ProxyManager;
import com.mikov.bulkemailchecker.smtp.core.SmtpClient;
import com.mikov.bulkemailchecker.smtp.dns.DnsRecordChecker;
import com.mikov.bulkemailchecker.smtp.dns.MxResolver;
import com.mikov.bulkemailchecker.smtp.model.SmtpConfig;
import com.mikov.bulkemailchecker.smtp.verification.CatchAllDetector;
import com.mikov.bulkemailchecker.smtp.verification.GreylistHandler;
import com.mikov.bulkemailchecker.smtp.verification.SmtpVerifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SmtpConfiguration {

    @Bean
    public MxResolver mxResolver() {
        return new MxResolver();
    }

    @Bean
    public DnsRecordChecker dnsRecordChecker() {
        return new DnsRecordChecker();
    }

    @Bean
    public CatchAllDetector catchAllDetector(SmtpConfig config, ProxyManager proxyManager) {
        return new CatchAllDetector(config, proxyManager);
    }

    @Bean
    public GreylistHandler greylistHandler(SmtpConfig config, ProxyManager proxyManager) {
        return new GreylistHandler(config, proxyManager);
    }

    @Bean
    public SmtpVerifier smtpVerifier(SmtpConfig config, ProxyManager proxyManager) {
        return new SmtpVerifier(config, proxyManager);
    }

    @Bean
    public SmtpConfig smtpConfig(ProxyManager proxyManager) {
        return SmtpConfig.builder()
                .timeout(5000)
                .proxyManager(proxyManager)
                .build();
    }

    @Bean
    public SmtpClient smtpClient(SmtpConfig config, ProxyManager proxyManager) {
        return new SmtpClient(config, proxyManager);
    }
} 