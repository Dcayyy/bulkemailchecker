package com.mikov.bulkemailchecker.config;

import com.mikov.bulkemailchecker.smtp.SmtpValidator;
import com.mikov.bulkemailchecker.smtp.model.SmtpConfig;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SmtpConfiguration {
    
    @Bean
    public SmtpConfig smtpConfig() {
        return SmtpConfig.getDefault();
    }
    
    @Bean
    public SmtpValidator smtpValidator(SmtpConfig config) {
        return new SmtpValidator(config);
    }
} 