package com.mikov.bulkemailchecker.validation;

import com.mikov.bulkemailchecker.dtos.ValidationResult;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Validator that detects potential typosquatting domains.
 * Calculates Levenshtein distance between the domain and popular domains.
 *
 * @author zahari.mikov
 */
@Component
public class TyposquattingValidator implements EmailValidator {

    private static final Logger logger = LoggerFactory.getLogger(TyposquattingValidator.class);

    private static final int MAX_LEVENSHTEIN_DISTANCE = 2;

    private final Set<String> popularDomains = new HashSet<>();

    @PostConstruct
    public void init() {
        popularDomains.addAll(Arrays.asList(
            "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
            "icloud.com", "protonmail.com", "mail.com", "zoho.com", "yandex.com",
            "gmx.com", "live.com", "msn.com", "googlemail.com", "me.com",
            "mail.ru", "inbox.com", "fastmail.com", "tutanota.com", "outlook.jp",
            "seznam.cz", "comcast.net", "verizon.net", "att.net", "bellsouth.net"
        ));
    }

    @Override
    public ValidationResult validate(final String email) {
       final var parts = email.split("@", 2);
        if (parts.length != 2) {
            return ValidationResult.invalid(getName(), "Invalid email format");
        }
        
        final var domain = parts[1].toLowerCase();
        
        if (popularDomains.contains(domain)) {
            return ValidationResult.valid(getName(), 1.0);
        }
        
        for (final var popularDomain : popularDomains) {
            final var distance = calculateLevenshteinDistance(domain, popularDomain);
            
            if (distance > 0 && distance <= MAX_LEVENSHTEIN_DISTANCE) {
                logger.debug("Email domain {} is similar to popular domain {} (distance={})", 
                        domain, popularDomain, distance);

                final var score = 1.0 - (distance / 3.0);
                
                final var result = ValidationResult.valid(getName(), score);
                result.getDetails().put("similar-to", (double) distance);
                result.getDetails().put("popular-domain", 1.0);
                result.getDetails().put("domain", 0.0);
                return result;
            }
        }
        
        return ValidationResult.valid(getName(), 1.0);
    }

    @Override
    public String getName() {
        return "typosquatting";
    }

    private int calculateLevenshteinDistance(final String s1, final String s2) {
        final var dp = new int[s1.length() + 1][s2.length() + 1];
        
        for (var i = 0; i <= s1.length(); i++) {
            dp[i][0] = i;
        }
        
        for (var j = 0; j <= s2.length(); j++) {
            dp[0][j] = j;
        }
        
        for (var i = 1; i <= s1.length(); i++) {
            for (var j = 1; j <= s2.length(); j++) {
                final var cost = (s1.charAt(i - 1) == s2.charAt(j - 1)) ? 0 : 1;
                dp[i][j] = Math.min(Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1), dp[i - 1][j - 1] + cost);
            }
        }
        
        return dp[s1.length()][s2.length()];
    }
} 