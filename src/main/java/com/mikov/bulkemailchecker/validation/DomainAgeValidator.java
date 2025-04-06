package com.mikov.bulkemailchecker.validation;

import com.mikov.bulkemailchecker.dtos.ValidationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.retry.annotation.Backoff;
import org.springframework.retry.annotation.Retryable;
import org.springframework.stereotype.Component;
import org.apache.commons.net.whois.WhoisClient;

import java.io.IOException;
import java.time.Duration;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Validator that checks domain age and reputation.
 * Newly registered domains are often used for spam and phishing.
 *
 * @author zahari.mikov
 */
@Component
public class DomainAgeValidator implements EmailValidator {
    private static final Logger logger = LoggerFactory.getLogger(DomainAgeValidator.class);
    
    private final Map<String, LocalDate> domainRegistrationDates = new HashMap<>();

    private static final Map<String, String> WHOIS_SERVERS = Map.of(
        ".com", "whois.verisign-grs.com",
        ".net", "whois.verisign-grs.com",
        ".org", "whois.pir.org",
        ".io", "whois.nic.io",
        ".co", "whois.nic.co",
        ".edu", "whois.educause.edu",
        ".gov", "whois.dotgov.gov",
        ".biz", "whois.biz",
        ".info", "whois.afilias.net"
    );

    private static final Pattern DATE_PATTERNS = Pattern.compile(
        "(Creation Date|Created Date|Created On|Registration Date|Registrar Registration Date|Creation time|Created):\\s*(\\d{4}-\\d{2}-\\d{2}|\\d{2}-\\d{2}-\\d{4}|\\d{4}/\\d{2}/\\d{2})"
    );

    @Override
    public ValidationResult validate(final String email) {
        final var parts = email.split("@", 2);
        if (parts.length != 2) {
            return ValidationResult.invalid(getName(), "Invalid email format");
        }
        
        final var domain = parts[1].toLowerCase();
        final var domainAgeDays = getDomainAgeDays(domain);
        
        final var details = new HashMap<String, Double>();
        details.put("age_days", (double) domainAgeDays);
        
        int ageInYears = (int) (domainAgeDays / 365);
        details.put("age", (double) ageInYears);

        if (domainAgeDays < 7) {
            return ValidationResult.invalid(getName(), "Very new domain (less than 1 week old)", details);
        }
        
        return ValidationResult.valid(getName(), details);
    }

    @Override
    public String getName() {
        return "domain-age";
    }

    @Retryable(
        value = { IOException.class }, backoff = @Backoff(delay = 1000, multiplier = 2)
    )
    public long getDomainAgeDays(final String domain) {
        try {
            final var cachedDate = domainRegistrationDates.get(domain);
            if (cachedDate != null) {
                return Duration.between(cachedDate.atStartOfDay(), LocalDate.now().atStartOfDay()).toDays();
            }

            final var tld = getTld(domain);
            final var whoisServer = WHOIS_SERVERS.get(tld);
            if (whoisServer == null) {
                logger.debug("No WHOIS server known for TLD {}, returning default age", tld);
                return 100;
            }

            try {
                final var whoisResponse = queryWhoisServer(whoisServer, domain);
                if (whoisResponse == null || whoisResponse.isEmpty()) {
                    logger.debug("Empty WHOIS response for domain {}, returning default age", domain);
                    return 100;
                }

                final var creationDate = extractCreationDate(whoisResponse);
                if (creationDate.isEmpty()) {
                    logger.debug("Could not extract creation date for domain {}, returning default age", domain);
                    return 100;
                }

                domainRegistrationDates.put(domain, creationDate.get());
                return Duration.between(creationDate.get().atStartOfDay(), LocalDate.now().atStartOfDay()).toDays();
            } catch (IOException e) {
                logger.warn("WHOIS connection issue for domain {}: {}", domain, e.getMessage());
                return 100;
            }
        } catch (Exception e) {
            logger.error("Error getting domain age for {}: {}", domain, e.getMessage());
            return 100;
        }
    }

    private String getTld(String domain) {
        final var lastDot = domain.lastIndexOf('.');
        if (lastDot == -1) {
            return "";
        }
        return domain.substring(lastDot);
    }

    private String queryWhoisServer(String whoisServer, String domain) throws IOException {
        final var whois = new WhoisClient();
        try {
            whois.setDefaultTimeout(5000); // 5 second timeout
            whois.connect(whoisServer);
            return whois.query(domain);
        } finally {
            whois.disconnect();
        }
    }

    private Optional<LocalDate> extractCreationDate(String whoisResponse) {
        final var matcher = DATE_PATTERNS.matcher(whoisResponse);
        if (matcher.find()) {
            try {
                final var dateStr = matcher.group(2);
                final var formatter = dateStr.contains("-") ? 
                    DateTimeFormatter.ofPattern("yyyy-MM-dd") :
                    dateStr.contains("/") ? 
                        DateTimeFormatter.ofPattern("yyyy/MM/dd") :
                        DateTimeFormatter.ofPattern("dd-MM-yyyy");
                
                return Optional.of(LocalDate.parse(dateStr, formatter));
            } catch (Exception e) {
                logger.warn("Error parsing date from WHOIS response: {}", e.getMessage());
            }
        }
        return Optional.empty();
    }
} 