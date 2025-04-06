package com.mikov.bulkemailchecker.validation;

import com.mikov.bulkemailchecker.dtos.ValidationResult;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Validator that checks if an email is a role-based address (e.g., info@, support@).
 * Role-based emails are less valuable for lead generation and outreach.
 *
 * @author zahari.mikov
 */
@Component
public class RoleBasedValidator implements EmailValidator {

    private static final Set<String> ROLE_PREFIXES = new HashSet<>(Arrays.asList(
            "admin", "administrator", "webmaster", "hostmaster", "postmaster", 
            "info", "information", "mail", "contact", "contacts", "support", 
            "help", "helpdesk", "sales", "marketing", "jobs", "careers", 
            "webadmin", "abuse", "noreply", "no-reply", "no.reply", "donotreply", 
            "do-not-reply", "do.not.reply", "security", "feedback", "inquiry", 
            "inquiries", "newsletter", "billing", "office", "team", "media", 
            "paypal", "account", "accounts", "service", "customerservice", 
            "customer.service", "customer-service", "hello", "public.relations", 
            "pr", "press", "recruitment", "enquiry", "enquiries", "donations", 
            "membership", "staff", "privacy", "notification", "notifications",
            "hr", "human.resources", "customercare", "customer.care"
    ));

    @Override
    public ValidationResult validate(final String email) {
        if (email == null || email.isBlank()) {
            return ValidationResult.invalid(getName(), "Email is null or empty");
        }
        
        final var parts = email.split("@", 2);
        if (parts.length != 2) {
            return ValidationResult.invalid(getName(), "Invalid email format");
        }
        
        final var localPart = parts[0].toLowerCase();
        
        for (final var prefix : ROLE_PREFIXES) {
            if (localPart.equals(prefix) || 
                localPart.startsWith(prefix + ".") || 
                localPart.startsWith(prefix + "-") || 
                localPart.startsWith(prefix + "_")) {

                return ValidationResult.invalid(getName(), "Email uses a role-based prefix: " + prefix);
            }
        }
        
        return ValidationResult.valid(getName());
    }

    @Override
    public String getName() {
        return "role-based";
    }
} 