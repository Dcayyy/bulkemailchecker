package com.mikov.bulkemailchecker.validation;

import com.mikov.bulkemailchecker.dtos.ValidationResult;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Validator for email syntax and format.
 * Performs quick, low-resource checks to discard obviously invalid emails.
 *
 * @author zahari.mikov
 */
@Component
public class SyntaxValidator implements EmailValidator {

    private static final Pattern RFC_5322_PATTERN = Pattern.compile("^[a-zA-Z0-9_!#$%&'*+/=?`{|}~^.-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$");
    private static final Pattern BASIC_EMAIL_PATTERN = Pattern.compile("^[A-Za-z0-9+_.-]+@([A-Za-z0-9.-]+\\.[A-Za-z]{2,})$");

    private static final int MAX_EMAIL_LENGTH = 254;
    private static final int MAX_LOCAL_PART_LENGTH = 64;
    private static final int MAX_DOMAIN_LENGTH = 253;

    private static final Set<Character> INVALID_CHARS = new HashSet<>(Arrays.asList('#', '!', ' ', ',', ';', '\\', '/', '$', '%', '^', '&', '*', '(', ')', '+', '=', '<', '>', '?', '|', '{', '}', '[', ']', '~'));

    @Override
    public ValidationResult validate(final String email) {
        if (email == null || email.isBlank()) {
            return ValidationResult.invalid(getName(), "Email is null or empty");
        }
        
        final var cleanEmail = email.trim().toLowerCase();
        if (cleanEmail.length() > MAX_EMAIL_LENGTH) {
            return ValidationResult.invalid(getName(), "Email exceeds maximum length of " + MAX_EMAIL_LENGTH);
        }
        
        if (!cleanEmail.contains("@")) {
            return ValidationResult.invalid(getName(), "Email missing @ symbol");
        }
        
        if (cleanEmail.indexOf('@') != cleanEmail.lastIndexOf('@')) {
            return ValidationResult.invalid(getName(), "Email contains multiple @ symbols");
        }
        
        final var parts = cleanEmail.split("@", 2);
        if (parts.length != 2) {
            return ValidationResult.invalid(getName(), "Email has invalid format");
        }
        
        final var localPart = parts[0];
        final var domain = parts[1];
        
        if (localPart.isEmpty()) {
            return ValidationResult.invalid(getName(), "Local part is empty");
        }
        
        if (localPart.length() > MAX_LOCAL_PART_LENGTH) {
            return ValidationResult.invalid(getName(), "Local part exceeds maximum length of " + MAX_LOCAL_PART_LENGTH);
        }
        
        if (localPart.startsWith(".") || localPart.endsWith(".")) {
            return ValidationResult.invalid(getName(), "Local part cannot start or end with a dot");
        }
        
        if (localPart.contains("..")) {
            return ValidationResult.invalid(getName(), "Local part contains consecutive dots");
        }
        
        if (domain.isEmpty()) {
            return ValidationResult.invalid(getName(), "Domain is empty");
        }
        
        if (domain.length() > MAX_DOMAIN_LENGTH) {
            return ValidationResult.invalid(getName(), "Domain exceeds maximum length of " + MAX_DOMAIN_LENGTH);
        }
        
        if (!domain.contains(".")) {
            return ValidationResult.invalid(getName(), "Domain missing TLD");
        }
        
        if (domain.startsWith(".") || domain.endsWith(".") || domain.startsWith("-") || domain.endsWith("-")) {
            return ValidationResult.invalid(getName(), "Domain cannot start or end with a dot or hyphen");
        }
        
        final var domainParts = domain.split("\\.");
        final var tld = domainParts[domainParts.length - 1];
        
        if (tld.length() < 2) {
            return ValidationResult.invalid(getName(), "TLD is too short");
        }
        
        for (final var c : cleanEmail.toCharArray()) {
            if (INVALID_CHARS.contains(c)) {
                return ValidationResult.invalid(getName(), "Email contains invalid character: " + c);
            }
        }
        
        if (!RFC_5322_PATTERN.matcher(cleanEmail).matches()) {
            if (!BASIC_EMAIL_PATTERN.matcher(cleanEmail).matches()) {
                return ValidationResult.invalid(getName(), "Email fails RFC-5322 compliance");
            }
        }
        
        return ValidationResult.valid(getName());
    }

    @Override
    public String getName() {
        return "syntax";
    }
} 