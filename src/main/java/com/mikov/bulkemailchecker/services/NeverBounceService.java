package com.mikov.bulkemailchecker.services;

import com.neverbounce.api.client.NeverbounceClient;
import com.neverbounce.api.client.NeverbounceClientFactory;
import com.mikov.bulkemailchecker.dtos.ValidationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import java.util.HashMap;
import java.util.Map;
import java.lang.reflect.Method;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Service for NeverBounce API integration, used to verify email addresses
 * specifically when dealing with catch-all domains.
 */
@Service
public class NeverBounceService {
    private static final Logger logger = LoggerFactory.getLogger(NeverBounceService.class);
    
    @Value("${neverbounce.api-key}")
    private String apiKey;
    
    private NeverbounceClient neverbounceClient;
    
    @PostConstruct
    public void init() {
        neverbounceClient = NeverbounceClientFactory.create(apiKey);
    }
    
    /**
     * Verify email specifically for catch-all domains using NeverBounce API
     * 
     * @param email The email to verify
     * @return ValidationResult with the verification result
     */
    public ValidationResult verifyEmail(String email) {
        if (neverbounceClient == null) {
            logger.warn("NeverBounce client not initialized. Skipping verification for: {}", email);
            Map<String, Object> details = new HashMap<>();
            details.put("error", "neverbounce_not_configured");
            return ValidationResult.invalid("neverbounce", "API key not configured", details);
        }
        
        try {
            logger.info("Performing NeverBounce verification for catch-all domain email: {}", email);
            
            // Use NeverBounce API to check email
            Object response = neverbounceClient
                    .prepareSingleCheckRequest()
                    .withEmail(email)
                    .withAddressInfo(true)
                    .withTimeout(30)
                    .build()
                    .execute();
            
            logger.debug("NeverBounce response: {}", response);
            
            // Map NeverBounce response to our validation model
            return mapNeverBounceResponse(response, email);
            
        } catch (Exception e) {
            logger.error("Error verifying email with NeverBounce: {}", e.getMessage(), e);
            Map<String, Object> details = new HashMap<>();
            details.put("error", e.getMessage());
            return ValidationResult.invalid("neverbounce", "API error", details);
        }
    }
    
    /**
     * Maps NeverBounce API response to our ValidationResult
     */
    private ValidationResult mapNeverBounceResponse(Object response, String email) {
        if (response == null) {
            return ValidationResult.invalid("neverbounce", "Null response from NeverBounce", null);
        }
        
        try {
            logger.debug("NeverBounce response class: {}", response.getClass().getName());
            
            // Get the response details using reflection since we don't have the right imports
            String resultString = "unknown";
            Map<String, Object> flags = new HashMap<>();
            
            try {
                // Get the Result enum object
                Object resultEnum = response.getClass().getMethod("getResult").invoke(response);
                
                if (resultEnum != null) {
                    // Get the enum name using name() method
                    Method nameMethod = resultEnum.getClass().getMethod("name");
                    resultString = (String) nameMethod.invoke(resultEnum);
                    
                    // Also get the description for more details
                    try {
                        Method descMethod = resultEnum.getClass().getMethod("getDescription");
                        String description = (String) descMethod.invoke(resultEnum);
                        if (description != null) {
                            flags.put("description", description);
                        }
                    } catch (Exception e) {
                        // Ignore if can't get description
                    }
                }
                
                // Try to get flags using getFlags() method
                Object flagsObj = response.getClass().getMethod("getFlags").invoke(response);
                if (flagsObj != null) {
                    flags.put("flags_info", flagsObj.toString());
                }
                
                // Extract additional information from the response
                extractAdditionalInfo(response, flags);
            } catch (Exception e) {
                logger.warn("Error extracting data from NeverBounce response: {}", e.getMessage());
            }
            
            logger.debug("NeverBounce returned result: {} for email: {}", resultString, email);
            
            Map<String, Object> details = new HashMap<>();
            details.put("neverbounce_result", resultString);
            details.put("neverbounce_flags", flags);
            
            // Format the response according to requirement
            formatResponseDetails(details, resultString, email);
            
            switch (resultString.toUpperCase()) {
                case "VALID":
                    return ValidationResult.valid("neverbounce", details);
                case "INVALID":
                    return ValidationResult.invalid("neverbounce", "Email invalid according to NeverBounce", details);
                case "DISPOSABLE":
                    return ValidationResult.invalid("neverbounce", "Disposable email detected", details);
                case "CATCHALL":
                    // Even NeverBounce considers it catch-all, so we'll return it as such
                    details.put("event", "is_catchall");
                    return ValidationResult.catchAll("neverbounce", "Domain is catch-all", details);
                case "UNKNOWN":
                default:
                    return ValidationResult.invalid("neverbounce", "Unknown result from NeverBounce", details);
            }
        } catch (Exception e) {
            logger.error("Error parsing NeverBounce response: {}", e.getMessage(), e);
            Map<String, Object> details = new HashMap<>();
            details.put("error", e.getMessage());
            return ValidationResult.invalid("neverbounce", "Error parsing response", details);
        }
    }
    
    /**
     * Format the response details according to requirements
     */
    private void formatResponseDetails(Map<String, Object> details, String resultString, String email) {
        // Create a standardized result format
        Map<String, Object> formattedResult = new HashMap<>();
        formattedResult.put("email", email);
        
        // Set timestamp
        formattedResult.put("timestamp", OffsetDateTime.now().format(DateTimeFormatter.ISO_INSTANT));
        
        // Generate an ID (can be replaced with a more sophisticated ID generation)
        formattedResult.put("id", System.currentTimeMillis() % 10000000);
        
        // Format the flags
        formattedResult.put("flags", details.getOrDefault("flags_info", ""));
        
        // Set result based on NeverBounce result
        switch (resultString.toUpperCase()) {
            case "VALID":
                formattedResult.put("result", "valid");
                details.put("event", "mailbox_exists");
                break;
            case "INVALID":
                formattedResult.put("result", "invalid");
                details.put("event", "mailbox_does_not_exist");
                break;
            case "CATCHALL":
                formattedResult.put("result", "catchall");
                break;
            case "DISPOSABLE":
                formattedResult.put("result", "disposable");
                break;
            default:
                formattedResult.put("result", "unknown");
                break;
        }
        
        // Store the formatted result in details
        details.put("formatted_result", formattedResult);
        
        // Also set the event appropriately
        if (resultString.equalsIgnoreCase("VALID")) {
            details.put("event", "mailbox_exists");
        } else if (resultString.equalsIgnoreCase("INVALID")) {
            details.put("event", "mailbox_does_not_exist");
        } else if (resultString.equalsIgnoreCase("CATCHALL")) {
            details.put("event", "is_catchall");
        }
    }
    
    /**
     * Extract additional information from the NeverBounce response
     * 
     * @param response The NeverBounce response object
     * @param flags Map to store extracted information
     */
    private void extractAdditionalInfo(Object response, Map<String, Object> flags) {
        try {
            // Common methods that might be available
            String[] methodNames = {
                "getSuggestion", "getAddressInfo", "getCreditsInfo", "getExecutionTime"
            };
            
            for (String methodName : methodNames) {
                try {
                    Method method = response.getClass().getMethod(methodName);
                    Object value = method.invoke(response);
                    if (value != null) {
                        flags.put(methodName.substring(3), value.toString());
                    }
                } catch (Exception e) {
                    // Skip if method doesn't exist
                }
            }
            
            // Try to extract address info (which might contain lots of useful details)
            try {
                Method addressInfoMethod = response.getClass().getMethod("getAddressInfo");
                Object addressInfo = addressInfoMethod.invoke(response);
                if (addressInfo != null) {
                    // Common fields in address info
                    String[] addressInfoMethods = {
                        "getMailbox", "getHost", "getRole", "getDisposable", "getFree", "getSyntax", "getDomain"
                    };
                    
                    for (String methodName : addressInfoMethods) {
                        try {
                            Method method = addressInfo.getClass().getMethod(methodName);
                            Object value = method.invoke(addressInfo);
                            if (value != null) {
                                flags.put("address_" + methodName.substring(3).toLowerCase(), value.toString());
                            }
                        } catch (Exception e) {
                            // Skip if method doesn't exist
                        }
                    }
                }
            } catch (Exception e) {
                // Skip if no address info
            }
        } catch (Exception e) {
            logger.warn("Error extracting additional info: {}", e.getMessage());
        }
    }
} 