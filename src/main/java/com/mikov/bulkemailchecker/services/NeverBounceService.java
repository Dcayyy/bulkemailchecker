package com.mikov.bulkemailchecker.services;

import com.mikov.bulkemailchecker.dtos.ValidationResult;
import com.neverbounce.api.client.NeverbounceClient;
import com.neverbounce.api.client.NeverbounceClientFactory;
import com.neverbounce.api.client.exception.NeverbounceApiException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

/**
 * Service for email verification using NeverBounce API
 */
@Service
public class NeverBounceService {
    private static final Logger logger = LoggerFactory.getLogger(NeverBounceService.class);

    public ValidationResult verifyEmail(String email, String apiKey) {
        logger.debug("Verifying email {} with NeverBounce API", email);
        
        try {
            NeverbounceClient client = NeverbounceClientFactory.create(apiKey);
            
            Object response = client
                    .prepareSingleCheckRequest()
                    .withEmail(email)
                    .withAddressInfo(true)
                    .withTimeout(30)
                    .build()
                    .execute();
            
            Map<String, Object> details = new HashMap<>();
            details.put("response", response);
            System.out.println(details.get("response"));
            
            Map<String, Object> formattedResult = new HashMap<>();
            formattedResult.put("result", "valid"); // Default to valid unless we detect otherwise
            details.put("formatted_result", formattedResult);
            
            return ValidationResult.builder()
                    .valid(true)
                    .validatorName("neverbounce")
                    .details(details)
                    .build();
                    
        } catch (NeverbounceApiException e) {
            logger.error("NeverBounce API error: {}", e.getMessage());
            
            if (e.getMessage() != null && e.getMessage().contains("Invalid API key")) {
                Map<String, Object> details = new HashMap<>();
                details.put("error", "Invalid NeverBounce API key. Please provide a valid API key.");
                details.put("error_code", "invalid_api_key");
                
                return ValidationResult.builder()
                        .valid(false)
                        .validatorName("neverbounce")
                        .reason("Invalid NeverBounce API key")
                        .details(details)
                        .build();
            }
            
            Map<String, Object> details = new HashMap<>();
            details.put("error", "NeverBounce API error: " + e.getMessage());
            details.put("error_code", "neverbounce_api_error");
            
            return ValidationResult.builder()
                    .valid(false)
                    .validatorName("neverbounce")
                    .reason("NeverBounce API error")
                    .details(details)
                    .build();
                    
        } catch (Exception e) {
            logger.error("Error verifying email with NeverBounce: {}", e.getMessage());
            
            Map<String, Object> details = new HashMap<>();
            details.put("error", "Error verifying email with NeverBounce: " + e.getMessage());
            details.put("error_code", "verification_error");
            
            return ValidationResult.builder()
                    .valid(false)
                    .validatorName("neverbounce")
                    .reason("Error during NeverBounce verification")
                    .details(details)
                    .build();
        }
    }
} 