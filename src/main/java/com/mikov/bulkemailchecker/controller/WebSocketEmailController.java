package com.mikov.bulkemailchecker.controller;

import com.mikov.bulkemailchecker.model.EmailVerificationRequest;
import com.mikov.bulkemailchecker.model.EmailVerificationResponse;
import com.mikov.bulkemailchecker.model.VerificationResult;
import com.mikov.bulkemailchecker.services.BulkEmailCheckerService;
import com.mikov.bulkemailchecker.dtos.ValidationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.Payload;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Controller;

import java.util.*;

/**
 * Controller for WebSocket-based email verification
 */
@Controller
public class WebSocketEmailController {
    private static final Logger logger = LoggerFactory.getLogger(WebSocketEmailController.class);
    private final SimpMessagingTemplate messagingTemplate;
    private final BulkEmailCheckerService bulkEmailCheckerService;
    
    @Autowired
    public WebSocketEmailController(SimpMessagingTemplate messagingTemplate,
                                    BulkEmailCheckerService bulkEmailCheckerService) {
        this.messagingTemplate = messagingTemplate;
        this.bulkEmailCheckerService = bulkEmailCheckerService;
    }

    @MessageMapping("/verify")
    public void verifyEmails(@Payload EmailVerificationRequest request) {
        final String sessionId = request.getSessionId();
        final List<String> emails = request.getEmails();
        final String neverbounceApiKey = request.getNeverbounceApiKey();
        
        logger.info("Received verification request for {} emails, session: {}", 
            emails.size(), sessionId);
        logger.debug("NeverBounce API key present: {}", neverbounceApiKey != null && !neverbounceApiKey.isBlank());
        
        processEmails(sessionId, emails, neverbounceApiKey);
    }

    private void processEmails(String sessionId, List<String> emails, String neverbounceApiKey) {
        final int totalEmails = emails.size();
        final Map<String, Object> stats = new HashMap<>();
        stats.put("valid", 0);
        stats.put("invalid", 0);
        stats.put("catchall", 0);
        stats.put("inconclusive", 0);
        
        logger.debug("Starting email processing with NeverBounce API key: {}", 
            neverbounceApiKey != null ? "provided" : "not provided");
        
        try {
            sendStatusUpdate(sessionId, "STARTED", 0, totalEmails, stats);
            
            Map<String, List<String>> emailsByDomain = groupEmailsByDomain(emails);
            logger.info("Grouped {} emails into {} domain groups", emails.size(), emailsByDomain.size());
            
            int processedCount = 0;
            
            for (Map.Entry<String, List<String>> entry : emailsByDomain.entrySet()) {
                String domain = entry.getKey();
                List<String> domainEmails = entry.getValue();
                
                logger.info("Processing batch of {} emails for domain {}", domainEmails.size(), domain);
                
                for (String email : domainEmails) {
                    long startTime = System.currentTimeMillis();
                    EmailVerificationResponse response = bulkEmailCheckerService.validateEmailWithRetry(email, neverbounceApiKey);
                    ValidationResult result = convertToValidationResult(response);
                    long processingTime = System.currentTimeMillis() - startTime;
                    
                    VerificationResult verificationResult = new VerificationResult(email, result, processingTime);
                    updateStatusStats(stats, result);
                    sendResultMessage(sessionId, verificationResult);
                    processedCount++;
                    sendStatusUpdate(sessionId, "PROGRESS", processedCount, totalEmails, stats);

                    try {
                        Thread.sleep(100);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }
            }
            
            logger.info("All verification tasks completed for session {}", sessionId);
            sendStatusUpdate(sessionId, "COMPLETED", processedCount, totalEmails, stats);
            
        } catch (Exception e) {
            logger.error("Error in email processing: {}", e.getMessage(), e);
            sendStatusUpdate(sessionId, "ERROR", 0, totalEmails, 
                Map.of("error", e.getMessage()));
        }
    }

    private ValidationResult convertToValidationResult(EmailVerificationResponse response) {
        Map<String, Object> details = new HashMap<>();
        details.put("email", response.getEmail());
        details.put("message", response.getMessage());
        details.put("responseTime", response.getResponseTime());
        
        if (response.getEvent() != null) {
            details.put("event", response.getEvent());
        }
        
        boolean isCatchAll = false;
        if (response.getMessage() != null && response.getMessage().contains("Catch-all domain")) {
            details.put("catch-all", 1.0);
            isCatchAll = true;
        }
        
        if (response.getEvent() != null && "is_catchall".equals(response.getEvent())) {
            details.put("catch-all", 1.0);
            isCatchAll = true;
        }
        
        if (isCatchAll) {
            details.put("status", "catch-all");
            return ValidationResult.catchAll("email", "Catch-all domain", details);
        } else if ("inconclusive".equals(response.getStatus())) {
            details.put("status", "inconclusive");
            return ValidationResult.valid("email", details); // inconclusive treated as technically valid but marked
        } else if ("valid".equals(response.getStatus())) {
            details.put("status", "valid");
            return ValidationResult.valid("email", details);
        } else {
            details.put("status", "invalid");
            return ValidationResult.invalid("email", response.getMessage(), details);
        }
    }

    private void updateStatusStats(Map<String, Object> stats, ValidationResult result) {
        Map<String, Object> details = result.getDetails();
        
        String status = "";
        if (details != null && details.containsKey("status")) {
            status = details.get("status").toString();
        }
        
        if ("catch-all".equals(status)) {
            incrementStat(stats, "catchall");
        } else if ("inconclusive".equals(status)) {
            incrementStat(stats, "inconclusive");
        } else if (result.isValid()) {
            incrementStat(stats, "valid");
        } else {
            incrementStat(stats, "invalid");
        }
    }
    
    private void incrementStat(Map<String, Object> stats, String key) {
        int current = (int) stats.getOrDefault(key, 0);
        stats.put(key, current + 1);
    }

    private void sendResultMessage(String sessionId, VerificationResult result) {
        String destination = "/topic/verification-result/" + sessionId;
        messagingTemplate.convertAndSend(destination, result.toMap());
    }

    private void sendStatusUpdate(String sessionId, String status, int processed, int total, Map<String, Object> stats) {
        String destination = "/topic/verification-status/" + sessionId;
        Map<String, Object> update = new HashMap<>();
        update.put("status", status);
        update.put("processed", processed);
        update.put("total", total);
        update.put("stats", stats);
        update.put("timestamp", System.currentTimeMillis());
        
        messagingTemplate.convertAndSend(destination, update);
    }

    private Map<String, List<String>> groupEmailsByDomain(List<String> emails) {
        Map<String, List<String>> emailsByDomain = new HashMap<>();
        
        for (String email : emails) {
            try {
                String[] parts = email.trim().split("@", 2);
                if (parts.length == 2) {
                    String domain = parts[1].toLowerCase();
                    emailsByDomain.computeIfAbsent(domain, k -> new ArrayList<>()).add(email);
                }
            } catch (Exception e) {
                logger.warn("Error grouping email {}: {}", email, e.getMessage());
            }
        }
        
        return emailsByDomain;
    }
} 