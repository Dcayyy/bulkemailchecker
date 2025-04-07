package com.mikov.bulkemailchecker.controller;

import com.mikov.bulkemailchecker.model.EmailVerificationRequest;
import com.mikov.bulkemailchecker.model.EmailVerificationResponse;
import com.mikov.bulkemailchecker.model.VerificationResult;
import com.mikov.bulkemailchecker.services.BulkEmailCheckerService;
import com.mikov.bulkemailchecker.services.SMTPValidator;
import com.mikov.bulkemailchecker.dtos.ValidationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.Payload;
import org.springframework.messaging.handler.annotation.SendTo;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Controller;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

/**
 * Controller for WebSocket-based email verification
 */
@Controller
public class WebSocketEmailController {
    private static final Logger logger = LoggerFactory.getLogger(WebSocketEmailController.class);
    private final SimpMessagingTemplate messagingTemplate;
    private final BulkEmailCheckerService bulkEmailCheckerService;
    
    // Simple cache to store recent results
    private final Map<String, VerificationResult> recentVerifications = new HashMap<>();
    
    @Autowired
    public WebSocketEmailController(SimpMessagingTemplate messagingTemplate,
                                    BulkEmailCheckerService bulkEmailCheckerService,
                                    SMTPValidator smtpValidator) {
        this.messagingTemplate = messagingTemplate;
        this.bulkEmailCheckerService = bulkEmailCheckerService;
    }
    
    /**
     * WebSocket endpoint for email verification
     */
    @MessageMapping("/verify")
    public void verifyEmails(@Payload EmailVerificationRequest request) {
        final String sessionId = request.getSessionId();
        final List<String> emails = request.getEmails();
        
        logger.info("Received verification request for {} emails, session: {}", 
            emails.size(), sessionId);
        
        // Process emails directly in this thread - completely sequential
        processEmails(sessionId, emails);
    }
    
    /**
     * Process emails one at a time, sequentially
     */
    private void processEmails(String sessionId, List<String> emails) {
        final int totalEmails = emails.size();
        final Map<String, Object> stats = new HashMap<>();
        stats.put("valid", 0);
        stats.put("invalid", 0);
        stats.put("catchall", 0);
        stats.put("inconclusive", 0);
        
        try {
            // Send initial status update
            sendStatusUpdate(sessionId, "STARTED", 0, totalEmails, stats);
            
            // Group emails by domain (just for organizational purposes)
            Map<String, List<String>> emailsByDomain = groupEmailsByDomain(emails);
            logger.info("Grouped {} emails into {} domain groups", emails.size(), emailsByDomain.size());
            
            // Process counter
            int processedCount = 0;
            
            // Process each domain's emails
            for (Map.Entry<String, List<String>> entry : emailsByDomain.entrySet()) {
                String domain = entry.getKey();
                List<String> domainEmails = entry.getValue();
                
                logger.info("Processing batch of {} emails for domain {}", domainEmails.size(), domain);
                
                // Process each email one at a time
                for (String email : domainEmails) {
                    // Verify email using the enhanced method with catch-all heuristics
                    long startTime = System.currentTimeMillis();
                    EmailVerificationResponse response = bulkEmailCheckerService.validateEmailWithRetry(email);
                    ValidationResult result = convertToValidationResult(response);
                    long processingTime = System.currentTimeMillis() - startTime;
                    
                    // Create verification result
                    VerificationResult verificationResult = new VerificationResult(email, result, processingTime);
                    
                    // Update stats
                    updateStatusStats(stats, result);
                    
                    // Send the result message
                    sendResultMessage(sessionId, verificationResult);
                    
                    // Update progress
                    processedCount++;
                    sendStatusUpdate(sessionId, "PROGRESS", processedCount, totalEmails, stats);
                    
                    // Add a small delay between emails to reduce load
                    try {
                        Thread.sleep(100);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }
            }
            
            // Send completion message
            logger.info("All verification tasks completed for session {}", sessionId);
            sendStatusUpdate(sessionId, "COMPLETED", processedCount, totalEmails, stats);
            
        } catch (Exception e) {
            logger.error("Error in email processing: {}", e.getMessage(), e);
            sendStatusUpdate(sessionId, "ERROR", 0, totalEmails, 
                Map.of("error", e.getMessage()));
        }
    }
    
    /**
     * Convert EmailVerificationResponse to ValidationResult
     */
    private ValidationResult convertToValidationResult(EmailVerificationResponse response) {
        Map<String, Object> details = new HashMap<>();
        details.put("email", response.getEmail());
        details.put("message", response.getMessage());
        details.put("responseTime", response.getResponseTime());
        
        // Copy event, it's important for catch-all detection
        if (response.getEvent() != null) {
            details.put("event", response.getEvent());
        }
        
        // Handle catch-all detection specially
        boolean isCatchAll = false;
        if (response.getMessage() != null && response.getMessage().contains("Catch-all domain")) {
            details.put("catch-all", 1.0);
            isCatchAll = true;
        }
        
        if (response.getEvent() != null && "is_catchall".equals(response.getEvent())) {
            details.put("catch-all", 1.0);
            isCatchAll = true;
        }
        
        // Handle each status type
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
    
    /**
     * Update the statistics based on the verification result
     */
    private void updateStatusStats(Map<String, Object> stats, ValidationResult result) {
        Map<String, Object> details = result.getDetails();
        
        // Check for explicit status in the details
        String status = "";
        if (details != null && details.containsKey("status")) {
            status = details.get("status").toString();
        }
        
        // Handle each status type
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
    
    /**
     * Send a result message for a verified email
     */
    private void sendResultMessage(String sessionId, VerificationResult result) {
        String destination = "/topic/verification-result/" + sessionId;
        messagingTemplate.convertAndSend(destination, result.toMap());
    }
    
    /**
     * Send a status update message
     */
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
    
    /**
     * Group emails by domain to optimize verification
     */
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