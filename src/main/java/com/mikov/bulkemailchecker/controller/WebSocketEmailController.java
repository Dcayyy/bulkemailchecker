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
public final class WebSocketEmailController {
    private static final Logger logger = LoggerFactory.getLogger(WebSocketEmailController.class);
    private final SimpMessagingTemplate messagingTemplate;
    private final BulkEmailCheckerService bulkEmailCheckerService;
    
    @Autowired
    public WebSocketEmailController(final SimpMessagingTemplate messagingTemplate,
                                  final BulkEmailCheckerService bulkEmailCheckerService) {
        this.messagingTemplate = messagingTemplate;
        this.bulkEmailCheckerService = bulkEmailCheckerService;
    }

    @MessageMapping("/verify")
    public void verifyEmails(@Payload final EmailVerificationRequest request) {
        final var sessionId = request.getSessionId();
        final var emails = request.getEmails();
        final var neverbounceApiKey = request.getNeverbounceApiKey();
        
        logger.info("Received verification request for {} emails, session: {}", 
            emails.size(), sessionId);
        logger.debug("NeverBounce API key present: {}", neverbounceApiKey != null && !neverbounceApiKey.isBlank());
        
        processEmails(sessionId, emails, neverbounceApiKey);
    }

    private void processEmails(final String sessionId, final List<String> emails, final String neverbounceApiKey) {
        final var totalEmails = emails.size();
        final var stats = new HashMap<String, Object>();
        stats.put("valid", 0);
        stats.put("invalid", 0);
        stats.put("catchall", 0);
        stats.put("inconclusive", 0);
        
        logger.debug("Starting email processing with NeverBounce API key: {}", 
            neverbounceApiKey != null ? "provided" : "not provided");
        
        try {
            sendStatusUpdate(sessionId, "STARTED", 0, totalEmails, stats);
            
            final var emailsByDomain = groupEmailsByDomain(emails);
            logger.info("Grouped {} emails into {} domain groups", emails.size(), emailsByDomain.size());
            
            var processedCount = 0;
            
            for (final var entry : emailsByDomain.entrySet()) {
                final var domain = entry.getKey();
                final var domainEmails = entry.getValue();
                
                logger.info("Processing batch of {} emails for domain {}", domainEmails.size(), domain);
                
                for (final var email : domainEmails) {
                    final var startTime = System.currentTimeMillis();
                    final var response = bulkEmailCheckerService.validateEmailWithRetry(email, neverbounceApiKey);
                    final var result = convertToValidationResult(response);
                    final var processingTime = System.currentTimeMillis() - startTime;
                    
                    final var verificationResult = new VerificationResult(email, result, processingTime);
                    updateStatusStats(stats, result);
                    sendResultMessage(sessionId, verificationResult);
                    processedCount++;
                    sendStatusUpdate(sessionId, "PROGRESS", processedCount, totalEmails, stats);

                    try {
                        Thread.sleep(100);
                    } catch (final InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }
            }
            
            logger.info("All verification tasks completed for session {}", sessionId);
            sendStatusUpdate(sessionId, "COMPLETED", processedCount, totalEmails, stats);
            
        } catch (final Exception e) {
            logger.error("Error in email processing: {}", e.getMessage(), e);
            sendStatusUpdate(sessionId, "ERROR", 0, totalEmails, 
                Map.of("error", e.getMessage()));
        }
    }

    private ValidationResult convertToValidationResult(final EmailVerificationResponse response) {
        final var details = new HashMap<String, Object>();
        details.put("email", response.getEmail());
        details.put("message", response.getMessage());
        details.put("responseTime", response.getResponseTime());
        
        if (response.getEvent() != null) {
            details.put("event", response.getEvent());
        }
        
        var isCatchAll = false;
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
            return ValidationResult.valid("email", details);
        } else if ("valid".equals(response.getStatus())) {
            details.put("status", "valid");
            return ValidationResult.valid("email", details);
        } else {
            details.put("status", "invalid");
            return ValidationResult.invalid("email", response.getMessage(), details);
        }
    }

    private void updateStatusStats(final Map<String, Object> stats, final ValidationResult result) {
        final var details = result.getDetails();
        
        var status = "";
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
    
    private void incrementStat(final Map<String, Object> stats, final String key) {
        final var current = (int) stats.getOrDefault(key, 0);
        stats.put(key, current + 1);
    }

    private void sendResultMessage(final String sessionId, final VerificationResult result) {
        final var destination = "/topic/verification-result/" + sessionId;
        messagingTemplate.convertAndSend(destination, result.toMap());
    }

    private void sendStatusUpdate(final String sessionId, final String status, final int processed, 
                                final int total, final Map<String, Object> stats) {
        final var destination = "/topic/verification-status/" + sessionId;
        final var update = new HashMap<String, Object>();
        update.put("status", status);
        update.put("processed", processed);
        update.put("total", total);
        update.put("stats", stats);
        update.put("timestamp", System.currentTimeMillis());
        
        messagingTemplate.convertAndSend(destination, update);
    }

    private Map<String, List<String>> groupEmailsByDomain(final List<String> emails) {
        final var emailsByDomain = new HashMap<String, List<String>>();
        
        for (final var email : emails) {
            try {
                final var parts = email.trim().split("@", 2);
                if (parts.length == 2) {
                    final var domain = parts[1].toLowerCase();
                    emailsByDomain.computeIfAbsent(domain, k -> new ArrayList<>()).add(email);
                }
            } catch (final Exception e) {
                logger.warn("Error grouping email {}: {}", email, e.getMessage());
            }
        }
        
        return emailsByDomain;
    }
} 