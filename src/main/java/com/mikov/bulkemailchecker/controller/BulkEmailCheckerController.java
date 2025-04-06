package com.mikov.bulkemailchecker.controller;

import com.mikov.bulkemailchecker.model.BulkEmailVerificationRequest;
import com.mikov.bulkemailchecker.model.EmailVerificationResponse;
import com.mikov.bulkemailchecker.services.BulkEmailCheckerService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.request.async.DeferredResult;

import java.util.Collections;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * REST controller for email verification
 */
@RestController
@RequestMapping("/bulkemailchecker")
public class BulkEmailCheckerController {

    private static final Logger logger = LoggerFactory.getLogger(BulkEmailCheckerController.class);
    private static final long RESPONSE_TIMEOUT_MS = TimeUnit.SECONDS.toMillis(30);
    
    private final BulkEmailCheckerService bulkEmailCheckerService;
    
    @Autowired
    public BulkEmailCheckerController(BulkEmailCheckerService bulkEmailCheckerService) {
        this.bulkEmailCheckerService = bulkEmailCheckerService;
    }
    
    /**
     * Verify a single email address - asynchronous endpoint
     * @param email Email to verify
     * @return Deferred result with email verification response
     */
    @GetMapping("/verify/{email}")
    public DeferredResult<ResponseEntity<EmailVerificationResponse>> verifyEmail(@PathVariable String email) {
        logger.info("Received request to verify email: {}", email);
        
        DeferredResult<ResponseEntity<EmailVerificationResponse>> deferredResult = 
            new DeferredResult<>(RESPONSE_TIMEOUT_MS);
        
        // Process verification asynchronously
        CompletableFuture.supplyAsync(() -> bulkEmailCheckerService.verifyEmail(email))
            .thenAccept(response -> deferredResult.setResult(ResponseEntity.ok(response)))
            .exceptionally(ex -> {
                logger.error("Error verifying email {}: {}", email, ex.getMessage());
                deferredResult.setErrorResult(
                    ResponseEntity.internalServerError().body(createErrorResponse(email, ex.getMessage())));
                return null;
            });
        
        return deferredResult;
    }
    
    /**
     * Verify multiple email addresses - asynchronous endpoint
     * @param request Bulk email verification request
     * @return Deferred result with list of email verification responses
     */
    @PostMapping(value = "/verify", consumes = MediaType.APPLICATION_JSON_VALUE)
    public DeferredResult<ResponseEntity<List<EmailVerificationResponse>>> verifyEmails(
            @RequestBody BulkEmailVerificationRequest request) {
        if (request == null || request.getEmails() == null || request.getEmails().isEmpty()) {
            logger.warn("Received empty request for bulk email verification");
            
            DeferredResult<ResponseEntity<List<EmailVerificationResponse>>> emptyResult = 
                new DeferredResult<>(RESPONSE_TIMEOUT_MS);
            emptyResult.setResult(ResponseEntity.badRequest().body(Collections.emptyList()));
            return emptyResult;
        }
        
        logger.info("Received request to verify {} emails", request.getEmails().size());
        
        DeferredResult<ResponseEntity<List<EmailVerificationResponse>>> deferredResult = 
            new DeferredResult<>(RESPONSE_TIMEOUT_MS);
        
        // Process bulk verification asynchronously
        CompletableFuture.supplyAsync(() -> bulkEmailCheckerService.verifyEmails(request.getEmails()))
            .thenAccept(responses -> deferredResult.setResult(ResponseEntity.ok(responses)))
            .exceptionally(ex -> {
                logger.error("Error verifying emails: {}", ex.getMessage());
                deferredResult.setErrorResult(ResponseEntity.internalServerError().build());
                return null;
            });
        
        return deferredResult;
    }
    
    /**
     * Create an error response for failed verification
     */
    private EmailVerificationResponse createErrorResponse(String email, String message) {
        return new EmailVerificationResponse.Builder(email)
                .withStatus("failed")
                .withValid(false)
                .withResultCode("error")
                .withMessage("Server error: " + message)
                .withResponseTime(0)
                .withDisposable(false)
                .withRole(false)
                .withSubAddressing(false)
                .withFree(false)
                .withSpam(false)
                .withHasMx(false)
                .withCountry("")
                .withSmtpServer("")
                .withIpAddress("")
                .withAdditionalInfo("")
                .build();
    }
}
