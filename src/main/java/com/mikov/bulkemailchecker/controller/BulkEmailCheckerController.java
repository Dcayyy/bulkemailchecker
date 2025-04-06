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
 * 
 * @author zahari.mikov
 */
@RestController
@RequestMapping("/bulkemailchecker")
public class BulkEmailCheckerController {

    private static final Logger logger = LoggerFactory.getLogger(BulkEmailCheckerController.class);
    private static final long RESPONSE_TIMEOUT_MS = TimeUnit.SECONDS.toMillis(120);
    
    private final BulkEmailCheckerService bulkEmailCheckerService;
    
    @Autowired
    public BulkEmailCheckerController(final BulkEmailCheckerService bulkEmailCheckerService) {
        this.bulkEmailCheckerService = bulkEmailCheckerService;
    }

    @GetMapping("/verify/{email}")
    public DeferredResult<ResponseEntity<EmailVerificationResponse>> verifyEmail(@PathVariable final String email) {
        logger.info("Received request to verify email: {}", email);
        
        final var deferredResult = new DeferredResult<ResponseEntity<EmailVerificationResponse>>(RESPONSE_TIMEOUT_MS);
        
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

    @PostMapping(value = "/verify", consumes = MediaType.APPLICATION_JSON_VALUE)
    public DeferredResult<ResponseEntity<List<EmailVerificationResponse>>> verifyEmails(
            @RequestBody final BulkEmailVerificationRequest request) {
        if (request == null || request.emails() == null || request.emails().isEmpty()) {
            logger.warn("Received empty request for bulk email verification");
            
            final var emptyResult = new DeferredResult<ResponseEntity<List<EmailVerificationResponse>>>(RESPONSE_TIMEOUT_MS);
            emptyResult.setResult(ResponseEntity.badRequest().body(Collections.emptyList()));
            return emptyResult;
        }
        
        logger.info("Received request to verify {} emails", request.emails().size());
        
        final var deferredResult = new DeferredResult<ResponseEntity<List<EmailVerificationResponse>>>(RESPONSE_TIMEOUT_MS);
        
        CompletableFuture.supplyAsync(() -> bulkEmailCheckerService.verifyEmails(request.emails()))
            .thenAccept(responses -> deferredResult.setResult(ResponseEntity.ok(responses)))
            .exceptionally(ex -> {
                logger.error("Error verifying emails: {}", ex.getMessage());
                deferredResult.setErrorResult(ResponseEntity.internalServerError().build());
                return null;
            });
        
        return deferredResult;
    }

    private EmailVerificationResponse createErrorResponse(final String email, final String message) {
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
