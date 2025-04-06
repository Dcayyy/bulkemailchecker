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
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.ConcurrentLinkedQueue;

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
    
    // Limit concurrent batch verification requests
    private static final int MAX_CONCURRENT_BATCH_REQUESTS = 5;
    private static final int MAX_CONCURRENT_SINGLE_REQUESTS = 15;
    private static final int MAX_EMAILS_PER_BATCH = 25;
    private static final int QUEUE_CAPACITY = 50;
    
    private final Semaphore batchRequestThrottler = new Semaphore(MAX_CONCURRENT_BATCH_REQUESTS, true);
    private final Semaphore singleRequestThrottler = new Semaphore(MAX_CONCURRENT_SINGLE_REQUESTS, true);
    
    // Queue for handling requests that exceed the concurrent limit
    private final ConcurrentLinkedQueue<PendingRequest> requestQueue = new ConcurrentLinkedQueue<>();
    private final AtomicBoolean queueProcessorRunning = new AtomicBoolean(false);
    
    private final BulkEmailCheckerService bulkEmailCheckerService;
    
    @Autowired
    public BulkEmailCheckerController(final BulkEmailCheckerService bulkEmailCheckerService) {
        this.bulkEmailCheckerService = bulkEmailCheckerService;
    }

    @GetMapping("/verify/{email}")
    public DeferredResult<ResponseEntity<EmailVerificationResponse>> verifyEmail(@PathVariable final String email) {
        final var deferredResult = new DeferredResult<ResponseEntity<EmailVerificationResponse>>(RESPONSE_TIMEOUT_MS);
        
        // Try to acquire a permit immediately
        boolean permitAcquired = singleRequestThrottler.tryAcquire();
        if (permitAcquired) {
            processEmailVerification(email, deferredResult);
        } else {
            // If we can't get a permit immediately, try to queue the request
            if (requestQueue.size() < QUEUE_CAPACITY) {
                logger.info("Queuing email verification request for: {}", email);
                requestQueue.add(new PendingRequest(email, deferredResult, null));
                startQueueProcessor(); // Ensure the queue processor is running
            } else {
                // If the queue is full, return a throttling response
                logger.warn("Request queue full, rejecting verification request for email: {}", email);
                deferredResult.setResult(ResponseEntity.status(429)
                    .body(createErrorResponse(email, "Too many requests. Please try again later.")));
            }
        }
        
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
        
        // Limit batch size
        if (request.emails().size() > MAX_EMAILS_PER_BATCH) {
            logger.warn("Batch email verification request exceeds maximum allowed size: {} emails", request.emails().size());
            final var errorResult = new DeferredResult<ResponseEntity<List<EmailVerificationResponse>>>(RESPONSE_TIMEOUT_MS);
            errorResult.setResult(ResponseEntity.badRequest()
                .body(Collections.singletonList(createErrorResponse("batch", 
                       "Batch size exceeds maximum allowed (" + MAX_EMAILS_PER_BATCH + " emails)"))));
            return errorResult;
        }
        
        logger.info("Received request to verify {} emails", request.emails().size());
        
        final var deferredResult = new DeferredResult<ResponseEntity<List<EmailVerificationResponse>>>(RESPONSE_TIMEOUT_MS);
        
        // Try to acquire a permit immediately
        boolean permitAcquired = batchRequestThrottler.tryAcquire();
        if (permitAcquired) {
            processBatchVerification(request.emails(), deferredResult);
        } else {
            // If we can't get a permit immediately, try to queue the request
            if (requestQueue.size() < QUEUE_CAPACITY) {
                logger.info("Queuing batch verification request for {} emails", request.emails().size());
                requestQueue.add(new PendingRequest(null, null, new BatchRequest(request.emails(), deferredResult)));
                startQueueProcessor(); // Ensure the queue processor is running
            } else {
                // If the queue is full, return a throttling response
                logger.warn("Request queue full, rejecting batch verification of {} emails", request.emails().size());
                deferredResult.setResult(ResponseEntity.status(429)
                    .body(Collections.singletonList(createErrorResponse("batch", 
                        "Too many requests. Please try again later."))));
            }
        }
        
        return deferredResult;
    }
    
    private void processEmailVerification(final String email, 
            final DeferredResult<ResponseEntity<EmailVerificationResponse>> deferredResult) {
        CompletableFuture.supplyAsync(() -> bulkEmailCheckerService.verifyEmail(email))
            .thenAccept(response -> deferredResult.setResult(ResponseEntity.ok(response)))
            .exceptionally(ex -> {
                logger.error("Error verifying email {}: {}", email, ex.getMessage());
                deferredResult.setErrorResult(
                    ResponseEntity.internalServerError().body(createErrorResponse(email, ex.getMessage())));
                return null;
            })
            .whenComplete((r, e) -> {
                singleRequestThrottler.release(); // Always release permit
                processNextQueuedRequest(); // Process next request from queue
            });
    }
    
    private void processBatchVerification(final List<String> emails,
            final DeferredResult<ResponseEntity<List<EmailVerificationResponse>>> deferredResult) {
        CompletableFuture.supplyAsync(() -> bulkEmailCheckerService.verifyEmails(emails))
            .thenAccept(responses -> deferredResult.setResult(ResponseEntity.ok(responses)))
            .exceptionally(ex -> {
                logger.error("Error verifying emails: {}", ex.getMessage());
                deferredResult.setErrorResult(ResponseEntity.internalServerError().build());
                return null;
            })
            .whenComplete((r, e) -> {
                batchRequestThrottler.release(); // Always release permit
                processNextQueuedRequest(); // Process next request from queue
            });
    }
    
    private synchronized void startQueueProcessor() {
        if (queueProcessorRunning.compareAndSet(false, true)) {
            CompletableFuture.runAsync(this::processNextQueuedRequest);
        }
    }
    
    private void processNextQueuedRequest() {
        PendingRequest request = requestQueue.poll();
        if (request == null) {
            queueProcessorRunning.set(false);
            return;
        }
        
        queueProcessorRunning.set(true);
        
        if (request.email != null) {
            // Handle single email request
            if (singleRequestThrottler.tryAcquire()) {
                logger.debug("Processing queued single email request: {}", request.email);
                processEmailVerification(request.email, request.singleResult);
            } else {
                // Put it back in the queue if we can't process it yet
                requestQueue.add(request);
                // Wait briefly before trying again
                CompletableFuture.delayedExecutor(100, TimeUnit.MILLISECONDS)
                    .execute(this::processNextQueuedRequest);
            }
        } else if (request.batchRequest != null) {
            // Handle batch request
            if (batchRequestThrottler.tryAcquire()) {
                logger.debug("Processing queued batch request with {} emails", request.batchRequest.emails.size());
                processBatchVerification(request.batchRequest.emails, request.batchRequest.deferredResult);
            } else {
                // Put it back in the queue if we can't process it yet
                requestQueue.add(request);
                // Wait briefly before trying again
                CompletableFuture.delayedExecutor(100, TimeUnit.MILLISECONDS)
                    .execute(this::processNextQueuedRequest);
            }
        }
    }

    private DeferredResult<ResponseEntity<EmailVerificationResponse>> createErrorDeferredResult(String email, String message) {
        final var result = new DeferredResult<ResponseEntity<EmailVerificationResponse>>(RESPONSE_TIMEOUT_MS);
        result.setResult(ResponseEntity.status(429).body(createErrorResponse(email, message)));
        return result;
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
                .withEvent("inconclusive")
                .build();
    }
    
    /**
     * Helper class to store pending requests in the queue
     */
    private static class PendingRequest {
        final String email;
        final DeferredResult<ResponseEntity<EmailVerificationResponse>> singleResult;
        final BatchRequest batchRequest;
        
        PendingRequest(String email, 
                      DeferredResult<ResponseEntity<EmailVerificationResponse>> singleResult,
                      BatchRequest batchRequest) {
            this.email = email;
            this.singleResult = singleResult;
            this.batchRequest = batchRequest;
        }
    }
    
    /**
     * Helper class to store batch request details
     */
    private static class BatchRequest {
        final List<String> emails;
        final DeferredResult<ResponseEntity<List<EmailVerificationResponse>>> deferredResult;
        
        BatchRequest(List<String> emails, 
                   DeferredResult<ResponseEntity<List<EmailVerificationResponse>>> deferredResult) {
            this.emails = emails;
            this.deferredResult = deferredResult;
        }
    }
}
