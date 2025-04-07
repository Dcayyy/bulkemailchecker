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
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
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
    private static final long RESPONSE_TIMEOUT_MS = TimeUnit.SECONDS.toMillis(300);
    
    private static final int MAX_CONCURRENT_BATCH_REQUESTS = 5;
    private static final int MAX_CONCURRENT_SINGLE_REQUESTS = 15;
    private static final int MAX_EMAILS_PER_BATCH = 1000;
    private static final int QUEUE_CAPACITY = 50;
    
    private final Semaphore batchRequestThrottler = new Semaphore(MAX_CONCURRENT_BATCH_REQUESTS, true);
    private final Semaphore singleRequestThrottler = new Semaphore(MAX_CONCURRENT_SINGLE_REQUESTS, true);
    
    private final ConcurrentLinkedQueue<PendingRequest> requestQueue = new ConcurrentLinkedQueue<>();
    private final AtomicBoolean queueProcessorRunning = new AtomicBoolean(false);
    
    // Store for tracking in-progress verifications by ID
    private final Map<String, CompletableFuture<EmailVerificationResponse>> pendingVerifications = new ConcurrentHashMap<>();
    
    private final BulkEmailCheckerService bulkEmailCheckerService;
    
    @Autowired
    public BulkEmailCheckerController(final BulkEmailCheckerService bulkEmailCheckerService) {
        this.bulkEmailCheckerService = bulkEmailCheckerService;
    }

    @GetMapping("/verify/{email}")
    public DeferredResult<ResponseEntity<EmailVerificationResponse>> verifyEmail(@PathVariable final String email) {
        final var deferredResult = new DeferredResult<ResponseEntity<EmailVerificationResponse>>(RESPONSE_TIMEOUT_MS);
        
        boolean permitAcquired = singleRequestThrottler.tryAcquire();
        if (permitAcquired) {
            processEmailVerification(email, deferredResult);
        } else {
            if (requestQueue.size() < QUEUE_CAPACITY) {
                logger.info("Queuing email verification request for: {}", email);
                requestQueue.add(new PendingRequest(email, deferredResult, null));
                startQueueProcessor(); // Ensure the queue processor is running
            } else {
                logger.warn("Request queue full, rejecting verification request for email: {}", email);
                deferredResult.setResult(ResponseEntity.status(429)
                    .body(createErrorResponse(email, "Too many requests. Please try again later.")));
            }
        }
        
        return deferredResult;
    }
    
    /**
     * Check the status of a pending verification
     */
    @GetMapping("/status/{verificationId}")
    public ResponseEntity<EmailVerificationResponse> checkVerificationStatus(
            @PathVariable final String verificationId) {
        
        CompletableFuture<EmailVerificationResponse> pendingFuture = pendingVerifications.get(verificationId);
        
        if (pendingFuture == null) {
            return ResponseEntity.notFound().build();
        }
        
        if (pendingFuture.isDone()) {
            try {
                EmailVerificationResponse result = pendingFuture.get();
                // Once retrieved, we can remove it from pending tracking
                pendingVerifications.remove(verificationId);
                return ResponseEntity.ok(result);
            } catch (Exception e) {
                logger.error("Error retrieving verification result for ID {}: {}", verificationId, e.getMessage());
                return ResponseEntity.internalServerError().build();
            }
        } else {
            // Still processing - create a "still pending" response
            EmailVerificationResponse response = EmailVerificationResponse.createPendingResponse(
                    "pending", "Verification still in progress, please check back later");
            return ResponseEntity.accepted().body(response);
        }
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
        
        boolean permitAcquired = batchRequestThrottler.tryAcquire();
        if (permitAcquired) {
            processBatchVerification(request.emails(), deferredResult);
        } else {
            if (requestQueue.size() < QUEUE_CAPACITY) {
                logger.info("Queuing batch verification request for {} emails", request.emails().size());
                requestQueue.add(new PendingRequest(null, null, new BatchRequest(request.emails(), deferredResult)));
                startQueueProcessor(); // Ensure the queue processor is running
            } else {
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
        CompletableFuture<EmailVerificationResponse> future = CompletableFuture.supplyAsync(
                () -> bulkEmailCheckerService.verifyEmail(email))
            .thenApply(response -> {
                // Check if this is a pending verification that needs tracking
                if (response.getRetryStatus() != null && response.getVerificationId() != null) {
                    // Create a new completable future to track the pending verification
                    CompletableFuture<EmailVerificationResponse> pendingFuture = new CompletableFuture<>();
                    pendingVerifications.put(response.getVerificationId(), pendingFuture);
                    
                    // Schedule a cleanup of this pending verification if it's never completed
                    schedulePendingVerificationCleanup(response.getVerificationId(), 
                            TimeUnit.MINUTES.toMillis(10)); // Expire after 10 minutes
                }
                return response;
            });
            
        future.thenAccept(response -> deferredResult.setResult(ResponseEntity.ok(response)))
            .exceptionally(ex -> {
                logger.error("Error verifying email {}: {}", email, ex.getMessage());
                deferredResult.setErrorResult(
                    ResponseEntity.internalServerError().body(createErrorResponse(email, ex.getMessage())));
                return null;
            })
            .whenComplete((r, e) -> {
                singleRequestThrottler.release();
                processNextQueuedRequest();
            });
    }
    
    private void processBatchVerification(final List<String> emails,
            final DeferredResult<ResponseEntity<List<EmailVerificationResponse>>> deferredResult) {
        CompletableFuture<List<EmailVerificationResponse>> future = CompletableFuture.supplyAsync(
                () -> bulkEmailCheckerService.verifyEmails(emails))
            .thenApply(responses -> {
                // Check all responses for pending verifications that need tracking
                for (EmailVerificationResponse response : responses) {
                    if (response.getRetryStatus() != null && response.getVerificationId() != null) {
                        // Create a new completable future to track the pending verification
                        CompletableFuture<EmailVerificationResponse> pendingFuture = new CompletableFuture<>();
                        pendingVerifications.put(response.getVerificationId(), pendingFuture);
                        
                        // Schedule a cleanup of this pending verification if it's never completed
                        schedulePendingVerificationCleanup(response.getVerificationId(), 
                                TimeUnit.MINUTES.toMillis(10)); // Expire after 10 minutes
                    }
                }
                return responses;
            });
            
        future.thenAccept(responses -> deferredResult.setResult(ResponseEntity.ok(responses)))
            .exceptionally(ex -> {
                logger.error("Error verifying emails: {}", ex.getMessage());
                deferredResult.setErrorResult(ResponseEntity.internalServerError().build());
                return null;
            })
            .whenComplete((r, e) -> {
                batchRequestThrottler.release();
                processNextQueuedRequest();
            });
    }
    
    /**
     * Schedule a cleanup task for pending verifications that are never completed
     */
    private void schedulePendingVerificationCleanup(String verificationId, long expiryMillis) {
        CompletableFuture.runAsync(() -> {
            try {
                Thread.sleep(expiryMillis);
                CompletableFuture<EmailVerificationResponse> future = pendingVerifications.remove(verificationId);
                if (future != null && !future.isDone()) {
                    logger.info("Cleaning up expired verification ID: {}", verificationId);
                    // Complete with timeout response
                    EmailVerificationResponse timeoutResponse = new EmailVerificationResponse.Builder("unknown")
                            .withStatus("failed")
                            .withValid(false)
                            .withResultCode("timeout")
                            .withMessage("Verification timed out")
                            .withEvent("verification_timeout")
                            .withResponseTime(0L)
                            .build();
                    future.complete(timeoutResponse);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
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
            if (singleRequestThrottler.tryAcquire()) {
                logger.debug("Processing queued single email request: {}", request.email);
                processEmailVerification(request.email, request.singleResult);
            } else {
                requestQueue.add(request);
                CompletableFuture.delayedExecutor(100, TimeUnit.MILLISECONDS)
                    .execute(this::processNextQueuedRequest);
            }
        } else if (request.batchRequest != null) {
            if (batchRequestThrottler.tryAcquire()) {
                logger.debug("Processing queued batch request with {} emails", request.batchRequest.emails.size());
                processBatchVerification(request.batchRequest.emails, request.batchRequest.deferredResult);
            } else {
                requestQueue.add(request);
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
                .withResponseTime(0L)
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

    private record PendingRequest(String email, DeferredResult<ResponseEntity<EmailVerificationResponse>> singleResult,
                                  BatchRequest batchRequest) {
    }

    private record BatchRequest(List<String> emails,
                                DeferredResult<ResponseEntity<List<EmailVerificationResponse>>> deferredResult) {
    }
}
