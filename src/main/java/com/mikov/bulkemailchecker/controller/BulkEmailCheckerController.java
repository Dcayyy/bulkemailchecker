package com.mikov.bulkemailchecker.controller;

import com.mikov.bulkemailchecker.model.BulkEmailVerificationRequest;
import com.mikov.bulkemailchecker.model.EmailVerificationResponse;
import com.mikov.bulkemailchecker.model.SimplifiedEmailResponse;
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
import java.util.stream.Collectors;

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
    public DeferredResult<ResponseEntity<SimplifiedEmailResponse>> verifyEmail(@PathVariable final String email) {
        final var deferredResult = new DeferredResult<ResponseEntity<SimplifiedEmailResponse>>(RESPONSE_TIMEOUT_MS);
        
        boolean permitAcquired = singleRequestThrottler.tryAcquire();
        if (permitAcquired) {
            processSimplifiedEmailVerification(email, deferredResult);
        } else {
            if (requestQueue.size() < QUEUE_CAPACITY) {
                logger.info("Queuing email verification request for: {}", email);
                requestQueue.add(new PendingRequest(email, deferredResult, null));
                startQueueProcessor(); // Ensure the queue processor is running
            } else {
                logger.warn("Request queue full, rejecting verification request for email: {}", email);
                // Create a simplified error response
                EmailVerificationResponse errorResponse = createErrorResponse(email, "Too many requests. Please try again later.");
                deferredResult.setResult(ResponseEntity.status(429)
                    .body(SimplifiedEmailResponse.from(errorResponse)));
            }
        }
        
        return deferredResult;
    }
    
    /**
     * Check the status of a pending verification
     */
    @GetMapping("/status/{verificationId}")
    public ResponseEntity<SimplifiedEmailResponse> checkVerificationStatus(
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
                return ResponseEntity.ok(SimplifiedEmailResponse.from(result));
            } catch (Exception e) {
                logger.error("Error retrieving verification result for ID {}: {}", verificationId, e.getMessage());
                return ResponseEntity.internalServerError().build();
            }
        } else {
            // Still processing - create a "still pending" response
            EmailVerificationResponse response = EmailVerificationResponse.createPendingResponse(
                    "pending", "Verification still in progress, please check back later");
            return ResponseEntity.accepted().body(SimplifiedEmailResponse.from(response));
        }
    }

    @PostMapping(value = "/verify", consumes = MediaType.APPLICATION_JSON_VALUE)
    public DeferredResult<ResponseEntity<List<SimplifiedEmailResponse>>> verifyEmails(
            @RequestBody final BulkEmailVerificationRequest request) {
        if (request == null || request.emails() == null || request.emails().isEmpty()) {
            logger.warn("Received empty request for bulk email verification");
            
            final var emptyResult = new DeferredResult<ResponseEntity<List<SimplifiedEmailResponse>>>(RESPONSE_TIMEOUT_MS);
            emptyResult.setResult(ResponseEntity.badRequest().body(Collections.emptyList()));
            return emptyResult;
        }
        
        if (request.emails().size() > MAX_EMAILS_PER_BATCH) {
            logger.warn("Batch email verification request exceeds maximum allowed size: {} emails", request.emails().size());
            final var errorResult = new DeferredResult<ResponseEntity<List<SimplifiedEmailResponse>>>(RESPONSE_TIMEOUT_MS);
            EmailVerificationResponse errorResponse = createErrorResponse("batch", 
                   "Batch size exceeds maximum allowed (" + MAX_EMAILS_PER_BATCH + " emails)");
            errorResult.setResult(ResponseEntity.badRequest()
                .body(Collections.singletonList(SimplifiedEmailResponse.from(errorResponse))));
            return errorResult;
        }
        
        logger.info("Received request to verify {} emails", request.emails().size());
        
        final var deferredResult = new DeferredResult<ResponseEntity<List<SimplifiedEmailResponse>>>(RESPONSE_TIMEOUT_MS);
        
        boolean permitAcquired = batchRequestThrottler.tryAcquire();
        if (permitAcquired) {
            processSimplifiedBatchVerification(request.emails(), deferredResult);
        } else {
            if (requestQueue.size() < QUEUE_CAPACITY) {
                logger.info("Queuing batch verification request for {} emails", request.emails().size());
                requestQueue.add(new PendingRequest(null, null, new SimplifiedBatchRequest(request.emails(), deferredResult)));
                startQueueProcessor(); // Ensure the queue processor is running
            } else {
                logger.warn("Request queue full, rejecting batch verification of {} emails", request.emails().size());
                EmailVerificationResponse errorResponse = createErrorResponse("batch", 
                    "Too many requests. Please try again later.");
                deferredResult.setResult(ResponseEntity.status(429)
                    .body(Collections.singletonList(SimplifiedEmailResponse.from(errorResponse))));
            }
        }
        
        return deferredResult;
    }
    
    private void processSimplifiedEmailVerification(final String email, 
            final DeferredResult<ResponseEntity<SimplifiedEmailResponse>> deferredResult) {
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
            
        future.thenAccept(response -> deferredResult.setResult(ResponseEntity.ok(SimplifiedEmailResponse.from(response))))
            .exceptionally(ex -> {
                logger.error("Error verifying email {}: {}", email, ex.getMessage());
                EmailVerificationResponse errorResponse = createErrorResponse(email, ex.getMessage());
                deferredResult.setErrorResult(
                    ResponseEntity.internalServerError().body(SimplifiedEmailResponse.from(errorResponse)));
                return null;
            })
            .whenComplete((r, e) -> {
                singleRequestThrottler.release();
                processNextQueuedRequest();
            });
    }
    
    private void processSimplifiedBatchVerification(final List<String> emails,
            final DeferredResult<ResponseEntity<List<SimplifiedEmailResponse>>> deferredResult) {
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
        
        future.thenAccept(responses -> {
                // Convert to simplified responses
                List<SimplifiedEmailResponse> simplifiedResponses = responses.stream()
                    .map(SimplifiedEmailResponse::from)
                    .collect(Collectors.toList());
                
                deferredResult.setResult(ResponseEntity.ok(simplifiedResponses));
            })
            .exceptionally(ex -> {
                logger.error("Error verifying batch emails: {}", ex.getMessage());
                EmailVerificationResponse errorResponse = createErrorResponse("batch", ex.getMessage());
                deferredResult.setErrorResult(ResponseEntity.internalServerError()
                    .body(Collections.singletonList(SimplifiedEmailResponse.from(errorResponse))));
                return null;
            })
            .whenComplete((r, e) -> {
                batchRequestThrottler.release();
                processNextQueuedRequest();
            });
    }
    
    private void schedulePendingVerificationCleanup(String verificationId, long expiryMillis) {
        // Schedule a task to clean up pending verifications that are never completed
        CompletableFuture.runAsync(() -> {
            try {
                Thread.sleep(expiryMillis);
                CompletableFuture<EmailVerificationResponse> pendingFuture = pendingVerifications.get(verificationId);
                if (pendingFuture != null && !pendingFuture.isDone()) {
                    // Attempt to complete with a timeout error
                    pendingFuture.complete(createErrorResponse("expired", 
                        "Verification timeout after " + (expiryMillis / 60000) + " minutes"));
                    pendingVerifications.remove(verificationId);
                    logger.warn("Expired pending verification: {}", verificationId);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
    }

    private synchronized void startQueueProcessor() {
        if (!queueProcessorRunning.getAndSet(true)) {
            processNextQueuedRequest();
        }
    }
    
    private void processNextQueuedRequest() {
        PendingRequest pendingRequest = requestQueue.poll();
        if (pendingRequest == null) {
            queueProcessorRunning.set(false);
            return;
        }
        
        try {
            // Process single email verification
            if (pendingRequest.email() != null && pendingRequest.singleResult() != null) {
                if (singleRequestThrottler.tryAcquire()) {
                    @SuppressWarnings("unchecked")
                    DeferredResult<ResponseEntity<SimplifiedEmailResponse>> deferredResult = 
                        (DeferredResult<ResponseEntity<SimplifiedEmailResponse>>) pendingRequest.singleResult();
                    processSimplifiedEmailVerification(pendingRequest.email(), deferredResult);
                } else {
                    // If we can't acquire a permit, put it back in the queue and try later
                    requestQueue.add(pendingRequest);
                    Thread.sleep(100); // Short delay before retrying
                    startQueueProcessor();
                }
            } 
            // Process batch verification
            else if (pendingRequest.batchRequest() != null) {
                if (batchRequestThrottler.tryAcquire()) {
                    SimplifiedBatchRequest batchRequest = (SimplifiedBatchRequest) pendingRequest.batchRequest();
                    processSimplifiedBatchVerification(batchRequest.emails(), batchRequest.deferredResult());
                } else {
                    // If we can't acquire a permit, put it back in the queue and try later
                    requestQueue.add(pendingRequest);
                    Thread.sleep(100); // Short delay before retrying
                    startQueueProcessor();
                }
            }
        } catch (Exception e) {
            logger.error("Error processing queued request: {}", e.getMessage());
        }
        
        // Process next request in queue
        processNextQueuedRequest();
    }
    
    private DeferredResult<ResponseEntity<SimplifiedEmailResponse>> createErrorDeferredResult(String email, String message) {
        final var result = new DeferredResult<ResponseEntity<SimplifiedEmailResponse>>();
        result.setResult(ResponseEntity.status(400).body(SimplifiedEmailResponse.from(createErrorResponse(email, message))));
        return result;
    }
    
    private EmailVerificationResponse createErrorResponse(final String email, final String message) {
        final var builder = new EmailVerificationResponse.Builder(email)
                .withValid(false)
                .withStatus("error")
                .withResultCode("error")
                .withMessage(message);
                
        return builder.build();
    }
    
    private record PendingRequest(String email, Object singleResult, Object batchRequest) {
    }
    
    private record SimplifiedBatchRequest(List<String> emails,
                                DeferredResult<ResponseEntity<List<SimplifiedEmailResponse>>> deferredResult) {
    }
}
