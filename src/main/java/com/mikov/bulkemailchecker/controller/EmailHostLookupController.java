package com.mikov.bulkemailchecker.controller;

import com.mikov.bulkemailchecker.service.EmailProviderDetectionService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/bulkemailchecker")
public class EmailHostLookupController {

    private final EmailProviderDetectionService emailProviderDetectionService;

    public EmailHostLookupController(EmailProviderDetectionService emailProviderDetectionService) {
        this.emailProviderDetectionService = emailProviderDetectionService;
    }

    @PostMapping("/email-host-lookup")
    public ResponseEntity<?> detectEmailProvider(@RequestBody EmailRequest request) {
        if (request.getEmail() == null || request.getEmail().isEmpty()) {
            return ResponseEntity.badRequest().body(new ErrorResponse("Email field is required."));
        }

        try {
            var result = emailProviderDetectionService.detectEmailProvider(request.getEmail());
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(new ErrorResponse(
                "Error detecting email provider",
                e.getMessage()
            ));
        }
    }

    public static class EmailRequest {
        private String email;

        public String getEmail() {
            return email;
        }

        public void setEmail(String email) {
            this.email = email;
        }
    }

    public static class ErrorResponse {
        private String error;
        private String details;

        public ErrorResponse(String error) {
            this.error = error;
        }

        public ErrorResponse(String error, String details) {
            this.error = error;
            this.details = details;
        }

        public String getError() {
            return error;
        }

        public String getDetails() {
            return details;
        }
    }
} 