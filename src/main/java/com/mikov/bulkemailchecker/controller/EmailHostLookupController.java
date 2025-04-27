package com.mikov.bulkemailchecker.controller;

import com.mikov.bulkemailchecker.service.EmailProviderDetectionService;
import lombok.Getter;
import lombok.Setter;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.InetAddress;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/bulkemailchecker")
public class EmailHostLookupController {

    private final EmailProviderDetectionService emailProviderDetectionService;

    public EmailHostLookupController(EmailProviderDetectionService emailProviderDetectionService) {
        this.emailProviderDetectionService = emailProviderDetectionService;
    }

    @GetMapping("/instance-info")
    public ResponseEntity<Map<String, String>> getInstanceInfo() {
        Map<String, String> info = new HashMap<>();
        try {
            info.put("hostname", InetAddress.getLocalHost().getHostName());
            info.put("port", System.getProperty("server.port"));
            info.put("instance", "Instance-" + System.getProperty("server.port"));
        } catch (Exception e) {
            info.put("error", e.getMessage());
        }
        return ResponseEntity.ok(info);
    }

    @PostMapping("/email-host-lookup")
    public ResponseEntity<?> detectEmailProvider(@RequestBody EmailRequest request) {
        if (request.getEmail() == null || request.getEmail().isEmpty()) {
            return ResponseEntity.badRequest().body(new ErrorResponse("Email field is required."));
        }

        try {
            var result = emailProviderDetectionService.detectEmailProvider(request.getEmail());
            Map<String, Object> response = new HashMap<>();
            response.put("result", result);
            response.put("instance", "Instance-" + System.getProperty("server.port"));
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(new ErrorResponse(
                "Error detecting email provider",
                e.getMessage()
            ));
        }
    }

    @Setter
    @Getter
    public static class EmailRequest {
        private String email;

    }

    @Getter
    public static class ErrorResponse {
        private final String error;
        private String details;

        public ErrorResponse(String error) {
            this.error = error;
        }

        public ErrorResponse(String error, String details) {
            this.error = error;
            this.details = details;
        }

    }
} 