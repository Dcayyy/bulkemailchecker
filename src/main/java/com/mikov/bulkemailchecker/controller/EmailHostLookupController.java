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
public final class EmailHostLookupController {

    private final EmailProviderDetectionService emailProviderDetectionService;

    public EmailHostLookupController(final EmailProviderDetectionService emailProviderDetectionService) {
        this.emailProviderDetectionService = emailProviderDetectionService;
    }

    @GetMapping("/instance-info")
    public ResponseEntity<Map<String, String>> getInstanceInfo() {
        final var info = new HashMap<String, String>();
        try {
            info.put("hostname", InetAddress.getLocalHost().getHostName());
            info.put("port", System.getProperty("server.port"));
            info.put("instance", "Instance-" + System.getProperty("server.port"));
        } catch (final Exception e) {
            info.put("error", e.getMessage());
        }
        return ResponseEntity.ok(info);
    }

    @PostMapping("/email-host-lookup")
    public ResponseEntity<?> detectEmailProvider(@RequestBody final EmailRequest request) {
        if (request.getEmail() == null || request.getEmail().isEmpty()) {
            return ResponseEntity.badRequest().body(new ErrorResponse("Email field is required."));
        }

        try {
            final var result = emailProviderDetectionService.detectEmailProvider(request.getEmail());
            final var response = new HashMap<String, Object>();
            response.put("result", result);
            response.put("instance", "Instance-" + System.getProperty("server.port"));
            return ResponseEntity.ok(response);
        } catch (final Exception e) {
            return ResponseEntity.internalServerError().body(new ErrorResponse(
                "Error detecting email provider",
                e.getMessage()
            ));
        }
    }

    @Setter
    @Getter
    public static final class EmailRequest {
        private String email;
    }

    @Getter
    public static final class ErrorResponse {
        private final String error;
        private final String details;

        public ErrorResponse(final String error) {
            this.error = error;
            this.details = null;
        }

        public ErrorResponse(final String error, final String details) {
            this.error = error;
            this.details = details;
        }
    }
} 