package com.mikov.bulkemailchecker.smtp.core;

import lombok.Getter;

@Getter
public class SmtpResponse {
    private final String response;
    private final int code;
    private final String message;
    private final boolean isSuccess;
    private final boolean isTempError;

    public SmtpResponse(String response) {
        this.response = response;
        this.code = parseCode(response);
        this.message = parseMessage(response);
        this.isSuccess = code >= 200 && code < 300;
        this.isTempError = code >= 400 && code < 500;
    }

    private int parseCode(String response) {
        if (response == null || response.isEmpty()) {
            return 0;
        }
        try {
            return Integer.parseInt(response.substring(0, 3));
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private String parseMessage(String response) {
        if (response == null || response.isEmpty()) {
            return "";
        }
        return response.substring(4).trim();
    }

    public boolean isTemporaryFailure() {
        return isTempError;
    }
} 