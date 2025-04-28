package com.mikov.bulkemailchecker.smtp.core;

import lombok.Getter;

@Getter
public class SmtpResponse {
    private final int code;
    private final String message;
    private final SmtpResponseCode type;
    private final boolean isTempError;

    public SmtpResponse(String response) {
        this.code = extractCode(response);
        this.message = response;
        this.type = SmtpResponseCode.fromCode(code);
        this.isTempError = determineIfTempError(code, response);
    }

    private int extractCode(String response) {
        if (response == null || response.length() < 3) {
            return 0;
        }
        try {
            return Integer.parseInt(response.substring(0, 3));
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private boolean determineIfTempError(int code, String response) {
        if (code >= 400 && code < 500) {
            return true;
        }
        if (code == 550) {
            String lowerResponse = response.toLowerCase();
            return lowerResponse.contains("try again") ||
                   lowerResponse.contains("try later") ||
                   lowerResponse.contains("unavailable") ||
                   lowerResponse.contains("temporarily");
        }
        return false;
    }

    public boolean isSuccess() {
        return type == SmtpResponseCode.SUCCESS;
    }

    public boolean isTemporaryFailure() {
        return type == SmtpResponseCode.TEMPORARY_FAILURE;
    }

    public boolean isPermanentFailure() {
        return type == SmtpResponseCode.PERMANENT_FAILURE;
    }
} 