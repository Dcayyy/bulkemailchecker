package com.mikov.bulkemailchecker.smtp.core;

public enum SmtpResponseCode {
    SUCCESS(200, 299),
    TEMPORARY_FAILURE(400, 499),
    PERMANENT_FAILURE(500, 599);

    private final int min;
    private final int max;

    SmtpResponseCode(int min, int max) {
        this.min = min;
        this.max = max;
    }

    public boolean matches(int code) {
        return code >= min && code <= max;
    }

    public static SmtpResponseCode fromCode(int code) {
        for (SmtpResponseCode responseCode : values()) {
            if (responseCode.matches(code)) {
                return responseCode;
            }
        }
        return null;
    }
} 