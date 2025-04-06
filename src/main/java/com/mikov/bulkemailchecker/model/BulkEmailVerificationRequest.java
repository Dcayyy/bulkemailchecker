package com.mikov.bulkemailchecker.model;

import java.util.List;

/**
 * Request model for bulk email verification
 *
 * @author zahari.mikov
 */
public record BulkEmailVerificationRequest(List<String> emails) {
}