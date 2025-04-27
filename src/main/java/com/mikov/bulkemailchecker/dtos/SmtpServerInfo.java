package com.mikov.bulkemailchecker.dtos;

/**
 * Data object containing SMTP server information.
 *
 * @author zahari.mikov
 */
public record SmtpServerInfo(String hostname, String ipAddress, String provider) {
}