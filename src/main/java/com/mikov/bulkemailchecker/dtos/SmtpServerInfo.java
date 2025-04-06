package com.mikov.bulkemailchecker.dtos;

/**
 * Data object containing SMTP server information.
 * 
 * @author zahari.mikov
 */
public class SmtpServerInfo {
    private final String hostname;
    private final String ipAddress;
    private final String provider;
    
    public SmtpServerInfo(final String hostname, final String ipAddress, final String provider) {
        this.hostname = hostname;
        this.ipAddress = ipAddress;
        this.provider = provider;
    }
    
    public String getHostname() {
        return hostname;
    }
    
    public String getIpAddress() {
        return ipAddress;
    }
    
    public String getProvider() {
        return provider;
    }
} 