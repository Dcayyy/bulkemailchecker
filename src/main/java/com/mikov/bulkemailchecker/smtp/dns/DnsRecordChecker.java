package com.mikov.bulkemailchecker.smtp.dns;

import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.util.Hashtable;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class DnsRecordChecker {
    private static final int DNS_TIMEOUT = 1000;
    private static final int DNS_RETRIES = 1;
    private static final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();

    public Map<String, Object> checkRecords(String domain) {
        Map<String, Object> details = new java.util.HashMap<>();
        boolean hasDnsIssues = false;

        try {
            CompletableFuture<String> spfFuture = checkSpfRecord(domain);
            CompletableFuture<String> dmarcFuture = checkDmarcRecord(domain);
            CompletableFuture<String> dkimFuture = checkDkimRecord(domain);

            String spfRecord = spfFuture.get(3, TimeUnit.SECONDS);
            String dmarcRecord = dmarcFuture.get(3, TimeUnit.SECONDS);
            String dkimRecord = dkimFuture.get(3, TimeUnit.SECONDS);

            if (spfRecord == null || spfRecord.isEmpty()) {
                details.put("spf_record", "missing");
                hasDnsIssues = true;
            } else {
                details.put("spf_record", "present");
                details.put("spf_policy", determineSpfPolicy(spfRecord));
            }

            if (dmarcRecord == null || dmarcRecord.isEmpty()) {
                details.put("dmarc_record", "missing");
                hasDnsIssues = true;
            } else {
                details.put("dmarc_record", "present");
                details.put("dmarc_policy", determineDmarcPolicy(dmarcRecord));
            }

            details.put("dkim_record", dkimRecord != null && !dkimRecord.isEmpty() ? "present" : "not_found");
            details.put("has_dns_issues", hasDnsIssues);

        } catch (Exception e) {
            details.put("dns_check_error", e.getMessage());
        }

        return details;
    }

    private CompletableFuture<String> checkSpfRecord(String domain) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return getTxtRecord(domain, "v=spf1");
            } catch (NamingException e) {
                return null;
            }
        }, executor);
    }

    private CompletableFuture<String> checkDmarcRecord(String domain) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return getTxtRecord("_dmarc." + domain, "v=DMARC1");
            } catch (NamingException e) {
                return null;
            }
        }, executor);
    }

    private CompletableFuture<String> checkDkimRecord(String domain) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return getTxtRecord("default._domainkey." + domain, "v=DKIM1");
            } catch (NamingException e) {
                return null;
            }
        }, executor);
    }

    private String getTxtRecord(String domain, String prefix) throws NamingException {
        Hashtable<String, String> env = new Hashtable<>();
        env.put("com.sun.jndi.dns.timeout.initial", String.valueOf(DNS_TIMEOUT));
        env.put("com.sun.jndi.dns.timeout.retries", String.valueOf(DNS_RETRIES));
        
        DirContext ctx = new InitialDirContext(env);
        Attributes attrs = ctx.getAttributes("dns:/" + domain, new String[] {"TXT"});
        javax.naming.directory.Attribute attr = attrs.get("TXT");
        
        if (attr != null) {
            for (int i = 0; i < attr.size(); i++) {
                String record = (String) attr.get(i);
                if (record.contains(prefix)) {
                    return record;
                }
            }
        }
        return null;
    }

    private String determineSpfPolicy(String spfRecord) {
        if (spfRecord.contains("-all")) return "strict";
        if (spfRecord.contains("~all")) return "soft_fail";
        if (spfRecord.contains("?all")) return "neutral";
        if (spfRecord.contains("+all")) return "allow_all";
        return "unknown";
    }

    private String determineDmarcPolicy(String dmarcRecord) {
        if (dmarcRecord.contains("p=reject")) return "reject";
        if (dmarcRecord.contains("p=quarantine")) return "quarantine";
        if (dmarcRecord.contains("p=none")) return "none";
        return "unknown";
    }
} 