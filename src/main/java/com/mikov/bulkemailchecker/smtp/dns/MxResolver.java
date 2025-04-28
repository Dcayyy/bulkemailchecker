package com.mikov.bulkemailchecker.smtp.dns;

import lombok.RequiredArgsConstructor;

import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Hashtable;
import java.util.List;

@RequiredArgsConstructor
public class MxResolver {
    private static final int DNS_TIMEOUT = 2000;
    private static final int DNS_RETRIES = 1;

    public List<MxRecord> resolve(String domain) throws NamingException {
        Hashtable<String, String> env = new Hashtable<>();
        env.put("com.sun.jndi.dns.timeout.initial", String.valueOf(DNS_TIMEOUT));
        env.put("com.sun.jndi.dns.timeout.retries", String.valueOf(DNS_RETRIES));
        
        DirContext ctx = new InitialDirContext(env);
        Attributes attrs = ctx.getAttributes("dns:/" + domain, new String[] {"MX"});
        javax.naming.directory.Attribute attr = attrs.get("MX");
        
        if (attr == null || attr.size() == 0) {
            return new ArrayList<>();
        }
        
        List<MxRecord> mxRecords = new ArrayList<>();
        for (int i = 0; i < attr.size(); i++) {
            String mxRecord = (String) attr.get(i);
            String[] parts = mxRecord.split("\\s+");
            if (parts.length >= 2) {
                int priority = Integer.parseInt(parts[0]);
                String hostname = parts[1];
                mxRecords.add(new MxRecord(hostname, priority));
            }
        }
        
        mxRecords.sort(Comparator.comparingInt(MxRecord::priority));
        return mxRecords;
    }

    public record MxRecord(String hostname, int priority) { }
} 