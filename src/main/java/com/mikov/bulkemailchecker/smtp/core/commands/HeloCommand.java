package com.mikov.bulkemailchecker.smtp.core.commands;

import com.mikov.bulkemailchecker.smtp.core.SmtpCommand;
import com.mikov.bulkemailchecker.smtp.core.SmtpResponse;

import java.io.BufferedReader;
import java.io.PrintWriter;

public class HeloCommand implements SmtpCommand {
    private final String domain;

    public HeloCommand(String domain) {
        this.domain = domain;
    }

    @Override
    public SmtpResponse execute(BufferedReader in, PrintWriter out) {
        out.print("HELO " + domain + "\r\n");
        out.flush();
        try {
            return new SmtpResponse(in.readLine());
        } catch (Exception e) {
            return new SmtpResponse("500 " + e.getMessage());
        }
    }

    @Override
    public String getCommand() {
        return "HELO";
    }
} 