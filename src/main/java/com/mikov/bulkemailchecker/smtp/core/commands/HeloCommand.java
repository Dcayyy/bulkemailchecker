package com.mikov.bulkemailchecker.smtp.core.commands;

import com.mikov.bulkemailchecker.smtp.core.SmtpCommand;
import com.mikov.bulkemailchecker.smtp.core.SmtpResponse;
import lombok.RequiredArgsConstructor;

import java.io.BufferedReader;
import java.io.PrintWriter;

@RequiredArgsConstructor
public class HeloCommand implements SmtpCommand {
    private final String domain;

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
        return "HELO " + domain;
    }
} 