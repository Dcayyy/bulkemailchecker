package com.mikov.bulkemailchecker.smtp.core.commands;

import com.mikov.bulkemailchecker.smtp.core.SmtpCommand;
import com.mikov.bulkemailchecker.smtp.core.SmtpResponse;

import java.io.BufferedReader;
import java.io.PrintWriter;

public class RcptToCommand implements SmtpCommand {
    private final String toEmail;

    public RcptToCommand(String toEmail) {
        this.toEmail = toEmail;
    }

    @Override
    public SmtpResponse execute(BufferedReader in, PrintWriter out) {
        out.print("RCPT TO:<" + toEmail + ">\r\n");
        out.flush();
        try {
            return new SmtpResponse(in.readLine());
        } catch (Exception e) {
            return new SmtpResponse("500 " + e.getMessage());
        }
    }

    @Override
    public String getCommand() {
        return "RCPT TO";
    }
} 