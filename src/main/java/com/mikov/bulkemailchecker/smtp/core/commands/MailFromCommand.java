package com.mikov.bulkemailchecker.smtp.core.commands;

import com.mikov.bulkemailchecker.smtp.core.SmtpCommand;
import com.mikov.bulkemailchecker.smtp.core.SmtpResponse;

import java.io.BufferedReader;
import java.io.PrintWriter;

public class MailFromCommand implements SmtpCommand {
    private final String fromEmail;

    public MailFromCommand(String fromEmail) {
        this.fromEmail = fromEmail;
    }

    @Override
    public SmtpResponse execute(BufferedReader in, PrintWriter out) {
        out.print("MAIL FROM:<" + fromEmail + ">\r\n");
        out.flush();
        try {
            return new SmtpResponse(in.readLine());
        } catch (Exception e) {
            return new SmtpResponse("500 " + e.getMessage());
        }
    }

    @Override
    public String getCommand() {
        return "MAIL FROM";
    }
} 