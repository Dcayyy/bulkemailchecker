package com.mikov.bulkemailchecker.smtp.core.commands;

import com.mikov.bulkemailchecker.smtp.core.SmtpCommand;
import com.mikov.bulkemailchecker.smtp.core.SmtpResponse;
import lombok.RequiredArgsConstructor;

import java.io.BufferedReader;
import java.io.PrintWriter;

@RequiredArgsConstructor
public class MailFromCommand implements SmtpCommand {
    private final String email;

    @Override
    public SmtpResponse execute(BufferedReader in, PrintWriter out) {
        out.print("MAIL FROM:<" + email + ">\r\n");
        out.flush();
        try {
            return new SmtpResponse(in.readLine());
        } catch (Exception e) {
            return new SmtpResponse("500 " + e.getMessage());
        }
    }

    @Override
    public String getCommand() {
        return "MAIL FROM: <" + email + ">";
    }
} 