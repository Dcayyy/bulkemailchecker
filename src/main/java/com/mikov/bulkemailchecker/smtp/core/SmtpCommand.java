package com.mikov.bulkemailchecker.smtp.core;

import java.io.BufferedReader;
import java.io.PrintWriter;

public interface SmtpCommand {
    SmtpResponse execute(BufferedReader in, PrintWriter out);
    String getCommand();
} 