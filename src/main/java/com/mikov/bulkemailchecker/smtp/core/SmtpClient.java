package com.mikov.bulkemailchecker.smtp.core;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;

@Getter
@RequiredArgsConstructor
public class SmtpClient {
    private static final Logger logger = LoggerFactory.getLogger(SmtpClient.class);
    private static final int DEFAULT_PORT = 25;
    private static final int DEFAULT_TIMEOUT = 5000;

    private final String host;
    private final int port;
    private final int timeout;
    private Socket socket;
    private BufferedReader in;
    private PrintWriter out;

    public SmtpClient(String host) {
        this(host, DEFAULT_PORT, DEFAULT_TIMEOUT);
    }

    public void connect() throws Exception {
        logger.debug("Connecting to SMTP server {}:{}", host, port);
        socket = new Socket();
        socket.connect(new java.net.InetSocketAddress(host, port), timeout);
        socket.setSoTimeout(timeout);
        in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        out = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()), true);
        
        SmtpResponse response = new SmtpResponse(in.readLine());
        logger.debug("Initial SMTP response from {}: {}", host, response.getMessage());
        
        if (response.isTemporaryFailure()) {
            logger.debug("Temporary failure from {}: {}", host, response.getMessage());
            throw new Exception("Temporary SMTP server error: " + response.getMessage());
        }
        
        if (!response.isSuccess()) {
            logger.debug("Failed to connect to {}: {}", host, response.getMessage());
            throw new Exception("Failed to connect to SMTP server: " + response.getMessage());
        }
    }

    public SmtpResponse executeCommand(SmtpCommand command) throws Exception {
        if (socket == null || !socket.isConnected()) {
            throw new IllegalStateException("Not connected to SMTP server");
        }
        logger.debug("Executing SMTP command: {} on {}", command.getCommand(), host);
        SmtpResponse response = command.execute(in, out);
        logger.debug("SMTP command response from {}: {}", host, response.getMessage());
        return response;
    }

    public void disconnect() {
        try {
            if (out != null) {
                out.print("QUIT\r\n");
                out.flush();
            }
            if (in != null) {
                in.readLine();
            }
        } catch (Exception e) {
            logger.debug("Error during SMTP disconnect: {}", e.getMessage());
        } finally {
            try {
                if (socket != null) {
                    socket.close();
                }
            } catch (Exception e) {
                logger.debug("Error closing SMTP socket: {}", e.getMessage());
            }
        }
    }

    public boolean isConnected() {
        return socket != null && socket.isConnected() && !socket.isClosed();
    }
} 