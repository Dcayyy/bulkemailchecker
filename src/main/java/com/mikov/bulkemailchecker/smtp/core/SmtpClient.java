package com.mikov.bulkemailchecker.smtp.core;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;

@Getter
@RequiredArgsConstructor
public class SmtpClient {
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
        socket = new Socket();
        socket.connect(new java.net.InetSocketAddress(host, port), timeout);
        socket.setSoTimeout(timeout);
        in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        out = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()), true);
        
        SmtpResponse response = new SmtpResponse(in.readLine());
        if (!response.isSuccess()) {
            throw new Exception("Failed to connect to SMTP server: " + response.getMessage());
        }
    }

    public SmtpResponse executeCommand(SmtpCommand command) throws Exception {
        if (socket == null || !socket.isConnected()) {
            throw new IllegalStateException("Not connected to SMTP server");
        }
        return command.execute(in, out);
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
            // Ignore errors during disconnect
        } finally {
            try {
                if (socket != null) {
                    socket.close();
                }
            } catch (Exception e) {
                // Ignore errors during socket close
            }
        }
    }

    public boolean isConnected() {
        return socket != null && socket.isConnected() && !socket.isClosed();
    }
} 