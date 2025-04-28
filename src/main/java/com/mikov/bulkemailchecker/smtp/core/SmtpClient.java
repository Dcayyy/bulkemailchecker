package com.mikov.bulkemailchecker.smtp.core;

import com.mikov.bulkemailchecker.smtp.model.ProxyConfig;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.util.Properties;

@Slf4j
@Component
@Getter
public class SmtpClient {
    private static final int DEFAULT_PORT = 25;
    private static final int DEFAULT_TIMEOUT = 30000;
    private static final int MAX_PROXY_RETRIES = 3;

    private final String host;
    private final int port;
    private final int timeout;
    private final ProxyManager proxyManager;
    private Socket socket;
    private BufferedReader in;
    private PrintWriter out;
    private String ipAddress;
    private ProxyConfig currentProxy;

    public SmtpClient(String host, ProxyManager proxyManager) {
        this(host, DEFAULT_PORT, DEFAULT_TIMEOUT, proxyManager);
    }

    public SmtpClient(String host, int port, int timeout, ProxyManager proxyManager) {
        this.host = host;
        this.port = port;
        this.timeout = timeout;
        this.proxyManager = proxyManager;
    }

    public void connect() throws Exception {
        log.debug("Connecting to SMTP server {}:{}", host, port);
        int proxyRetryCount = 0;
        Exception lastException = null;

        while (proxyRetryCount < MAX_PROXY_RETRIES) {
            try {
                socket = createSocket(host, port);
                socket.setSoTimeout(timeout);
                in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                out = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));
                ipAddress = socket.getInetAddress().getHostAddress();
                readResponse(); // Read initial server greeting
                return;
            } catch (Exception e) {
                lastException = e;
                proxyRetryCount++;
                log.warn("Failed to connect through proxy {} (attempt {}/{}): {}", 
                    currentProxy.getHost(), proxyRetryCount, MAX_PROXY_RETRIES, e.getMessage());
                
                if (socket != null) {
                    try {
                        socket.close();
                    } catch (Exception ex) {
                        log.debug("Error closing failed socket: {}", ex.getMessage());
                    }
                }
            }
        }

        throw new Exception("Failed to connect after " + MAX_PROXY_RETRIES + " proxy attempts. Last error: " + 
            (lastException != null ? lastException.getMessage() : "Unknown error"));
    }

    public SmtpResponse executeCommand(SmtpCommand command) throws Exception {
        log.debug("Executing command: {}", command);
        String response = sendCommand(command.getCommand());
        return new SmtpResponse(response);
    }

    public String sendCommand(String command) throws Exception {
        log.debug("Sending command: {}", command);
        out.println(command);
        out.flush();
        return readResponse();
    }

    private String readResponse() throws Exception {
        StringBuilder response = new StringBuilder();
        String line;
        while ((line = in.readLine()) != null) {
            response.append(line).append("\n");
            if (line.charAt(3) != '-') {
                break;
            }
        }
        return response.toString().trim();
    }

    public void disconnect() throws Exception {
        if (socket != null && !socket.isClosed()) {
            try {
                sendCommand("QUIT");
            } catch (Exception e) {
                log.warn("Error sending QUIT command: {}", e.getMessage());
            }
            socket.close();
        }
    }

    public boolean isConnected() {
        return socket != null && socket.isConnected() && !socket.isClosed();
    }

    public Socket createSocket(String host, int port) throws Exception {
        currentProxy = proxyManager.getNextAvailableProxy();
        log.info("Using proxy {}:{} for SMTP connection to {}:{}", 
            currentProxy.getHost(), currentProxy.getPort(), host, port);

        try {
            Socket socket = new Socket();
            SocketAddress proxyAddress = new InetSocketAddress(currentProxy.getHost(), currentProxy.getPort());
            socket.connect(proxyAddress, timeout);
            socket.setSoTimeout(timeout);

            // Authenticate with proxy if needed
            if (currentProxy.getUsername() != null && currentProxy.getPassword() != null) {
                authenticateProxy(socket, currentProxy);
            }

            proxyManager.markProxySuccess(currentProxy);
            return socket;
        } catch (Exception e) {
            proxyManager.markProxyFailure(currentProxy);
            log.error("Failed to connect through proxy {}:{} - {}", 
                currentProxy.getHost(), currentProxy.getPort(), e.getMessage());
            throw e;
        }
    }

    private void authenticateProxy(Socket socket, ProxyConfig proxy) throws Exception {
        // Implement SOCKS5 authentication
        byte[] authRequest = new byte[]{
            (byte) 0x05, // SOCKS version
            (byte) 0x01, // Number of authentication methods
            (byte) 0x02  // Username/password authentication
        };
        
        socket.getOutputStream().write(authRequest);
        byte[] authResponse = new byte[2];
        socket.getInputStream().read(authResponse);
        
        if (authResponse[1] == (byte) 0x02) {
            // Send username/password
            byte[] username = proxy.getUsername().getBytes();
            byte[] password = proxy.getPassword().getBytes();
            
            byte[] authDetails = new byte[3 + username.length + password.length];
            authDetails[0] = 0x01; // Version of username/password authentication
            authDetails[1] = (byte) username.length;
            System.arraycopy(username, 0, authDetails, 2, username.length);
            authDetails[2 + username.length] = (byte) password.length;
            System.arraycopy(password, 0, authDetails, 3 + username.length, password.length);
            
            socket.getOutputStream().write(authDetails);
            byte[] authResult = new byte[2];
            socket.getInputStream().read(authResult);
            
            if (authResult[1] != 0x00) {
                throw new Exception("Proxy authentication failed");
            }
        }
    }

    public Properties getSessionProperties() {
        Properties props = new Properties();
        props.put("mail.smtp.connectiontimeout", timeout);
        props.put("mail.smtp.timeout", timeout);
        props.put("mail.smtp.writetimeout", timeout);
        return props;
    }
} 