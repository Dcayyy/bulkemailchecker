package com.mikov.bulkemailchecker.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketTransportRegistration;

/**
 * WebSocket configuration to enable real-time email verification status updates
 */
@Configuration
@EnableWebSocketMessageBroker
public class WebSocketConfig implements WebSocketMessageBrokerConfigurer {
    
    private static final Logger logger = LoggerFactory.getLogger(WebSocketConfig.class);

    @Override
    public void configureMessageBroker(MessageBrokerRegistry config) {
        // Enable a simple in-memory message broker for sending messages back to the client
        // Client subscribes to these destinations to receive messages
        config.enableSimpleBroker("/topic", "/queue");
        
        // Prefix for client-to-server messages
        config.setApplicationDestinationPrefixes("/app");
        
        logger.info("WebSocket message broker configured with topics: /topic, /queue");
    }

    @Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        // Register the "/ws-emailverifier" endpoint, enabling SockJS fallback options
        registry.addEndpoint("/ws-emailverifier")
                .setAllowedOriginPatterns("*") // For development - restrict in production
                .withSockJS();
        
        logger.info("WebSocket STOMP endpoint registered at /ws-emailverifier");
    }
    
    @Override
    public void configureWebSocketTransport(WebSocketTransportRegistration registration) {
        registration.setMessageSizeLimit(64 * 1024) // 64KB
                    .setSendBufferSizeLimit(512 * 1024) // 512KB
                    .setSendTimeLimit(20000); // 20 seconds
        
        logger.info("WebSocket transport configured with expanded limits");
    }
} 