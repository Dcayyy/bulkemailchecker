# Bulk Email Checker WebSocket API

This document describes how to use the WebSocket API for real-time email verification.

## Overview

The WebSocket API provides a persistent connection that enables:
- Real-time status updates during verification
- Individual result delivery as soon as each email is verified
- Progress tracking for batch operations
- Improved handling of rate-limited verifications

## Connection Details

### WebSocket Endpoint
```
ws://your-server/ws-emailverifier
```

The API uses STOMP protocol over SockJS for broad browser compatibility.

## Message Types

### Client to Server

#### Single Email Verification
```json
{
  "sessionId": "unique-session-id",
  "email": "example@domain.com"
}
```

Send to destination: `/app/verify-email`

#### Batch Email Verification
```json
{
  "sessionId": "unique-session-id", 
  "emails": ["example1@domain.com", "example2@domain.com", "..."]
}
```

Send to destination: `/app/verify-emails`

### Server to Client

Clients should subscribe to their personal verification queue:

```
/queue/verification/{sessionId}
```

The server sends the following types of messages:

#### Started Update
```json
{
  "sessionId": "unique-session-id",
  "type": "STARTED",
  "progress": 0,
  "message": "Verification started for..."
}
```

#### Progress Update
```json
{
  "sessionId": "unique-session-id",
  "type": "PROGRESS",
  "progress": 45,
  "message": "Processed 45 of 100 emails"
}
```

#### Result Update
```json
{
  "sessionId": "unique-session-id",
  "type": "RESULT",
  "progress": 46,
  "message": "Processed 46 of 100 emails",
  "result": {
    "email": "example@domain.com",
    "valid": true,
    "status": "deliverable",
    "resultCode": "success",
    "message": "Email exists and is deliverable",
    "responseTime": 1234,
    "...": "Additional properties"
  }
}
```

#### Completed Update
```json
{
  "sessionId": "unique-session-id",
  "type": "COMPLETED",
  "progress": 100,
  "message": "Verification completed",
  "results": [
    {
      "email": "example1@domain.com",
      "valid": true,
      "...": "Properties"
    },
    {
      "email": "example2@domain.com",
      "valid": false,
      "...": "Properties"
    }
  ]
}
```

#### Error Update
```json
{
  "sessionId": "unique-session-id",
  "type": "ERROR",
  "message": "Error message"
}
```

## Example Client Implementation

This repository includes a sample HTML/JavaScript implementation at:
`/websocket-demo.html`

### Basic JavaScript Example

```javascript
// Connect
const socket = new SockJS('/ws-emailverifier');
const stompClient = Stomp.over(socket);

// Generate a unique session ID
const sessionId = 'session-' + Math.random().toString(36).substr(2, 9);

// Connect and subscribe
stompClient.connect({}, frame => {
  // Subscribe to personal queue
  stompClient.subscribe('/queue/verification/' + sessionId, message => {
    const response = JSON.parse(message.body);
    console.log('Received:', response);
    
    // Handle different update types
    switch(response.type) {
      case 'STARTED':
        // Update UI: Started
        break;
      case 'PROGRESS':
        // Update progress indicator
        break;
      case 'RESULT':
        // Display individual result
        break;
      case 'COMPLETED':
        // Show completion, all results
        break;
      case 'ERROR':
        // Show error
        break;
    }
  });
  
  // Send a verification request
  const request = {
    sessionId: sessionId,
    email: 'example@domain.com'
  };
  
  stompClient.send('/app/verify-email', {}, JSON.stringify(request));
});
```

## Benefits of WebSocket over REST API

1. **Real-time updates**: No need to poll for status
2. **Progressive results**: Get results as they become available
3. **Better handling of long operations**: Maintain connection during rate limiting and retries
4. **Reduced server load**: No polling required for status updates
5. **Improved user experience**: Show progress and individual results immediately

## Error Handling

If the WebSocket connection is lost, clients should implement reconnection logic with exponential backoff. 