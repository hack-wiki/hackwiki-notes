% Filename: 02-reconnaissance/enum-web/websocket.md
% Display name: WebSocket Enumeration
% Last update: 2026-02-10
% ATT&CK Tactics: TA0043 (Reconnaissance)
% ATT&CK Techniques: T1595 (Active Scanning)
% Authors: @TristanInSec

# WebSocket Enumeration

## Overview

WebSocket (WS on TCP 80, WSS on TCP 443) provides full-duplex communication between client and server over a single persistent connection. Unlike standard HTTP request-response, WebSocket maintains an open channel for real-time data exchange. Applications using WebSocket include chat systems, live dashboards, gaming, trading platforms, and collaborative tools. WebSocket connections are initiated via an HTTP Upgrade handshake, then switch to the WebSocket protocol.

## ATT&CK Mapping

- **Tactic:** TA0043 - Reconnaissance
- **Technique:** T1595 - Active Scanning

## Prerequisites

- Network access to target TCP 80/443
- Tools: websocat, Burp Suite, or browser developer tools
- WebSocket endpoints are often discovered during HTTP enumeration (JavaScript source review)

## Enumeration Techniques

### Detection

WebSocket endpoints are not discoverable by port scanning — they use the same ports as HTTP. Detection requires:

```bash
# Look for WebSocket references in JavaScript files
curl -s http://<target>/ | grep -i "websocket\|ws://\|wss://"

# Check for Upgrade headers in HTTP responses
curl -i -N \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  http://<target>/ws
```

A successful WebSocket handshake returns HTTP 101 Switching Protocols.

Common WebSocket endpoint paths:

| Path | Usage |
|------|-------|
| /ws | Generic WebSocket |
| /socket.io/ | Socket.IO framework |
| /sockjs/ | SockJS fallback |
| /hub | SignalR (.NET) |
| /cable | ActionCable (Rails) |
| /graphql | GraphQL subscriptions |
| /api/ws | API WebSocket |

### websocat

```bash
# websocat
# https://github.com/vi/websocat
# Not on Kali by default — install from releases page
# Download the linux x86_64 binary from GitHub releases

# websocat
# https://github.com/vi/websocat
# Connect to a WebSocket
websocat ws://<target>/ws

# Connect to secure WebSocket
websocat wss://<target>/ws

# Send a message and read response
echo '{"type":"ping"}' | websocat ws://<target>/ws

# With custom headers
websocat -H "Authorization: Bearer <token>" ws://<target>/ws

# With Origin header (bypass CORS-like checks)
websocat --origin http://<target> ws://<target>/ws
```

Once connected, type messages to send them. Responses appear in real-time. Use Ctrl+C to disconnect.

### Browser Developer Tools

The most practical WebSocket enumeration approach:

1. Open browser Developer Tools (F12)
2. Navigate to the target application
3. Go to **Network** tab → filter by **WS**
4. Interact with the application to trigger WebSocket connections
5. Click on the WebSocket connection to view Messages tab
6. Observe message format, authentication tokens, and data structures

This reveals the exact message format the application expects, which is essential for crafting test payloads.

### Burp Suite

Burp Suite (both Community and Professional) supports WebSocket interception:

1. Configure browser proxy to Burp (127.0.0.1:8080)
2. Navigate to the target application
3. WebSocket messages appear in **Proxy > WebSocket history**
4. Right-click messages to **Send to Repeater** for manipulation
5. Modify and resend messages to test for authorization bypass, injection, etc.

### Manual Handshake Analysis

```bash
# Capture the WebSocket upgrade request
curl -v -i -N \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  http://<target>/ws 2>&1 | head -30
```

Key handshake elements to examine:

| Element | What to check |
|---------|---------------|
| Sec-WebSocket-Accept | Server confirms WebSocket support |
| Sec-WebSocket-Protocol | Sub-protocol negotiation (may reveal functionality) |
| Sec-WebSocket-Extensions | Compression or other extensions |
| Cookie / Authorization | Authentication mechanism used |
| Origin validation | Whether server validates Origin header |

## Post-Enumeration

With WebSocket access, prioritize:
- Message format analysis — understand the protocol to craft test payloads
- Authentication testing — can you connect without valid credentials or tokens?
- Authorization testing — can you access other users' data by modifying message parameters?
- Input validation — test for injection (SQLi, XSS, command injection) in WebSocket messages
- Cross-Site WebSocket Hijacking (CSWSH) — check if Origin header is validated
- Rate limiting — WebSocket connections may bypass HTTP rate limiting

For detailed WebSocket attack techniques, see `04-web-testing/api-testing/websocket.md`.

## References

### Official Documentation

- [websocat](https://github.com/vi/websocat)
- [RFC 6455 - The WebSocket Protocol](https://datatracker.ietf.org/doc/html/rfc6455)

### Pentest Guides & Research

- [OWASP Testing for WebSockets](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets)

### MITRE ATT&CK

- [T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)
