% Filename: 09-mobile-security/common/api-testing.md
% Display name: Mobile API Testing
% Last update: 2026-02-11
% Authors: @TristanInSec

# Mobile API Testing

## Overview

Mobile apps communicate with backend APIs for authentication, data retrieval,
and business logic. Testing the API layer is a critical part of any mobile
security assessment — client-side controls can be bypassed, so server-side
validation is the real security boundary. This file covers intercepting mobile
API traffic and testing for common API vulnerabilities.

## Setting Up Traffic Interception

### Proxy Configuration

```bash
# Android: set system proxy via ADB
adb shell settings put global http_proxy <burp_ip>:8080

# Android: remove proxy
adb shell settings put global http_proxy :0

# iOS: configure proxy manually
# Settings > Wi-Fi > (network) > HTTP Proxy > Manual
# Server: <burp_ip>  Port: 8080
```

### Burp Suite Setup

1. Start Burp Suite with proxy listener on `All interfaces` port 8080
2. Export the Burp CA certificate (Proxy > Options > Import/Export CA
   Certificate > Export Certificate in DER format)
3. Install the CA on the device (see Android/iOS setup files)
4. If the app uses SSL pinning, apply a bypass first

### Alternative: mitmproxy

```bash
# Start mitmproxy on all interfaces
mitmproxy --listen-port 8080 --listen-host 0.0.0.0

# Or use mitmdump for scripted interception
mitmdump --listen-port 8080 -s capture_script.py

# View captured traffic in the mitmproxy web interface
mitmweb --listen-port 8080 --web-port 8081
```

## Common API Vulnerabilities

### Broken Object Level Authorization (BOLA / IDOR)

The most common API vulnerability. The app sends an object ID in the request,
and the server does not verify that the authenticated user owns that object.

```bash
# Original request (authenticated as user 123)
GET /api/v1/users/123/profile HTTP/1.1
Authorization: Bearer <token>

# Test: change the user ID
GET /api/v1/users/124/profile HTTP/1.1
Authorization: Bearer <token>
# If the server returns user 124's profile, BOLA is confirmed
```

Test by:
1. Identifying endpoints that use object IDs (user IDs, order IDs, file IDs)
2. Changing the ID while keeping the same authentication token
3. Checking if the server returns data belonging to another user

### Broken Authentication

```bash
# Test: access endpoints without authentication
GET /api/v1/admin/users HTTP/1.1
# No Authorization header — does the server still respond?

# Test: reuse expired tokens
GET /api/v1/users/123/profile HTTP/1.1
Authorization: Bearer <expired_token>

# Test: use tokens from a different user context
GET /api/v1/admin/settings HTTP/1.1
Authorization: Bearer <regular_user_token>
```

### Mass Assignment

The API accepts more parameters than intended, allowing attackers to set
fields they should not control.

```bash
# Original registration request
POST /api/v1/register HTTP/1.1
Content-Type: application/json

{"username": "newuser", "password": "pass123", "email": "user@test.com"}

# Test: add extra fields
POST /api/v1/register HTTP/1.1
Content-Type: application/json

{"username": "newuser", "password": "pass123", "email": "user@test.com",
 "role": "admin", "isAdmin": true, "verified": true}
```

### Excessive Data Exposure

The API returns more data than the client displays. The mobile app filters
data client-side, but the full response is visible in the proxy.

```bash
# The app shows only the user's name and avatar
# But the API response contains:
{
    "id": 123,
    "name": "John Doe",
    "email": "john@example.com",
    "avatar": "...",
    "ssn": "123-45-6789",
    "credit_card": "4111111111111111",
    "internal_notes": "VIP customer, discount applied"
}
```

Always inspect the full API response in the proxy — the app may hide
sensitive fields that are still being transmitted.

### Rate Limiting

```bash
# Test: send multiple rapid requests to sensitive endpoints
# Login endpoint — potential brute force
POST /api/v1/login HTTP/1.1

# OTP verification — potential bypass
POST /api/v1/verify-otp HTTP/1.1

# Password reset — potential abuse
POST /api/v1/forgot-password HTTP/1.1

# Use Burp Intruder or a script to send 100+ requests
# and check if the server applies rate limiting
```

### Insecure Direct Object References in File Access

```bash
# Test: access other users' files
GET /api/v1/files/document_12345.pdf HTTP/1.1
Authorization: Bearer <user_a_token>

# Change the file ID
GET /api/v1/files/document_12346.pdf HTTP/1.1
Authorization: Bearer <user_a_token>
```

## Mobile-Specific API Issues

### Hardcoded API Keys

Mobile apps often embed API keys in the binary. These keys should be
considered public — extract them during static analysis and test what access
they provide.

```bash
# Search for API keys in decompiled Android source
grep -rni 'x-api-key\|apikey\|api_key\|Authorization' output_dir/sources/

# Search in iOS binary strings
strings extracted/Payload/Target.app/Target | grep -iE 'api.key|bearer|x-api'
```

### Client-Side Validation Only

Mobile apps sometimes enforce business rules client-side (e.g., limiting
purchase quantity, enforcing discount rules). Always test by sending modified
requests directly through the proxy.

```bash
# The app limits quantity to 1-10 on the UI
# Test: send quantity outside the expected range
POST /api/v1/orders HTTP/1.1
Content-Type: application/json

{"product_id": 42, "quantity": -1, "price": 0.01}
```

### API Versioning Issues

```bash
# The app uses v3 of the API
GET /api/v3/users/123 HTTP/1.1

# Test: try older API versions that may lack security controls
GET /api/v1/users/123 HTTP/1.1
GET /api/v2/users/123 HTTP/1.1
```

Older API versions may not have authentication checks, rate limiting, or
input validation that was added in newer versions.

### Token Storage and Transmission

Check where the app stores authentication tokens:

| Location | Risk Level | Notes |
|---|---|---|
| SharedPreferences (Android) | Medium | Accessible with root |
| NSUserDefaults (iOS) | Medium | Accessible with jailbreak |
| Android Keystore | Low | Hardware-backed on supported devices |
| iOS Keychain | Low | Depends on accessibility attribute |
| SQLite database | High | Often stored in plaintext |
| Logcat / NSLog | High | Tokens visible in device logs |

```bash
# Android: check for tokens in logcat
adb logcat | grep -iE 'bearer|token|jwt|session'

# Android: check shared preferences
adb shell cat /data/data/com.example.app/shared_prefs/*.xml | grep -i token
```

## Testing with Burp Suite

### Useful Burp Extensions for Mobile API Testing

- **Autorize** — automated authorization testing (checks if requests succeed
  with a lower-privileged token)
- **JSON Web Token Attacker** — JWT manipulation and attack automation
- **InQL** — GraphQL introspection and testing (if the API uses GraphQL)
- **Logger++** — enhanced logging with filters for mobile traffic

### Workflow

1. Configure the device proxy to Burp
2. Browse the app normally — Burp captures all API requests in the HTTP
   History
3. Review each endpoint in the Sitemap
4. Send interesting requests to Repeater for manual testing
5. Use Intruder for parameter fuzzing and BOLA testing
6. Check responses for excessive data exposure

## References

### Official Documentation

- [OWASP API Security Top 10](https://owasp.org/API-Security/)
- [OWASP MASTG — Network Communication](https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0011/)

### Tools

- [Burp Suite](https://portswigger.net/burp)
- [mitmproxy](https://github.com/mitmproxy/mitmproxy)
