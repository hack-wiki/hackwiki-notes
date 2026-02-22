% Filename: 04-web-testing/auth-session/overview.md
% Display name: Auth and Session Overview
% Last update: 2026-02-11
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# Auth and Session

## Overview

Authentication and session management are the gatekeepers of web applications. Flaws in these mechanisms allow attackers to impersonate users, escalate privileges, and access protected resources without valid credentials. These vulnerabilities are consistently among the most impactful findings in penetration tests.

## Topics in This Section

- [Authentication Bypass](authentication-bypass.md) — default credentials, brute force, login logic flaws, 2FA bypass, response manipulation
- [JWT Attacks](jwt.md) — algorithm confusion, weak secrets, header injection (jwk/jku/kid), token forgery
- [OAuth Vulnerabilities](oauth.md) — redirect_uri manipulation, authorization code theft, CSRF, scope abuse, token leakage
- [Password Reset Vulnerabilities](password-reset.md) — token predictability, host header poisoning, token leakage via referer, account takeover chains
- [Insecure Direct Object Reference (IDOR)](idor.md) — horizontal/vertical privilege escalation, parameter tampering, reference manipulation across contexts
- [Session Attacks](session-attacks.md) — session fixation, hijacking, prediction, cookie security flags, session management flaws
