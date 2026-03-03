% Filename: 04-web-testing/client-side/overview.md
% Display name: Client-Side Attacks
% Last update: 2026-02-11
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# Client-Side Attacks

## Overview

Client-side vulnerabilities exploit the trust relationship between a user's browser and the web application. Unlike server-side injection (which targets back-end interpreters), client-side attacks execute in the victim's browser context — stealing sessions, performing actions on behalf of users, or exfiltrating sensitive data. Testing focuses on how the application handles user input in rendered HTML/JavaScript and how it enforces cross-origin boundaries.

## Topics in This Section

- [Cross-Site Scripting (XSS)](xss.md)
- [Cross-Site Request Forgery (CSRF)](csrf.md)
- [Cross-Origin Resource Sharing (CORS) Misconfiguration](cors.md)
- [Clickjacking](clickjacking.md)

## General Approach

1. **Map the attack surface** — identify where user input appears in rendered HTML, JavaScript, or HTTP responses (reflected, stored, DOM sinks)
2. **Identify output context** — determine whether input lands in HTML body, attribute values, JavaScript strings, URLs, or CSS (each requires different payloads)
3. **Test origin policies** — check CORS headers, SameSite cookie attributes, X-Frame-Options, and CSP for misconfigurations
4. **Validate defenses** — test CSRF tokens, Content-Security-Policy enforcement, and frame-busting scripts for bypass opportunities
5. **Chain vulnerabilities** — client-side bugs often chain together (e.g., CORS misconfiguration + XSS = full account takeover)
