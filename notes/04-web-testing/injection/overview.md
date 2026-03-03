% Filename: 04-web-testing/injection/overview.md
% Display name: Injection Attacks
% Last update: 2026-02-11
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# Injection Attacks

## Overview

Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. The attacker's input changes the intended execution — extracting data, executing system commands, or bypassing logic. Injection consistently ranks among the most critical web vulnerabilities (OWASP Top 10).

Testing methodology: identify input points (parameters, headers, cookies, JSON fields), determine the back-end technology, then apply injection techniques appropriate to that interpreter.

## Topics in This Section

- [SQL Injection](sql-injection.md)
- [Command Injection](command-injection.md)
- [Server-Side Template Injection (SSTI)](ssti.md)
- [XML External Entity (XXE) Injection](xxe.md)
- [LDAP Injection](ldap-injection.md)
- [NoSQL Injection](nosql-injection.md)

## General Approach

1. **Map inputs** — identify all user-controlled data reaching back-end interpreters (URL params, POST body, headers, cookies, JSON/XML fields)
2. **Fingerprint the stack** — determine the DBMS, language, framework, and template engine through error messages, response behavior, and headers
3. **Test boundary characters** — submit interpreter-specific metacharacters (`'`, `"`, `{{`, `${`, `<`, `;`, `|`) and observe changes in response (errors, timing, content differences)
4. **Confirm injection** — use benign proofs (math expressions, string concatenation, time delays) before attempting data extraction
5. **Escalate** — move from proof-of-concept to data extraction, file read/write, or command execution depending on the injection type and privilege level
