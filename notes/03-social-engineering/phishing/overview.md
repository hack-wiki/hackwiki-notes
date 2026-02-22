% Filename: 03-social-engineering/phishing/overview.md
% Display name: Phishing Attacks
% Last update: 2026-02-11
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# Phishing Attacks

## Overview

Phishing uses electronic communications to manipulate targets into revealing
credentials, executing payloads, or performing actions beneficial to the
attacker. In authorized assessments, phishing campaigns measure employee
susceptibility, security awareness training effectiveness, and incident
reporting response times.

All phishing tests require explicit written authorization that defines
target scope, allowable pretexts, payload restrictions, and data handling
procedures for any credentials captured.

## Topics in This Section

- [Email Phishing](email-phishing.md) — campaign setup with GoPhish, email crafting with swaks, credential harvesting
- [Spear Phishing](spear-phishing.md) — targeted attacks, OSINT reconnaissance, evilginx MFA bypass
- [Vishing & Smishing](vishing-smishing.md) — voice and SMS-based social engineering

## General Approach

1. **Scope definition** — agree on targets, pretexts, and success criteria
2. **Reconnaissance** — gather organizational intelligence for realistic pretexts
3. **Infrastructure setup** — domains, mail servers, landing pages
4. **Campaign execution** — send phishing, track opens/clicks/submissions
5. **Reporting** — metrics, captured data (handled per data handling agreement), recommendations
