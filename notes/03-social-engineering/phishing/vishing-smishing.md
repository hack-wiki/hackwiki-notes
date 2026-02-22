% Filename: 03-social-engineering/phishing/vishing-smishing.md
% Display name: Vishing & Smishing
% Last update: 2026-02-11
% ATT&CK Tactics: TA0001 (Initial Access), TA0043 (Reconnaissance)
% ATT&CK Techniques: T1566.004 (Spearphishing Voice), T1598.004 (Phishing for Information: Spearphishing Voice)
% Authors: @TristanInSec

# Vishing & Smishing

## Overview

Vishing (voice phishing) uses phone calls to manipulate targets into revealing
information or performing actions. Smishing (SMS phishing) delivers phishing
messages via text. Both exploit the immediacy and perceived trust of phone
communications compared to email.

In authorized assessments, vishing and smishing test employee resilience
against voice-based and SMS-based social engineering — a vector that bypasses
email security controls entirely.

## ATT&CK Mapping

- **Tactic:** TA0001 - Initial Access
- **Technique:** T1566.004 - Spearphishing Voice
- **Tactic:** TA0043 - Reconnaissance
- **Technique:** T1598.004 - Phishing for Information: Spearphishing Voice

## Prerequisites

- Written authorization explicitly covering voice and/or SMS phishing
- Pre-approved call scripts and SMS message templates
- Target phone numbers (provided by client or from OSINT)
- Understanding of recording consent laws in the testing jurisdiction

> **Rules of engagement — critical legal considerations:**
>
> - **Recording laws** — many jurisdictions require all-party consent to record
>   phone calls. Confirm recording rules before any vishing test. When in doubt,
>   do not record; rely on written notes instead.
> - **Caller ID spoofing** — spoofing caller ID may be illegal in some
>   jurisdictions for deceptive purposes. Confirm legality and include in RoE.
> - **Pre-approved scripts** — vishing scripts must be approved by the client.
>   Never improvise pretexts involving threats, law enforcement, or emergencies.
> - **Employee welfare** — if a target becomes distressed during a call,
>   disengage immediately. Do not pressure resistant targets.

## Vishing Techniques

### Call Pretexts

Common pretexts used in authorized vishing assessments:

| Pretext | Target | Objective |
|---|---|---|
| IT helpdesk | General employees | Obtain credentials for "system migration" |
| Security team | All staff | "Verify identity" by confirming password |
| Vendor support | Finance/procurement | Confirm bank details or approve transaction |
| Executive assistant | Admin staff | Request urgent document or access |
| Building management | Reception/facilities | Obtain visitor access procedures |

### Vishing Call Structure

A structured vishing call typically follows this pattern:

1. **Introduction** — identify yourself using the pre-approved pretext
2. **Rapport building** — reference real organizational details (department names, systems, recent events)
3. **Authority/urgency** — establish a reason for the request (deadline, security incident, system maintenance)
4. **Information request** — ask for the target information (credentials, access codes, procedures)
5. **Graceful exit** — thank the target and close the call naturally

### Documentation During Calls

Since call recording may not be permitted, document:

- Date, time, and duration of each call
- Target name/role (or identifier per reporting rules)
- Pretext used
- Information disclosed or action taken by target
- Whether the target challenged or escalated the call
- Exact quotes where possible (write immediately after the call)

## Smishing Techniques

### SMS Message Crafting

SMS messages are limited in length, so they rely on urgency and a call to
action:

- **Credential harvesting** — "IT Alert: Your account has been flagged. Verify at [link]"
- **Callback phishing** — "Voicemail from [Executive Name]. Call back at [number]"
- **MFA code harvesting** — "Your verification code is needed to complete enrollment. Reply with code."

> **Note:** SMS-based MFA code harvesting (requesting a target reply with
> their 2FA code) should only be tested with explicit authorization that
> covers MFA bypass scenarios.

### Delivery Considerations

- SMS sender ID spoofing capabilities vary by carrier and jurisdiction
- Short URLs reduce message length but may be flagged by mobile security
- Timing matters — messages sent during business hours from "IT" are more credible
- Delivery receipts and link click tracking require purpose-built infrastructure

## Detection Methods

- Employee awareness of unexpected calls requesting credentials or sensitive information
- Caller ID verification procedures for sensitive requests
- Call-back verification to known numbers before disclosing information
- Mobile device management (MDM) with SMS filtering capabilities
- Centralized reporting mechanism for suspicious calls and texts

## Mitigation Strategies

- Train employees to verify caller identity through independent channels (call back to known number)
- Establish a policy: IT/security will never ask for passwords over the phone
- Implement callback verification procedures for any sensitive phone requests
- Deploy SMS filtering on corporate mobile devices
- Create a clear escalation path for suspicious calls (report to security team)
- Conduct regular vishing simulations to maintain awareness

## References

### MITRE ATT&CK

- [T1566.004 — Spearphishing Voice](https://attack.mitre.org/techniques/T1566/004/)
- [T1598.004 — Phishing for Information: Spearphishing Voice](https://attack.mitre.org/techniques/T1598/004/)

### Frameworks

- [Social-Engineer.org — Attack Vectors](https://www.social-engineer.org/framework/attack-vectors/)
