% Filename: 12-defensive/incident-response/phishing-ir.md
% Display name: Phishing Incident Response
% Last update: 2026-02-19
% Authors: @TristanInSec

# Phishing Incident Response

## Overview

Phishing incidents are the most common initial access vector for
cyberattacks. A phishing incident response playbook covers email analysis,
determining scope (who else received the email), credential compromise
assessment, malware analysis if applicable, and user notification.
Speed is critical — the faster compromised credentials are reset, the less
time an attacker has to use them.

## Detection and Reporting

```text
How phishing incidents are identified:

User reports:
  - User reports suspicious email (phish button, helpdesk ticket)
  - User reports clicking a link or opening an attachment
  - User reports entering credentials on a suspicious site

Automated detection:
  - Email gateway flags malicious attachment or URL
  - Sandbox detonation identifies malware
  - URL reputation service blocks known phishing domain
  - DMARC/SPF/DKIM failure alerts

Post-compromise detection:
  - Impossible travel alerts (login from unusual location)
  - Mail forwarding rule created (auto-forward to external address)
  - OAuth app consent from suspicious application
  - Multiple failed MFA challenges followed by success
```

## Email Analysis

```text
Analyze the phishing email:

1. Email headers
   - Return-Path and envelope sender (actual source)
   - Received headers (trace the delivery path)
   - X-Originating-IP (source IP of sender)
   - Authentication-Results (SPF, DKIM, DMARC pass/fail)
   - Reply-To (different from From? common in phishing)

2. Sender analysis
   - Is the sender domain legitimate or a lookalike?
   - Is the display name spoofed (different from actual sender)?
   - Was the email sent from a compromised legitimate account?

3. URL analysis
   - Hover/extract all URLs (do NOT click)
   - Check against URL reputation (VirusTotal, URLScan.io)
   - Look for URL shorteners, redirects, or obfuscation
   - Check for credential harvesting forms
   - Analyze the landing page (screenshot, wget to safe environment)

4. Attachment analysis
   - File type and hash
   - Submit to sandbox (VirusTotal, Any.Run, Joe Sandbox)
   - Check for macros (Office documents)
   - Check for embedded scripts (HTML, PDF)
   - Analyze in isolated malware analysis environment
```

### Email Header Analysis

```bash
# Extract key headers from a saved email (.eml file)

# View all headers
grep -E "^(From|To|Subject|Date|Return-Path|Received|X-Originating|Reply-To|Authentication)" email.eml

# Extract URLs from email body
grep -oE 'https?://[^ >"]+' email.eml | sort -u

# Check sender IP reputation
# Extract X-Originating-IP and check with:
# https://www.abuseipdb.com/
# https://www.virustotal.com/

# Check URL reputation
# Submit extracted URLs to:
# https://urlscan.io/
# https://www.virustotal.com/
```

## Scope Assessment

```text
Determine who else received the phishing email:

1. Search email logs for the same:
   - Sender address
   - Subject line
   - Attachment hash
   - URLs in the body
   - Message-ID

2. Identify all recipients
   - Who received the email?
   - Who opened the email?
   - Who clicked the link?
   - Who submitted credentials?
   - Who opened the attachment?

3. Email gateway actions
   - Quarantine or delete the email from all mailboxes
   - Block the sender address/domain
   - Block the phishing URL at the proxy/firewall
   - Block the attachment hash
```

## Credential Compromise Response

```text
If credentials were submitted to a phishing site:

Immediate (within 1 hour):
  1. Reset the user's password immediately
  2. Revoke all active sessions
  3. Reset MFA enrollment (attacker may have enrolled their device)
  4. Disable account temporarily if unsure of scope

Investigation:
  5. Review sign-in logs for unauthorized access
     - Successful logins from unusual IPs or locations
     - Sign-ins from multiple locations simultaneously
  6. Check for persistence in mailbox
     - Email forwarding rules (auto-forward to external address)
     - Inbox rules (move/delete specific emails)
     - OAuth app consents (third-party app access)
     - Delegates with access to mailbox
  7. Check for lateral movement
     - Did the attacker access other systems with these credentials?
     - Were emails sent from the compromised account (BEC)?
     - Were contacts exfiltrated?

Cleanup:
  8. Remove unauthorized forwarding rules and OAuth consents
  9. Notify contacts if phishing was sent from compromised account
  10. Check for credential reuse on other systems
```

## Malware Delivery Response

```text
If the phishing email delivered malware:

1. Identify all systems that executed the malware
   - Check EDR for execution events
   - Search for file hash across endpoints
   - Check email gateway logs for who downloaded the attachment

2. Isolate affected systems
   - Network quarantine via EDR or switch port shutdown
   - Preserve memory before any remediation

3. Analyze the malware
   - Sandbox analysis for behavior (C2, persistence, lateral movement)
   - Extract IOCs (C2 domains/IPs, file hashes, registry keys)

4. Block IOCs
   - Block C2 at firewall and proxy
   - Block file hashes at endpoint protection
   - Add YARA rules for detection

5. Remediate
   - Remove malware from all affected systems
   - Check for persistence mechanisms
   - Reset credentials for users on affected systems
```

## User Communication

```text
Notification to affected users:

If the user reported the phishing:
  - Thank them for reporting
  - Confirm the email was malicious
  - Advise on any required actions (password reset, etc.)

If the user clicked/submitted credentials:
  - Inform them their credentials were compromised
  - Explain the password has been reset
  - Advise them to reset the same password on any other sites where reused
  - Provide guidance on identifying phishing in the future

Organization-wide notification (if broad campaign):
  - Alert all users about the phishing campaign
  - Describe the phishing email (sender, subject, appearance)
  - Include screenshots if helpful
  - Remind users how to report suspicious emails
  - Do NOT share the phishing URL in the notification
```

## Prevention Improvements

```text
After the incident, review and improve:

Technical controls:
  - Email authentication (SPF, DKIM, DMARC enforcement)
  - URL filtering and sandboxing
  - Attachment sandboxing
  - Phishing-resistant MFA (FIDO2, hardware keys)

User awareness:
  - Targeted training for users who clicked
  - Simulated phishing exercises
  - Clear reporting process (phish button, dedicated email)

Detection:
  - New rules based on observed TTPs
  - Improved email gateway policies
  - Enhanced monitoring for credential compromise indicators
```

## References

### Further Reading

- [NIST SP 800-61: Computer Security Incident Handling Guide](https://csrc.nist.gov/pubs/sp/800/61/r2/final)

> **Note:** YARA rules can produce false positives. Tune rules and test against known-clean mail samples before deploying in phishing triage workflows.
