% Filename: 02-reconnaissance/enum-network/smtp.md
% Display name: SMTP Enumeration
% Last update: 2026-02-10
% ATT&CK Tactics: TA0043 (Reconnaissance)
% ATT&CK Techniques: T1595 (Active Scanning), T1589.002 (Gather Victim Identity Information: Email Addresses)
% Authors: @TristanInSec

# SMTP Enumeration

## Overview

SMTP runs on TCP 25 (plaintext), TCP 465 (SMTPS), and TCP 587 (submission). Enumeration targets banner grabbing for software version, user enumeration via VRFY/EXPN/RCPT TO commands, and open relay detection. Misconfigured mail servers frequently leak valid usernames and allow unauthenticated relay.

## ATT&CK Mapping

- **Tactic:** TA0043 - Reconnaissance
- **Technique:** T1595 - Active Scanning
- **Technique:** T1589.002 - Gather Victim Identity Information: Email Addresses

## Prerequisites

- Network access to target SMTP port(s)
- Nmap or netcat/telnet installed
- Wordlist of usernames for enumeration (e.g., SecLists)

## Enumeration Techniques

### Banner Grabbing

```bash
nc -nv <target> 25
```

Expected output:
```text
220 mail.example.com ESMTP Postfix (Ubuntu)
```

The banner often reveals the MTA software (Postfix, Exim, Sendmail, Exchange) and OS. Issue `EHLO test` after connecting to enumerate supported extensions:

```text
EHLO test
```

Expected output (truncated):
```text
250-mail.example.com
250-PIPELINING
250-SIZE 10240000
250-VRFY
250-ETRN
250-STARTTLS
250-AUTH PLAIN LOGIN
250 DSN
```

Extensions like `VRFY`, `EXPN`, and `AUTH` types are key findings for further enumeration. Note: servers can advertise `VRFY` in the EHLO response but return `252 2.0.0` (ambiguous) for all users regardless — a common anti-enumeration technique. Verify VRFY actually distinguishes valid from invalid users before relying on it.

### User Enumeration — VRFY

The VRFY command confirms whether a mailbox exists on the server.

```text
VRFY root
252 2.0.0 root

VRFY nonexistentuser
550 5.1.1 <nonexistentuser>: Recipient address rejected
```

A `250` or `252` response indicates a valid user. A `550` indicates the user does not exist.

### User Enumeration — EXPN

The EXPN command expands mailing lists into individual members.

```text
EXPN admin
250 2.1.5 admin@example.com

EXPN postmaster
250 2.1.5 <postmaster@example.com>, <admin@example.com>
```

EXPN is frequently disabled but worth testing.

### User Enumeration — RCPT TO

When VRFY and EXPN are disabled, RCPT TO can be used to enumerate valid recipients:

```text
MAIL FROM:<test@test.com>
250 OK
RCPT TO:<admin@example.com>
250 OK

RCPT TO:<fakeuser@example.com>
550 Unknown user
```

A `250` response to RCPT TO confirms the recipient exists. This method works on most SMTP servers even when VRFY/EXPN are disabled.

### Nmap Service Detection

```bash
# Nmap
# https://nmap.org/
nmap -sV -p 25,465,587 --script smtp-commands <target>
```

Expected output (truncated):
```text
25/tcp  open  smtp  Postfix smtpd
| smtp-commands: mail.example.com, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS,
|   AUTH PLAIN LOGIN, ENHANCEDSTATUSCODES, 8BITMIME, DSN
```

### Nmap NSE Scripts

```bash
# Nmap
# https://nmap.org/
# Enumerate valid users via VRFY, EXPN, and RCPT TO
nmap -p 25 --script smtp-enum-users --script-args smtp-enum-users.methods={VRFY,EXPN,RCPT} <target>

# Check for open relay
nmap -p 25 --script smtp-open-relay <target>

# Enumerate supported NTLM authentication info (Exchange/Windows)
nmap -p 25 --script smtp-ntlm-info <target>
```

The `smtp-ntlm-info` script is particularly useful against Exchange servers — it can reveal the internal domain name, server hostname, and DNS domain without authentication.

### STARTTLS Certificate Inspection

```bash
openssl s_client -starttls smtp -connect <target>:25 -quiet
```

Expected output (truncated):
```text
subject=CN = mail.internal.corp.example.com
issuer=CN = Example Corp Internal CA
---
```

Certificates frequently leak internal hostnames, subdomain structures, and CA hierarchy. For port 465 (SMTPS), connect directly without `-starttls`:

```bash
openssl s_client -connect <target>:465 -quiet
```

### Swaks (Swiss Army Knife for SMTP)

```bash
# Swaks
# https://github.com/jetmore/swaks
# Basic connectivity and banner grab
swaks --to user@example.com --server <target> --quit-after EHLO

# Test open relay
swaks --to victim@external.com --from attacker@external.com --server <target>

# Test authenticated SMTP (port 587)
swaks --to user@example.com --from sender@example.com --server <target> --port 587 -tls --auth-user admin --auth-password 'pass'

# Send test email with custom headers (phishing pretext validation)
swaks --to user@example.com --from ceo@example.com --server <target> --header "Subject: Test" --body "Relay test"
```

Swaks provides cleaner output than manual telnet sessions and handles TLS negotiation, authentication, and encoding automatically. The `--quit-after` flag is useful for non-intrusive probing.

### Automated User Enumeration with smtp-user-enum

```bash
# smtp-user-enum
# https://github.com/pentestmonkey/smtp-user-enum
smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t <target>

# Use RCPT TO method instead
smtp-user-enum -M RCPT -U /usr/share/seclists/Usernames/Names/names.txt -t <target> -D example.com
```

The `-M` flag selects the method (VRFY, EXPN, or RCPT). The `-D` flag appends the domain to usernames when using RCPT TO.

### Open Relay Testing

An open relay allows unauthenticated users to send email through the server to external recipients.

```text
telnet <target> 25
EHLO test
MAIL FROM:<attacker@external.com>
RCPT TO:<victim@anotherdomain.com>
DATA
Subject: Relay Test
Test
.
```

If the server accepts the message and returns `250 OK` after the DATA terminator, the server is an open relay.

## SMTP Response Code Reference

Interpreting response codes accurately is critical when scripting or analyzing results manually.

| Code | Meaning | Enumeration Implication |
|------|---------|------------------------|
| 220  | Service ready | Server is accepting connections |
| 250  | Requested action OK | User exists (VRFY/RCPT) or command succeeded |
| 251  | User not local, will forward | User valid but handled by another server |
| 252  | Cannot verify, will attempt delivery | User may exist — server won't confirm |
| 421  | Service not available | Server is rejecting connections (rate-limited or shutting down) |
| 450  | Mailbox unavailable (temporary) | Greylisting or temporary block — retry later |
| 550  | Mailbox unavailable (permanent) | User does not exist |
| 551  | User not local | User invalid on this server |
| 553  | Mailbox name not allowed | Invalid address format or policy rejection |

Codes 250, 251, and 252 all indicate a likely valid user. Code 550 is a definitive rejection. Code 252 is intentionally ambiguous — the server is configured not to confirm or deny, but will still attempt delivery.

## Post-Enumeration

With valid usernames confirmed, prioritize:
- Password spraying against authenticated SMTP (port 587) or webmail interfaces
- Phishing with spoofed internal addresses if open relay is confirmed
- Correlating discovered usernames with other services (SSH, RDP, web applications)
- Checking for SPF, DKIM, and DMARC records to assess spoofing potential

## References

### Official Documentation

- [Nmap smtp-commands NSE Script](https://nmap.org/nsedoc/scripts/smtp-commands.html)
- [Nmap smtp-enum-users NSE Script](https://nmap.org/nsedoc/scripts/smtp-enum-users.html)
- [Nmap smtp-open-relay NSE Script](https://nmap.org/nsedoc/scripts/smtp-open-relay.html)
- [Nmap smtp-ntlm-info NSE Script](https://nmap.org/nsedoc/scripts/smtp-ntlm-info.html)
- [smtp-user-enum](https://pentestmonkey.net/tools/user-enumeration/smtp-user-enum)
- [Swaks - Swiss Army Knife for SMTP](https://www.jetmore.org/john/code/swaks/)
- [RFC 5321 - Simple Mail Transfer Protocol](https://datatracker.ietf.org/doc/html/rfc5321)

### MITRE ATT&CK

- [T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)
- [T1589.002 - Gather Victim Identity Information: Email Addresses](https://attack.mitre.org/techniques/T1589/002/)
