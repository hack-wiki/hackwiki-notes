% Filename: 02-reconnaissance/enum-network/pop3-imap.md
% Display name: POP3/IMAP Enumeration
% Last update: 2026-02-10
% ATT&CK Tactics: TA0043 (Reconnaissance)
% ATT&CK Techniques: T1595 (Active Scanning)
% Authors: @TristanInSec

# POP3/IMAP Enumeration

## Overview

POP3 runs on TCP 110 (plaintext) and TCP 995 (POP3S). IMAP runs on TCP 143 (plaintext) and TCP 993 (IMAPS). Both protocols retrieve email from a mail server. Enumeration focuses on banner grabbing for software identification, authentication testing, and mailbox extraction. POP3 and IMAP transmit credentials in plaintext on unencrypted ports — even passive sniffing can capture passwords.

## ATT&CK Mapping

- **Tactic:** TA0043 - Reconnaissance
- **Technique:** T1595 - Active Scanning

## Prerequisites

- Network access to target POP3/IMAP ports
- Netcat or telnet installed
- Valid credentials (for authenticated mailbox access)

## POP3 Enumeration

### Banner Grabbing

```bash
nc -nv <target> 110
```

Expected output:
```text
+OK Dovecot ready.
```

Common server banners: Dovecot, Courier, Microsoft Exchange POP3 service, hMailServer. The banner identifies the mail server software for version-specific vulnerability research.

### POP3 Authentication Testing

```bash
telnet <target> 110
USER admin
PASS password123
```

Response codes:
- `+OK` — command succeeded (valid login, message retrieved, etc.)
- `-ERR` — command failed (bad credentials, mailbox locked, etc.)

### POP3 Mailbox Enumeration (Authenticated)

Once authenticated:

```bash
# List number of messages and total size
STAT

# List individual messages with sizes
LIST

# Retrieve message headers only (first 0 lines of body)
TOP 1 0

# Retrieve full message
RETR 1

# Retrieve all message headers for quick triage (requires valid credentials)
# Custom script created for this guide
{
    echo "USER admin"
    echo "PASS password123"
    sleep 1
    for i in $(seq 1 10); do
        echo "TOP $i 0"
    done
    echo "QUIT"
} | nc <target> 110
```

`TOP <msg> 0` retrieves headers without the body — useful for quickly scanning senders, subjects, and timestamps to identify high-value messages before downloading full content.

### POP3S (POP3 over TLS)

```bash
# Implicit TLS (port 995)
openssl s_client -connect <target>:995 -quiet

# Explicit TLS (STLS on port 110)
openssl s_client -starttls pop3 -connect <target>:110 -quiet
```

After the TLS handshake, use the same POP3 commands (USER, PASS, STAT, LIST, RETR). Certificate inspection may reveal internal hostnames.

## IMAP Enumeration

### Banner Grabbing

```bash
nc -nv <target> 143
```

Expected output:
```text
* OK [CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE] Dovecot ready.
```

IMAP banners frequently include the CAPABILITY list inline, immediately revealing supported extensions without a separate query.

### IMAP Capability Enumeration

```bash
telnet <target> 143
a1 CAPABILITY
```

Expected output:
```text
* CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE AUTH=PLAIN AUTH=LOGIN STARTTLS
a1 OK Pre-login capabilities listed.
```

Key capabilities to note:
- `AUTH=PLAIN`, `AUTH=LOGIN` — plaintext credential auth methods
- `STARTTLS` — TLS upgrade available
- `IDLE` — server supports push notifications
- `ID` — server will reveal software details on request

### IMAP Server Identification

The `ID` command reveals detailed server information:

```bash
telnet <target> 143
a1 ID NIL
```

Expected output:
```text
* ID ("name" "Dovecot" "version" "2.3.19" "os" "Linux" "os-version" "6.1.0")
a1 OK ID completed.
```

This can reveal the exact server version and OS version — more detail than the banner alone.

### IMAP Authentication Testing

```bash
telnet <target> 143
a1 LOGIN admin password123
```

Response:
- `a1 OK` — successful authentication
- `a1 NO` — authentication failed
- `a1 BAD` — malformed command

### IMAP Mailbox Enumeration (Authenticated)

Once authenticated:

```bash
# List all mailboxes/folders
a2 LIST "" "*"

# Select inbox
a3 SELECT INBOX

# Search all messages
a4 SEARCH ALL

# Search unread messages
a5 SEARCH UNSEEN

# Search by subject
a6 SEARCH SUBJECT "password"

# Search by sender
a7 SEARCH FROM "admin"

# Fetch message headers
a8 FETCH 1 (BODY[HEADER])

# Fetch full message
a9 FETCH 1 (BODY[])
```

IMAP's `SEARCH` command is powerful for targeted extraction — searching for keywords like "password", "credentials", "VPN", "reset" across all mailboxes quickly identifies high-value emails.

### IMAPS (IMAP over TLS)

```bash
# Implicit TLS (port 993)
openssl s_client -connect <target>:993 -quiet

# Explicit TLS (STARTTLS on port 143)
openssl s_client -starttls imap -connect <target>:143 -quiet
```

## Nmap NSE Scripts

```bash
# Nmap
# https://nmap.org/
# POP3 capabilities
nmap -p 110 --script pop3-capabilities <target>

# POP3 NTLM info (Exchange — reveals internal domain)
nmap -p 110 --script pop3-ntlm-info <target>

# IMAP capabilities
nmap -p 143 --script imap-capabilities <target>

# IMAP NTLM info (Exchange — reveals internal domain)
nmap -p 143 --script imap-ntlm-info <target>

# Brute-force POP3
nmap -p 110 --script pop3-brute <target>

# Brute-force IMAP
nmap -p 143 --script imap-brute <target>

# Scan all mail ports at once
nmap -sV -p 110,143,993,995 --script "pop3-* or imap-*" <target>
```

The `ntlm-info` scripts are particularly useful against Exchange — they leak the internal domain name, server hostname, and DNS domain without authentication, just like `smtp-ntlm-info`.

### curl for IMAP/POP3

```bash
# List IMAP mailboxes
curl -k "imaps://<target>" --user "admin:password"

# Fetch inbox messages
curl -k "imaps://<target>/INBOX" --user "admin:password"

# Fetch specific message
curl -k "imaps://<target>/INBOX;UID=1" --user "admin:password"

# POP3 message list
curl -k "pop3s://<target>" --user "admin:password"

# POP3 retrieve message
curl -k "pop3s://<target>/1" --user "admin:password"
```

`curl` handles TLS negotiation automatically with `-k` and provides a scriptable alternative to manual telnet sessions.

## Post-Enumeration

With mail access confirmed, prioritize:
- Searching mailboxes for credentials, password reset links, VPN configs, and internal documentation
- Extracting attachments (documents, spreadsheets, certificates)
- Identifying internal email addresses for targeted phishing or SMTP relay abuse
- Correlating discovered usernames with other services (SSH, SMB, web applications)
- Checking if the same credentials work on the SMTP submission port (587) for sending

## References

### Official Documentation

- [Nmap pop3-capabilities NSE Script](https://nmap.org/nsedoc/scripts/pop3-capabilities.html)
- [Nmap pop3-ntlm-info NSE Script](https://nmap.org/nsedoc/scripts/pop3-ntlm-info.html)
- [Nmap imap-capabilities NSE Script](https://nmap.org/nsedoc/scripts/imap-capabilities.html)
- [Nmap imap-ntlm-info NSE Script](https://nmap.org/nsedoc/scripts/imap-ntlm-info.html)
- [RFC 1939 - Post Office Protocol Version 3](https://datatracker.ietf.org/doc/html/rfc1939)
- [RFC 3501 - Internet Message Access Protocol](https://datatracker.ietf.org/doc/html/rfc3501)

### MITRE ATT&CK

- [T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)
