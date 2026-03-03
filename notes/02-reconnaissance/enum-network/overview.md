% Filename: 02-reconnaissance/enum-network/overview.md
% Display name: Network Enumeration
% Last update: 2026-02-09
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# Network Enumeration

## Overview

Network service enumeration is the process of actively querying discovered services to extract version information, configuration details, user accounts, and data. It follows host discovery and port scanning — once you know what ports are open, enumeration determines what's running and how it's configured.

Each protocol has unique enumeration techniques. A service's default behavior, supported commands, and common misconfigurations define what information is accessible without credentials and what requires authentication.

## Topics in This Section

- [DNS Enumeration](dns.md) — Record discovery, zone transfers, subdomain brute-forcing
- [FTP Enumeration](ftp.md) — Anonymous access, directory listing, file extraction, bounce scanning
- [NTP Enumeration](ntp.md) — Peer lists, monlist client disclosure, time sync for Kerberos
- [POP3/IMAP Enumeration](pop3-imap.md) — Mail server identification, mailbox access, NTLM info
- [Rsync Enumeration](rsync.md) — Module listing, anonymous file access, write testing
- [SMTP Enumeration](smtp.md) — User enumeration (VRFY/EXPN/RCPT TO), open relay, NTLM info
- [SNMP Enumeration](snmp.md) — Community strings, MIB walks, user/process/network extraction
- [SSH Enumeration](ssh.md) — Version-to-OS mapping, auth methods, algorithm enumeration
- [Telnet Enumeration](telnet.md) — Banner analysis, default credentials, NTLM info
- [TFTP Enumeration](tftp.md) — Blind file retrieval, config extraction, PXE boot files

## General Approach

1. **Start with DNS** — it maps the attack surface before touching anything else
2. **Enumerate unauthenticated services first** — SNMP, FTP anonymous, TFTP, rsync modules
3. **Extract credentials and usernames** — SMTP user enumeration, SNMP user OIDs, leaked configs
4. **Use discovered credentials across services** — a password from FTP may work on SSH, SMTP, or web apps
5. **Check TLS certificates** — SMTP STARTTLS, FTPS, IMAPS, and POP3S certificates leak internal hostnames
6. **Document NTLM disclosures** — SMTP, POP3, IMAP, and Telnet NTLM info scripts reveal internal domain names on Exchange/Windows
