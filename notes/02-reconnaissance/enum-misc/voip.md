% Filename: 02-reconnaissance/enum-misc/voip.md
% Display name: VoIP / SIP Enumeration
% Last update: 2026-02-10
% ATT&CK Tactics: TA0043 (Reconnaissance)
% ATT&CK Techniques: T1595 (Active Scanning)
% Authors: @TristanInSec

# VoIP / SIP Enumeration

## Overview

SIP (Session Initiation Protocol) runs on TCP/UDP 5060 (plaintext) and TCP 5061 (TLS). SIP is the signaling protocol for most VoIP deployments — PBX systems (Asterisk, FreePBX, Cisco UCM), IP phones, and softphones. Enumeration targets SIP server identification, extension/user enumeration, and supported methods discovery. While rarely a primary entry point, VoIP infrastructure on internal networks can reveal valid usernames, internal phone directories, and misconfigured PBX systems that accept unauthenticated calls.

## ATT&CK Mapping

- **Tactic:** TA0043 - Reconnaissance
- **Technique:** T1595 - Active Scanning

## Prerequisites

- Network access to target port 5060/5061
- `sipvicious` tools installed (in Kali repos, not pre-installed: `sudo apt install sipvicious`)
- Nmap for NSE SIP scripts

## Enumeration Techniques

### Service Detection

```bash
# Nmap
# https://nmap.org/
nmap -sV -p 5060 <target>
nmap -sU -sV -p 5060 <target>
```

SIP commonly runs on UDP. Always scan both TCP and UDP.

Expected output:
```text
5060/tcp open  sip     Asterisk PBX 18.12.0
5060/udp open  sip     Asterisk PBX 18.12.0
```

### SIP Methods Discovery

```bash
# Nmap
# https://nmap.org/
nmap -sU -p 5060 --script sip-methods <target>
```

Expected output:
```text
| sip-methods:
|   INVITE, ACK, CANCEL, OPTIONS, BYE, REFER,
|_  SUBSCRIBE, NOTIFY, INFO, PUBLISH, MESSAGE
```

Supported methods reveal capabilities. `REGISTER` indicates the server accepts registrations (extension enrollment). `INVITE` confirms call setup is possible.

### Manual SIP OPTIONS Request

```bash
# Send a SIP OPTIONS request to fingerprint the server
# (uses netcat — no special tools required)
echo -e "OPTIONS sip:100@<target> SIP/2.0\r\nVia: SIP/2.0/UDP <your-ip>:5060;branch=z9hG4bK-test\r\nFrom: <sip:test@<your-ip>>;tag=test\r\nTo: <sip:100@<target>>\r\nCall-ID: test@<your-ip>\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n" | nc -u -w 3 <target> 5060
```

The response `User-Agent` or `Server` header reveals the PBX software and version.

### SIP Extension Enumeration

Extension enumeration identifies valid SIP user/extension numbers. The server responds differently to valid vs. invalid extensions.

```bash
# SIPVicious (svwar)
# https://github.com/EnableSecurity/sipvicious
# Enumerate extensions 100-999
svwar -m REGISTER -e 100-999 <target>
```

Expected output:
```text
| Extension | Authentication |
+-----------+----------------+
| 100       | reqauth        |
| 101       | reqauth        |
| 200       | reqauth        |
| 500       | noauth         |
```

`reqauth` = valid extension, requires password. `noauth` = valid extension, no password required. Extensions with `noauth` can be registered without credentials.

Enumeration methods:

- `REGISTER` — most reliable, tests if the server acknowledges the extension
- `INVITE` — may trigger call setup (noisy)
- `OPTIONS` — least intrusive

```bash
# SIPVicious (svwar)
# https://github.com/EnableSecurity/sipvicious
# Use OPTIONS method (quieter)
svwar -m OPTIONS -e 100-999 <target>

# Use INVITE method (may ring phones — use with caution)
svwar -m INVITE -e 100-999 <target>
```

### Nmap NSE SIP Scripts

```bash
# Nmap
# https://nmap.org/
# Enumerate SIP extensions/users
nmap -sU -p 5060 --script sip-enum-users <target>

# Brute-force SIP accounts
nmap -sU -p 5060 --script sip-brute <target>
```

### SIP Server Scanning

```bash
# SIPVicious (svmap)
# https://github.com/EnableSecurity/sipvicious
# Discover SIP servers on a subnet
svmap 10.10.10.0/24
```

Expected output:
```text
| SIP Device       | User Agent               | Fingerprint |
+------------------+--------------------------+-------------+
| 10.10.10.50:5060 | Asterisk PBX 18.12.0     |             |
| 10.10.10.51:5060 | Cisco-SIPGateway/IOS-16  |             |
| 10.10.10.100:5060| Yealink SIP-T46S         |             |
```

This reveals PBX servers, gateways, and individual IP phones on the network.

### SIP Password Cracking

```bash
# SIPVicious (svcrack)
# https://github.com/EnableSecurity/sipvicious
# Brute-force a specific extension
svcrack -u 100 -d /usr/share/wordlists/rockyou.txt <target>
```

### Metasploit Modules

```msf
# Metasploit Framework
# https://www.metasploit.com/
# SIP endpoint scanner
msf6 > use auxiliary/scanner/sip/enumerator
msf6 > set RHOSTS <target>
msf6 > set MINEXT 100
msf6 > set MAXEXT 999
msf6 > run

# SIP OPTIONS scanner
msf6 > use auxiliary/scanner/sip/options
msf6 > set RHOSTS <target>
msf6 > run
```

## Post-Enumeration

With SIP/VoIP access confirmed, prioritize:
- Valid extensions with no authentication — register and make calls, potentially toll fraud
- Extension-to-name mapping reveals internal user directories and naming conventions
- PBX admin interfaces (typically HTTP on ports 8080, 8088, or 443) may have default credentials
- Voicemail systems often use extension number as default PIN
- Call recordings or voicemail files on the PBX filesystem

## References

### Official Documentation

- [SIPVicious OSS (GitHub)](https://github.com/enablesecurity/sipvicious)
- [SIPVicious svwar Usage Wiki](https://github.com/EnableSecurity/sipvicious/wiki/SVWar-Usage)
- [SIPVicious svmap Usage Wiki](https://github.com/EnableSecurity/sipvicious/wiki/SVMap-Usage)
- [sipvicious - Kali Linux Tools](https://www.kali.org/tools/sipvicious/)
- [Metasploit SIP Username Enumerator Module](https://www.rapid7.com/db/modules/auxiliary/scanner/sip/enumerator/)
- [Metasploit SIP Options Scanner Module](https://www.rapid7.com/db/modules/auxiliary/scanner/sip/options/)
- [RFC 3261 - SIP: Session Initiation Protocol](https://datatracker.ietf.org/doc/html/rfc3261)

### Pentest Guides & Tutorials

- [Vartai Security - Practical VoIP Penetration Testing](https://medium.com/vartai-security/practical-voip-penetration-testing-a1791602e1b4)
- [Enable Security - SIPVicious OSS](https://www.enablesecurity.com/sipvicious/)

### MITRE ATT&CK

- [T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)
