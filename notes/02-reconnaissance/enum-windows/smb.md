% Filename: 02-reconnaissance/enum-windows/smb.md
% Display name: SMB Enumeration
% Last update: 2026-02-19
% ATT&CK Tactics: TA0043 (Reconnaissance), TA0007 (Discovery)
% ATT&CK Techniques: T1595 (Active Scanning), T1135 (Network Share Discovery)
% Authors: @TristanInSec

# SMB Enumeration

## Overview

SMB runs on TCP 445 (direct) and TCP 139 (over NetBIOS). Enumeration targets share listing, user and group enumeration, OS discovery, password policy extraction, and RID cycling. SMB is one of the highest-value enumeration targets on Windows networks — null sessions, guest access, and misconfigured shares frequently expose credentials, backups, and internal documentation.

## ATT&CK Mapping

- **Tactics:** TA0043 - Reconnaissance, TA0007 - Discovery
- **Technique:** T1595 - Active Scanning
- **Technique:** T1135 - Network Share Discovery

## Prerequisites

- Network access to target TCP 139/445
- `smbclient`, `enum4linux`, `smbmap`, or Nmap installed
- `enum4linux-ng` (installed by default on Kali Linux)

## Enumeration Techniques

### Service Detection and OS Discovery

```bash
# Nmap
# https://nmap.org/
nmap -v -p 139,445 --script smb-os-discovery <target>
```

Expected output:
```text
| smb-os-discovery:
|   OS: Windows 10 Pro 19041 (Windows 10 Pro 6.3)
|   Computer name: WORKSTATION01
|   NetBIOS computer name: WORKSTATION01\x00
|   Domain name: corp.local
|   Forest name: corp.local
|   FQDN: WORKSTATION01.corp.local
```

This single script reveals OS version, hostname, domain name, and forest — critical for scoping an AD environment.

### NetBIOS Discovery

```bash
# nbtscan
# https://github.com/charlesroelli/nbtscan
# Discover SMB hosts on a subnet
nbtscan <network>/24
```

Expected output:
```text
10.10.10.1      WORKSTATION01   <server>   CORP
10.10.10.5      DC01            <server>   CORP
10.10.10.12     FILESERVER      <server>   CORP
```

```bash
# nbtscan
# https://github.com/charlesroelli/nbtscan
# Verbose output with MAC addresses
nbtscan -r <network>/24
```

`nbtscan` is faster than Nmap for initial SMB host discovery across large subnets. The `-r` flag uses local port 137 for queries, which is required in some network configurations.

### Null Session Testing

A null session connects with an empty username and password — if accepted, it often grants read access to shares, user lists, and group information:

```bash
# smbclient (Samba)
# https://www.samba.org/
# Test null session — list shares
smbclient -L <target> -U '' -N
```

Expected output on success:
```text
	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	Public          Disk      Public Share
	Backups         Disk      
```

The `-N` flag suppresses the password prompt (null authentication). If shares are listed, null sessions are permitted.

```bash
# smbclient
# https://www.samba.org/
# Connect to a specific share
smbclient //<target>/Public -U '' -N

# Common commands once connected
smb: \> dir
smb: \> cd subdir
smb: \> get filename.txt
smb: \> mget *
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *
```

### Share Enumeration with smbmap

```bash
# smbmap
# https://github.com/ShawnDEvans/smbmap
# Null session share enumeration
smbmap -H <target>

# Guest access
smbmap -H <target> -u guest -p ''

# Authenticated
smbmap -H <target> -u <user> -p <password> -d <domain>
```

Expected output:
```text
[+] IP: 10.10.10.1:445	Name: 10.10.10.1
	Disk                                Permissions     Comment
	----                                -----------     -------
	ADMIN$                              NO ACCESS       Remote Admin
	C$                                  NO ACCESS       Default share
	IPC$                                READ ONLY       Remote IPC
	Public                              READ, WRITE     Public Share
	Backups                             READ ONLY
```

`smbmap` shows permissions per share — immediately identifying writable shares and access levels. This is more informative than `smbclient -L` alone.

```bash
# smbmap
# https://github.com/ShawnDEvans/smbmap
# Recursive file listing
smbmap -H <target> -r Backups

# Download a file
smbmap -H <target> --download 'Backups\config.bak'

# Search for files by pattern
smbmap -H <target> -r -A '\.conf$|\.bak$|\.xml$|password'
```

### Comprehensive Enumeration with enum4linux-ng

`enum4linux-ng` is the modern Python rewrite of the original Perl `enum4linux`. Same concept, better output. Installed by default on Kali Linux.

```bash
# enum4linux-ng
# https://github.com/cddmp/enum4linux-ng
# Full enumeration (null session)
enum4linux-ng -A <target>
```

This runs all checks: OS info, users, groups, shares, password policy, RID cycling, and printers. The `-A` flag is equivalent to the old `enum4linux -a`.

```bash
# enum4linux-ng
# https://github.com/cddmp/enum4linux-ng
# Specific checks
enum4linux-ng -U <target>          # Users
enum4linux-ng -G <target>          # Groups
enum4linux-ng -S <target>          # Shares
enum4linux-ng -P <target>          # Password policy
enum4linux-ng -o <target>          # OS information
enum4linux-ng -R <target>          # RID cycling (user enumeration)
```

The original `enum4linux` (Perl) is also on Kali:

```bash
# enum4linux
# https://github.com/CiscoCXSecurity/enum4linux
enum4linux -a <target>             # All basic checks
enum4linux -U -o <target>          # Users + OS info
enum4linux -r <target>             # RID cycling
```

### RID Cycling (User Enumeration)

RID cycling brute-forces Security Identifiers (SIDs) to enumerate users and groups even when null sessions don't return user lists directly:

```bash
# Impacket lookupsid
# https://github.com/fortra/impacket
impacket-lookupsid ''@<target>

# With credentials
impacket-lookupsid '<domain>/<user>:<password>'@<target>
```

Expected output:
```text
[*] Brute forcing SIDs at 10.10.10.1
[*] StringBinding ncacn_np:10.10.10.1[\pipe\lsarpc]
500: CORP\Administrator (SidTypeUser)
501: CORP\Guest (SidTypeUser)
502: CORP\krbtgt (SidTypeUser)
1000: CORP\DC01$ (SidTypeUser)
1103: CORP\svc_sql (SidTypeUser)
1104: CORP\j.smith (SidTypeUser)
```

RIDs 500 (Administrator), 501 (Guest), and 502 (krbtgt) are well-known. Custom accounts start at 1000+. Every `SidTypeUser` entry is a valid username for password spraying.

### NetExec (formerly CrackMapExec)

```bash
# NetExec
# https://github.com/Pennyw0rth/NetExec
# Enumerate shares (null session)
nxc smb <target> -u '' -p '' --shares

# Enumerate shares (guest)
nxc smb <target> -u 'guest' -p '' --shares

# Enumerate shares (authenticated)
nxc smb <target> -u <user> -p <password> --shares

# Enumerate users
nxc smb <target> -u <user> -p <password> --users

# RID brute-force
nxc smb <target> -u '' -p '' --rid-brute

# Password policy
nxc smb <target> -u <user> -p <password> --pass-pol

# Spider shares for interesting files
nxc smb <target> -u <user> -p <password> -M spider_plus
```

NetExec (command: `nxc`) is the actively maintained successor to CrackMapExec (`crackmapexec`). It supports mass enumeration across entire subnets:

```bash
# NetExec
# https://github.com/Pennyw0rth/NetExec
# Scan entire subnet
nxc smb <network>/24 --shares -u '' -p ''
```

### Nmap NSE Scripts

```bash
# Nmap
# https://nmap.org/
# Enumerate shares
nmap -p 445 --script smb-enum-shares <target>

# Enumerate users
nmap -p 445 --script smb-enum-users <target>

# Enumerate groups
nmap -p 445 --script smb-enum-groups <target>

# Enumerate sessions (logged-in users)
nmap -p 445 --script smb-enum-sessions <target>

# Enumerate services
nmap -p 445 --script smb-enum-services <target>

# SMB protocol version and security mode
nmap -p 445 --script smb-protocols <target>
nmap -p 445 --script smb-security-mode <target>

# Vulnerability scanning
nmap -p 445 --script smb-vuln-ms17-010 <target>
nmap -p 445 --script "smb-vuln-*" --script-args unsafe=1 <target>

# Run all SMB enumeration scripts
nmap -p 139,445 --script "smb-enum-*" <target>
```

Key vulnerability scripts:
- `smb-vuln-ms17-010` — EternalBlue (critical, still common)
- `smb-vuln-ms08-067` — Conficker (legacy, Windows XP/2003)

For SMBGhost (CVE-2020-0796), no official Nmap NSE script exists. Community scripts are available on GitHub but are not part of the Nmap distribution.

### Impacket SMB Tools

```bash
# Impacket smbclient
# https://github.com/fortra/impacket
impacket-smbclient ''@<target>
impacket-smbclient '<domain>/<user>:<password>'@<target>

# Dump SAM hashes via SMB (requires admin)
impacket-secretsdump '<domain>/<user>:<password>'@<target>

# samrdump — enumerate users via MSRPC over SMB
impacket-samrdump ''@<target>
impacket-samrdump '<domain>/<user>:<password>'@<target>
```

`impacket-samrdump` is the modern version of the `samrdump.py` from your old toolkit — same functionality, now installed as a system command on Kali.

### SMB Signing Check

SMB signing prevents relay attacks. If signing is disabled or not required, the host is vulnerable to NTLM relay:

```bash
# Nmap
# https://nmap.org/
nmap -p 445 --script smb-security-mode <target>
```

Expected output:
```text
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
```

`message_signing: disabled` = relay target. `message_signing: required` = not relayable.

> **Note:** SMB signing is disabled by default on most Windows versions, but newer releases change this: **Windows 11 24H2 (Enterprise/Pro/Education)** requires both inbound and outbound signing by default; **Windows Server 2025** requires outbound signing by default. Windows 11 24H2 Home does not require signing. Relay attacks against those enterprise targets will fail unless signing is explicitly disabled via policy.

```bash
# NetExec
# https://github.com/Pennyw0rth/NetExec
# Check signing across a subnet
nxc smb <network>/24 --gen-relay-list relay_targets.txt
```

This generates a file of all hosts where signing is not required — ready for `ntlmrelayx`.

## Post-Enumeration

With SMB data collected, prioritize:
- Writable shares for webshell or payload placement
- Extracted usernames for password spraying (RID cycling + enum4linux results)
- Password policy to tune spray attempts (lockout threshold, complexity)
- Files from accessible shares — configs, scripts, backups, credentials
- SMB signing status for NTLM relay attacks
- Vulnerability scan results (EternalBlue, SMBGhost) for direct exploitation

## References

### Nmap NSE Scripts

- [smb-os-discovery](https://nmap.org/nsedoc/scripts/smb-os-discovery.html)
- [smb-enum-shares](https://nmap.org/nsedoc/scripts/smb-enum-shares.html)
- [smb-enum-users](https://nmap.org/nsedoc/scripts/smb-enum-users.html)
- [smb-enum-groups](https://nmap.org/nsedoc/scripts/smb-enum-groups.html)
- [smb-enum-sessions](https://nmap.org/nsedoc/scripts/smb-enum-sessions.html)
- [smb-enum-services](https://nmap.org/nsedoc/scripts/smb-enum-services.html)
- [smb-security-mode](https://nmap.org/nsedoc/scripts/smb-security-mode.html)
- [smb-protocols](https://nmap.org/nsedoc/scripts/smb-protocols.html)
- [smb-vuln-ms17-010](https://nmap.org/nsedoc/scripts/smb-vuln-ms17-010.html)
- [smb-vuln-ms08-067](https://nmap.org/nsedoc/scripts/smb-vuln-ms08-067.html)

### Tools

- [enum4linux-ng](https://github.com/cddmp/enum4linux-ng)
- [smbmap](https://github.com/ShawnDEvans/smbmap)
- [NetExec](https://github.com/Pennyw0rth/NetExec)
- [Impacket](https://github.com/fortra/impacket)
- [nbtscan](https://github.com/resurrecting-open-source-projects/nbtscan)

### MITRE ATT&CK

- [T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)
- [T1135 - Network Share Discovery](https://attack.mitre.org/techniques/T1135/)
