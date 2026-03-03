% Filename: 02-reconnaissance/enum-windows/rdp.md
% Display name: RDP Enumeration
% Last update: 2026-02-10
% ATT&CK Tactics: TA0043 (Reconnaissance)
% ATT&CK Techniques: T1595 (Active Scanning)
% Authors: @TristanInSec

# RDP Enumeration

## Overview

RDP runs on TCP 3389 by default. Enumeration focuses on service detection, encryption level assessment, NLA (Network Level Authentication) status, and credential testing. RDP itself reveals limited information compared to SMB or LDAP, but its presence confirms a Windows host and its configuration determines whether brute-forcing or pass-the-hash attacks are viable.

## ATT&CK Mapping

- **Tactic:** TA0043 - Reconnaissance
- **Technique:** T1595 - Active Scanning

## Prerequisites

- Network access to target TCP 3389
- `rdesktop`, `xfreerdp3`, `nmap`, or NetExec installed

## Enumeration Techniques

### Service Detection

```bash
# Nmap
# https://nmap.org/
nmap -sV -p 3389 <target>
```

Expected output:
```text
3389/tcp open  ms-wbt-server  Microsoft Terminal Services
```

RDP is often moved to non-standard ports for obscurity:

```bash
# Nmap
# https://nmap.org/
nmap -sV -p 3389,3390,13389 <target>

# Full scan filtered for RDP
nmap -sV -p- --open <target> | grep -i "ms-wbt\|rdp\|terminal"
```

### Nmap NSE Scripts

```bash
# Nmap
# https://nmap.org/
# Enumerate RDP encryption and security
nmap -p 3389 --script rdp-enum-encryption <target>
```

Expected output:
```text
| rdp-enum-encryption:
|   Security layer
|     CredSSP (NLA): SUCCESS
|     CredSSP with Early User Auth: SUCCESS
|     Native RDP: SUCCESS
|     RDSTLS: SUCCESS
|     SSL: SUCCESS
|   RDP Encryption level: High
|_  RDP Protocol Version: RDP 10.7
```

If `Native RDP: SUCCESS` without NLA, the server accepts connections before authentication — exposing the login screen to unauthenticated users and making brute-force easier.

```bash
# Nmap
# https://nmap.org/
# NTLM info extraction (reveals hostname, domain, DNS)
nmap -p 3389 --script rdp-ntlm-info <target>
```

Expected output:
```text
| rdp-ntlm-info:
|   Target_Name: CORP
|   NetBIOS_Domain_Name: CORP
|   NetBIOS_Computer_Name: WORKSTATION01
|   DNS_Domain_Name: corp.local
|   DNS_Computer_Name: WORKSTATION01.corp.local
|   DNS_Tree_Name: corp.local
|_  Product_Version: 10.0.19041
```

Same NTLM info disclosure pattern as SMTP, IMAP, POP3, and Telnet — reveals internal domain and hostname without authentication.

```bash
# Nmap
# https://nmap.org/
# Check for MS12-020 (CVE-2012-0002 RCE + CVE-2012-0152 DoS)
nmap -p 3389 --script rdp-vuln-ms12-020 <target>
```

Nmap does not include an `rdp-brute` NSE script. Use Hydra for RDP brute-forcing:

```bash
# Hydra
# https://github.com/vanhauser-thc/thc-hydra
hydra -L users.txt -P passwords.txt rdp://<target> -t 1 -W 3
```

The `-t 1` flag limits to one parallel connection (RDP rate-limits aggressively) and `-W 3` adds a 3-second wait between attempts to avoid lockouts.

For BlueKeep (CVE-2019-0708), no official Nmap NSE script exists. Use Metasploit's `auxiliary/scanner/rdp/cve_2019_0708_bluekeep` or standalone tools like [rdpscan](https://github.com/robertdavidgraham/rdpscan) instead.

### Connection Testing with rdesktop

`rdesktop` is available on Kali by default for basic RDP connections:

```bash
# rdesktop
# https://github.com/rdesktop/rdesktop
rdesktop <target>
rdesktop -u <user> -p <password> -g 92% <target>

# Mount local share on remote host
rdesktop -u <user> -p <password> -g 92% -r disk:share=/tmp/ <target>
# Access from Windows: \\tsclient\share
```

### Connection Testing with xfreerdp3

`xfreerdp3` is the modern FreeRDP client. It supports NLA, pass-the-hash, and drive redirection:

```bash
# xfreerdp3
# https://github.com/FreeRDP/FreeRDP
# Test credentials (connect and disconnect)
xfreerdp3 /v:<target> /u:<user> /p:<password> +auth-only

# Full connection
xfreerdp3 /v:<target> /u:<user> /p:<password> /cert:ignore

# Connect with domain credentials
xfreerdp3 /v:<target> /u:<user> /p:<password> /d:<domain> /cert:ignore

# Share local directory with target
xfreerdp3 /v:<target> /u:<user> /p:<password> /cert:ignore /drive:share,/tmp

# Pass-the-hash (requires Restricted Admin mode or NLA disabled)
xfreerdp3 /v:<target> /u:Administrator /pth:<NTLM_hash> /cert:ignore

# Adjust resolution
xfreerdp3 /v:<target> /u:<user> /p:<password> /cert:ignore /size:1280x720
```

The `+auth-only` flag tests credentials without opening a full session — useful for validating creds across many hosts without triggering a desktop.

### NLA (Network Level Authentication) Check

NLA requires valid credentials before establishing the RDP session. Its absence is a security finding:

```bash
# Nmap
# https://nmap.org/
nmap -p 3389 --script rdp-enum-encryption <target> | grep -i "NLA\|CredSSP"
```

If CredSSP (NLA) shows `SUCCESS` alongside Native RDP `SUCCESS`, the server accepts both — meaning NLA can be bypassed by a client that requests the legacy protocol.

### NetExec RDP Module

```bash
# NetExec
# https://github.com/Pennyw0rth/NetExec
# Test credentials via RDP
nxc rdp <target> -u <user> -p <password>

# Test credentials across a subnet
nxc rdp <network>/24 -u <user> -p <password>

# Brute-force with user/password lists
nxc rdp <target> -u users.txt -p passwords.txt
```

NetExec's RDP module tests authentication without opening a full session, making it faster than manual xfreerdp3 testing across multiple targets.

### Accessing Shared Drives via RDP

Once connected, files can be transferred between attacker and target through drive redirection:

```bash
# rdesktop
# https://github.com/rdesktop/rdesktop
rdesktop -u <user> -p <password> -g 92% -r disk:loot=/tmp/loot <target>

# xfreerdp3
# https://github.com/FreeRDP/FreeRDP
xfreerdp3 /v:<target> /u:<user> /p:<password> /cert:ignore /drive:loot,/tmp/loot
```

On the Windows side, the shared drive appears at `\\tsclient\loot` — accessible from Explorer or the command line. This avoids the need for separate file transfer mechanisms.

## Post-Enumeration

With RDP access confirmed, prioritize:
- Credential validation across multiple hosts via NetExec
- NTLM info for internal domain and hostname mapping
- NLA status for security posture assessment
- BlueKeep (CVE-2019-0708) for potential remote code execution on unpatched hosts
- Drive redirection for file staging and exfiltration during active sessions
- Screenshot/recording capabilities for evidence collection during testing

## References

### Nmap NSE Scripts

- [rdp-enum-encryption](https://nmap.org/nsedoc/scripts/rdp-enum-encryption.html)
- [rdp-ntlm-info](https://nmap.org/nsedoc/scripts/rdp-ntlm-info.html)
- [rdp-vuln-ms12-020](https://nmap.org/nsedoc/scripts/rdp-vuln-ms12-020.html)
### Tools

- [FreeRDP / xfreerdp3](https://github.com/FreeRDP/FreeRDP)
- [NetExec](https://github.com/Pennyw0rth/NetExec)
- [Hydra](https://github.com/vanhauser-thc/thc-hydra)
- [rdpscan — BlueKeep scanner](https://github.com/robertdavidgraham/rdpscan)

### CVE References

- [CVE-2012-0002 - MS12-020 RDP RCE](https://nvd.nist.gov/vuln/detail/CVE-2012-0002)
- [CVE-2019-0708 - BlueKeep RDP RCE](https://nvd.nist.gov/vuln/detail/CVE-2019-0708)

### MITRE ATT&CK

- [T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)
