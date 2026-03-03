% Filename: 02-reconnaissance/enum-windows/overview.md
% Display name: Windows Enumeration
% Last update: 2026-02-09
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# Windows Enumeration

## Overview

Windows service enumeration targets the protocols and management interfaces specific to Windows and Active Directory environments. These services frequently expose usernames, group memberships, password policies, share structures, and domain topology — often with null sessions or minimal credentials.

## Topics in This Section

- [Kerberos Enumeration](kerberos.md) — User validation, AS-REP Roasting, Kerberoasting, SPNs
- [LDAP Enumeration](ldap.md) — AD directory queries, user/group extraction, SPNs, delegation
- [MSRPC Enumeration](rpc.md) — Endpoint mapping, rpcclient, SAMR user enumeration
- [RDP Enumeration](rdp.md) — NLA detection, NTLM info, credential testing, xfreerdp3
- [SMB Enumeration](smb.md) — Shares, users, enum4linux-ng, smbmap, NetExec, RID cycling, NetBIOS
- [WinRM Enumeration](winrm.md) — Service detection, Evil-WinRM, remote management access

## General Approach

1. **Start with SMB and LDAP** — they expose the most data with the least credentials
2. **Test null sessions and guest access** — SMB null sessions, LDAP anonymous bind, RPC null sessions
3. **Enumerate users via multiple paths** — SMB RID cycling, LDAP queries, SAMR, NTLM info leaks
4. **Map the domain** — LDAP gives you the full AD structure, GPOs, trusts, and delegation
5. **Check every protocol for NTLM info** — SMB, RDP, RPC all leak domain names and hostnames
6. **Test discovered credentials across all services** — a password from SMB may grant WinRM or RDP access
