% Filename: 02-reconnaissance/enum-misc/overview.md
% Display name: Miscellaneous Service Enumeration
% Last update: 2026-02-10
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# Miscellaneous Service Enumeration

## Overview

This section covers enumeration of services that don't fit neatly into network, web, Windows, or database categories but are frequently encountered during internal penetration tests. NFS and IPMI are high-value targets — NFS exports commonly leak sensitive files and enable privilege escalation, while IPMI on enterprise servers often yields credentials through protocol-level hash disclosure. VNC provides direct desktop access when misconfigured, and VoIP/SIP infrastructure reveals internal user directories and extension maps.

## Topics in This Section

- [NFS Enumeration](nfs.md) — Network File System shares, exports, and no_root_squash escalation
- [IPMI Enumeration](ipmi.md) — BMC management interfaces, RAKP hash dumping, default credentials
- [VNC Enumeration](vnc.md) — Remote desktop access, authentication bypass, password file recovery
- [VoIP / SIP Enumeration](voip.md) — PBX discovery, extension enumeration, SIP server fingerprinting

## General Approach

When encountering these services during a port scan:

1. **NFS (111/2049)** — immediately check `showmount -e` for open exports. Mount and search for SSH keys, credentials, and writable shares with `no_root_squash`.
2. **IPMI (623/udp)** — run Metasploit `ipmi_dumphashes` to extract password hashes without authentication. Test default credentials for the vendor (Dell: root/calvin, Supermicro: ADMIN/ADMIN).
3. **VNC (5900+)** — check for no-auth access first (`vnc_none_auth` scanner), then brute-force if needed. Password-protected VNC is limited to 8-character DES — trivially crackable.
4. **SIP (5060)** — enumerate extensions with `svwar`, identify extensions without authentication, and fingerprint the PBX software for version-specific vulnerabilities.
