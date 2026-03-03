% Filename: 02-reconnaissance/enum-network/tftp.md
% Display name: TFTP Enumeration
% Last update: 2026-02-10
% ATT&CK Tactics: TA0043 (Reconnaissance)
% ATT&CK Techniques: T1595 (Active Scanning)
% Authors: @TristanInSec

# TFTP Enumeration

## Overview

TFTP runs on UDP 69. It is a simplified file transfer protocol with no authentication, no directory listing, and no encryption. Enumeration is limited to service detection and blind file retrieval — you must know (or guess) the exact filename to download. TFTP is primarily used for PXE network booting, firmware updates, and configuration backups on network equipment. Its lack of authentication means any accessible file can be downloaded by anyone who can reach the port.

## ATT&CK Mapping

- **Tactic:** TA0043 - Reconnaissance
- **Technique:** T1595 - Active Scanning

## Prerequisites

- Network access to target UDP 69
- `tftp` client or Nmap installed

## Enumeration Techniques

### Service Detection

```bash
# Nmap
# https://nmap.org/
nmap -sU -sV -p 69 <target>
```

Expected output:
```text
69/udp open  tftp
```

TFTP service detection is unreliable via version probing because the protocol has no banner and only responds to valid file requests. Nmap may report `open|filtered` if no response is received.

### Nmap NSE Script

```bash
# Nmap
# https://nmap.org/
# Enumerate accessible files by testing common filenames
nmap -sU -p 69 --script tftp-enum <target>
```

Expected output on success:
```text
| tftp-enum:
|   pxelinux.cfg/default
|   boot/grub/menu.lst
|_  running-config
```

The `tftp-enum` script tests a built-in list of common filenames. It can also accept a custom wordlist:

```bash
# Nmap
# https://nmap.org/
nmap -sU -p 69 --script tftp-enum --script-args tftp-enum.filelist=/path/to/wordlist.txt <target>
```

### Manual File Retrieval

TFTP has no directory listing command — you must request files by exact name:

```bash
tftp <target>
get /etc/passwd
get running-config
get startup-config
get pxelinux.cfg/default
quit
```

Or as one-liners:

```bash
# Using tftp client
tftp <target> -c get running-config

# Using curl (if compiled with TFTP support)
curl tftp://<target>/running-config -o running-config
```

A successful transfer downloads the file silently. A failed transfer returns `Error code 1: File not found` or times out.

### Common TFTP File Targets

Since directory listing is impossible, target files based on the device type:

| Device Type | Files to Try |
|-------------|-------------|
| Network equipment (Cisco) | `running-config`, `startup-config`, `vlan.dat` |
| PXE boot servers | `pxelinux.cfg/default`, `pxelinux.0`, `boot/grub/menu.lst` |
| VoIP phones | `SIPDefault.cnf`, `SEP<MAC>.cnf.xml` |
| General | `/etc/passwd`, `/etc/shadow`, `backup.tar`, `config.bak` |

Network equipment configuration files are the highest-value TFTP target — they often contain plaintext or weakly hashed credentials, SNMP community strings, VPN keys, and full network topology.

PXE boot configurations may reveal installation scripts, preseed files, or kickstart files that contain default credentials or point to internal servers.

### Write Access Testing

TFTP servers may allow file uploads without authentication:

```bash
echo "test" > test.txt
tftp <target> -c put test.txt
```

If the upload succeeds, any file in the TFTP root can be overwritten. On PXE boot servers, this could allow replacing boot images or configuration files with malicious versions.

## Post-Enumeration

With TFTP file access confirmed, prioritize:
- Network equipment configs for credentials, SNMP community strings, and topology
- PXE boot files for installation scripts, preseed/kickstart configs, and internal server references
- Testing write access for config replacement or malicious boot image deployment
- Using extracted credentials against other services (SSH, SNMP, web management)

## References

### Official Documentation

- [Nmap tftp-enum NSE Script](https://nmap.org/nsedoc/scripts/tftp-enum.html)
- [RFC 1350 - TFTP Protocol Revision 2](https://datatracker.ietf.org/doc/html/rfc1350)
- [RFC 2347 - TFTP Option Extension](https://datatracker.ietf.org/doc/html/rfc2347)

### MITRE ATT&CK

- [T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)
