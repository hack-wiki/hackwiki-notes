% Filename: 02-reconnaissance/enum-network/snmp.md
% Display name: SNMP Enumeration
% Last update: 2026-02-19
% ATT&CK Tactics: TA0043 (Reconnaissance), TA0009 (Collection)
% ATT&CK Techniques: T1595 (Active Scanning), T1602 (Data from Configuration Repository)
% Authors: @TristanInSec

# SNMP Enumeration

## Overview

SNMP runs on UDP 161 (queries) and UDP 162 (traps). Enumeration targets community string discovery, MIB tree walking, and data extraction. SNMP v1 and v2c transmit community strings in plaintext — a correct community string grants read (and sometimes write) access to device configuration, network topology, running processes, installed software, and user accounts.

## ATT&CK Mapping

- **Tactics:** TA0043 - Reconnaissance, TA0009 - Collection
- **Technique:** T1595 - Active Scanning
- **Technique:** T1602 - Data from Configuration Repository

## Prerequisites

- Network access to target UDP 161
- `snmpwalk`, `snmpget`, or `snmp-check` installed
- Community string(s) — default is often `public` (read) and `private` (read-write)

## Enumeration Techniques

### Community String Discovery

Default community strings are the most common SNMP misconfiguration. Start by testing well-known defaults:

```bash
# Net-SNMP (snmpwalk)
# https://www.net-snmp.org/
snmpwalk -v2c -c public <target> 1
```

If the target responds with OID data, the community string is valid. If it times out, the string may be wrong or SNMP may be filtered. `noSuchName` is an SNMPv1-specific error code; on SNMPv2c/v3 you may see different responses. Treat any error as a signal to investigate, not definitive proof.

```bash
# Nmap
# https://nmap.org/
# Brute-force community strings
nmap -sU -p 161 --script snmp-brute <target>
```

Expected output on success (truncated):
```text
| snmp-brute:
|   public - Valid credentials
|_  private - Valid credentials
```

```bash
# onesixtyone
# https://github.com/trailofbits/onesixtyone
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt <target>

# Against multiple targets
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt -i targets.txt
```

Onesixtyone is significantly faster than Nmap for community string brute-forcing across large target lists because it sends all requests asynchronously.

### Full MIB Tree Walk

Once a valid community string is found, walk the entire MIB tree:

```bash
# Net-SNMP (snmpwalk)
# https://www.net-snmp.org/
# Walk all OIDs (verbose output with descriptions)
snmpwalk -v2c -c public <target>

# Walk with numeric OIDs only (cleaner for parsing)
snmpwalk -v2c -c public -On <target>

# SNMPv1 (fall back if v2c fails)
snmpwalk -v1 -c public <target>
```

A full walk on a verbose device (router, switch, Windows host) can return thousands of OIDs. Pipe to a file for offline analysis:

```bash
# Net-SNMP (snmpwalk)
# https://www.net-snmp.org/
snmpwalk -v2c -c public <target> > snmp_full_walk.txt
```

### Targeted OID Enumeration

Instead of walking everything, query specific high-value OID subtrees directly:

```bash
# Net-SNMP (snmpwalk)
# https://www.net-snmp.org/
# System information (hostname, description, uptime, contact)
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.1

# Network interfaces
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.2.2.1

# IP addresses configured on the device
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.4.20

# Routing table
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.4.21

# ARP table (IP-to-MAC mappings — reveals other hosts on the network)
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.4.22.1

# TCP open connections
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.6.13

# UDP listening ports
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.7.5

# Installed software (Windows)
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.25.6.3.1.2

# Running processes
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.25.4.2.1.2

# Storage/disk information
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.25.2

# User accounts (Windows)
snmpwalk -v2c -c public <target> 1.3.6.1.4.1.77.1.2.25
```

The Windows user accounts OID (`1.3.6.1.4.1.77.1.2.25`) is particularly valuable — it enumerates local user accounts without authentication beyond the community string.

### High-Value OID Reference

| OID | Data | Value |
|-----|------|-------|
| 1.3.6.1.2.1.1 | System info | Hostname, OS, uptime, contact |
| 1.3.6.1.2.1.2.2.1 | Interfaces | Network adapters, IPs, MACs |
| 1.3.6.1.2.1.4.20 | IP addresses | All configured addresses |
| 1.3.6.1.2.1.4.21 | Routing table | Internal network topology |
| 1.3.6.1.2.1.4.22.1 | ARP table | Neighboring hosts |
| 1.3.6.1.2.1.6.13 | TCP connections | Active connections, listening ports |
| 1.3.6.1.2.1.25.4.2.1.2 | Processes | Running software |
| 1.3.6.1.2.1.25.6.3.1.2 | Installed software | Software inventory (Windows) |
| 1.3.6.1.4.1.77.1.2.25 | User accounts | Local users (Windows) |

### Automated Enumeration with snmp-check

```bash
# snmp-check
# https://www.nothink.org/codes/snmpcheck/
snmp-check <target> -c public -v 2c   # Default is v1; use -v 2c for SNMPv2c
```

`snmp-check` parses the raw OID output into human-readable categories: system info, user accounts, processes, network interfaces, routing, listening ports, storage, and installed software. One command gives a formatted overview of everything.

### Nmap NSE Scripts

```bash
# Nmap
# https://nmap.org/
# System information extraction
nmap -sU -p 161 --script snmp-sysdescr <target>

# Enumerate network interfaces
nmap -sU -p 161 --script snmp-interfaces <target>

# Enumerate running processes
nmap -sU -p 161 --script snmp-processes <target>

# Enumerate Windows user accounts
nmap -sU -p 161 --script snmp-win32-users <target>

# Enumerate Windows shares
nmap -sU -p 161 --script snmp-win32-shares <target>

# Enumerate installed software
nmap -sU -p 161 --script snmp-win32-software <target>

# Enumerate network services
nmap -sU -p 161 --script snmp-win32-services <target>

# Run all SNMP scripts
nmap -sU -p 161 --script "snmp-*" <target>
```

All SNMP NSE scripts require a valid community string. If the default `public` doesn't work, add `--script-args snmpcommunity=<string>`.

### SNMPv3 Enumeration

SNMPv3 introduces authentication and encryption. If v3 is in use, you need valid credentials:

```bash
# Net-SNMP (snmpwalk)
# https://www.net-snmp.org/
# SNMPv3 with authentication (authNoPriv)
snmpwalk -v3 -l authNoPriv -u <username> -a SHA -A <auth_pass> <target>

# SNMPv3 with authentication and encryption (authPriv)
snmpwalk -v3 -l authPriv -u <username> -a SHA -A <auth_pass> -x AES -X <priv_pass> <target>
```

```bash
# Nmap
# https://nmap.org/
# Enumerate SNMPv3 usernames (no credentials needed)
nmap -sU -p 161 --script snmp-info <target>
```

The `snmp-info` script can reveal SNMPv3 engine ID and sometimes usernames without authentication, which can then be targeted for credential attacks.

### SNMP Write Access Testing

If the `private` community string (or another read-write string) is valid, write access may allow configuration changes:

```bash
# Net-SNMP (snmpget/snmpset)
# https://www.net-snmp.org/
# Test write access by reading then setting sysContact
snmpget -v2c -c private <target> 1.3.6.1.2.1.1.4.0
snmpset -v2c -c private <target> 1.3.6.1.2.1.1.4.0 s "test"
```

Write access on network devices can enable configuration extraction, VLAN manipulation, or even traffic redirection. On some devices, it allows downloading the full running configuration via TFTP.

## Post-Enumeration

With SNMP data collected, prioritize:
- Extracted usernames for password spraying against other services (SSH, RDP, SMB)
- Network topology from routing and ARP tables for lateral movement planning
- Running processes to identify security software, databases, and vulnerable services
- Installed software versions for known CVE matching
- Write access for device configuration extraction or modification

## References

### Official Documentation

- [Nmap snmp-brute NSE Script](https://nmap.org/nsedoc/scripts/snmp-brute.html)
- [Nmap snmp-sysdescr NSE Script](https://nmap.org/nsedoc/scripts/snmp-sysdescr.html)
- [Nmap snmp-interfaces NSE Script](https://nmap.org/nsedoc/scripts/snmp-interfaces.html)
- [Nmap snmp-processes NSE Script](https://nmap.org/nsedoc/scripts/snmp-processes.html)
- [Onesixtyone](https://github.com/trailofbits/onesixtyone)
- [RFC 3411 - SNMP Architecture](https://datatracker.ietf.org/doc/html/rfc3411)
- [RFC 3414 - SNMPv3 User-based Security Model](https://datatracker.ietf.org/doc/html/rfc3414)

### MITRE ATT&CK

- [T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)
- [T1602 - Data from Configuration Repository](https://attack.mitre.org/techniques/T1602/)
