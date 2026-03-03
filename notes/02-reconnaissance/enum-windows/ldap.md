% Filename: 02-reconnaissance/enum-windows/ldap.md
% Display name: LDAP Enumeration
% Last update: 2026-02-10
% ATT&CK Tactics: TA0043 (Reconnaissance), TA0007 (Discovery)
% ATT&CK Techniques: T1595 (Active Scanning), T1087.002 (Account Discovery: Domain Account)
% Authors: @TristanInSec

# LDAP Enumeration

## Overview

LDAP runs on TCP 389 (plaintext) and TCP 636 (LDAPS). On Active Directory domain controllers, LDAP is the primary directory service — it stores all user accounts, groups, computers, OUs, GPOs, and trust relationships. Enumeration via LDAP can extract the entire AD structure if anonymous bind or authenticated access is available.

## ATT&CK Mapping

- **Tactics:** TA0043 - Reconnaissance, TA0007 - Discovery
- **Technique:** T1595 - Active Scanning
- **Technique:** T1087.002 - Account Discovery: Domain Account

## Prerequisites

- Network access to target TCP 389/636
- `ldapsearch`, Nmap, or NetExec installed
- Optional: `windapsearch` (not on Kali by default)

## Enumeration Techniques

### Service Detection

```bash
# Nmap
# https://nmap.org/
nmap -sV -p 389,636,3268,3269 <target>
```

Port 3268 (Global Catalog) and 3269 (Global Catalog over SSL) are only present on domain controllers and search across the entire forest.

### Anonymous Bind Testing

Some domain controllers allow anonymous LDAP binds — querying the directory without credentials:

```bash
# ldapsearch (OpenLDAP)
# https://openldap.org/
# Test anonymous bind — retrieve base naming context
ldapsearch -x -H ldap://<target> -s base namingcontexts
```

Expected output on success:
```text
dn:
namingContexts: DC=corp,DC=local
namingContexts: CN=Configuration,DC=corp,DC=local
namingContexts: CN=Schema,CN=Configuration,DC=corp,DC=local
namingContexts: DC=DomainDnsZones,DC=corp,DC=local
namingContexts: DC=ForestDnsZones,DC=corp,DC=local
```

If naming contexts are returned, anonymous bind is allowed. The base DN (`DC=corp,DC=local`) is needed for all subsequent queries.


### Domain Enumeration

```bash
# ldapsearch (OpenLDAP)
# https://openldap.org/
# All users
ldapsearch -x -H ldap://<target> -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName

# All computers
ldapsearch -x -H ldap://<target> -b "DC=corp,DC=local" "(objectClass=computer)" name operatingSystem

# All groups
ldapsearch -x -H ldap://<target> -b "DC=corp,DC=local" "(objectClass=group)" cn member

# Domain admins
ldapsearch -x -H ldap://<target> -b "DC=corp,DC=local" "(&(objectClass=group)(cn=Domain Admins))" member

# Service accounts (accounts with SPNs — Kerberoastable)
ldapsearch -x -H ldap://<target> -b "DC=corp,DC=local" "(servicePrincipalName=*)" sAMAccountName servicePrincipalName
```

### Authenticated Queries

```bash
# ldapsearch (OpenLDAP)
# https://openldap.org/
# Authenticated with simple bind
ldapsearch -x -H ldap://<target> -D "<user>@corp.local" -w "<password>" -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName

# LDAPS (encrypted)
ldapsearch -x -H ldaps://<target> -D "<user>@corp.local" -w "<password>" -b "DC=corp,DC=local" "(objectClass=user)"
```

### Targeted Queries

```bash
# ldapsearch (OpenLDAP)
# https://openldap.org/
# Users with "password never expires" flag
ldapsearch -x -H ldap://<target> -b "DC=corp,DC=local" "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))" sAMAccountName

# Disabled accounts
ldapsearch -x -H ldap://<target> -b "DC=corp,DC=local" "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))" sAMAccountName

# Accounts with delegation (unconstrained)
ldapsearch -x -H ldap://<target> -b "DC=corp,DC=local" "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))" sAMAccountName

# Accounts with "Do not require pre-authentication" (ASREPRoastable)
ldapsearch -x -H ldap://<target> -b "DC=corp,DC=local" "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" sAMAccountName

# Group Policy Objects
ldapsearch -x -H ldap://<target> -b "DC=corp,DC=local" "(objectClass=groupPolicyContainer)" displayName gPCFileSysPath
```

The `userAccountControl` bitwise filter (`1.2.840.113556.1.4.803`) is an LDAP matching rule OID specific to Active Directory.

### windapsearch

`windapsearch` is not installed on Kali by default. Install the Python version from source:

```bash
# Install windapsearch from source (not on Kali by default)
# https://github.com/ropnop/windapsearch
git clone https://github.com/ropnop/windapsearch.git
cd windapsearch
pip install python-ldap --break-system-packages
```

```bash
# windapsearch (Python version)
# https://github.com/ropnop/windapsearch
# Enumerate domain admins (recursive — discovers nested memberships)
python3 windapsearch.py -d <domain> --dc-ip <target> --da

# Enumerate all users
python3 windapsearch.py -d <domain> --dc-ip <target> -U

# Enumerate groups
python3 windapsearch.py -d <domain> --dc-ip <target> -G

# Enumerate computers
python3 windapsearch.py -d <domain> --dc-ip <target> -C

# Kerberoastable accounts (SPNs)
python3 windapsearch.py -d <domain> --dc-ip <target> --user-spns

# Members of a specific group
python3 windapsearch.py -d <domain> --dc-ip <target> -m "Remote Desktop Users"

# Custom LDAP filter
python3 windapsearch.py -d <domain> --dc-ip <target> --custom "(servicePrincipalName=*)" --attrs sAMAccountName,servicePrincipalName

# Authenticated
python3 windapsearch.py -d <domain> --dc-ip <target> -u '<user>@<domain>' -p '<password>' -U
```

A Go rewrite ([go-windapsearch](https://github.com/ropnop/go-windapsearch)) is also available with pre-compiled binaries and a module-based syntax (`-m domain-admins`, `-m users`, `-m computers`).

### Nmap NSE Scripts

```bash
# Nmap
# https://nmap.org/
# Extract root DSE (base info, no auth needed)
nmap -p 389 --script ldap-rootdse <target>

# Brute-force LDAP
nmap -p 389 --script ldap-brute <target>

# Search LDAP directory
nmap -p 389 --script ldap-search <target>
```

The `ldap-rootdse` script retrieves the Root DSE (DSA-Specific Entry) which includes naming contexts, supported LDAP versions, supported SASL mechanisms, and the domain functionality level — all without authentication.

### NetExec LDAP Module

```bash
# NetExec
# https://github.com/Pennyw0rth/NetExec
# Enumerate users
nxc ldap <target> -u <user> -p <password> --users

# Enumerate groups
nxc ldap <target> -u <user> -p <password> --groups

# ASREPRoastable accounts
nxc ldap <target> -u <user> -p <password> --asreproast asrep_hashes.txt

# Kerberoastable accounts
nxc ldap <target> -u <user> -p <password> --kerberoasting kerb_hashes.txt

# Extract LAPS passwords (if readable)
nxc ldap <target> -u <user> -p <password> -M laps
```

## Post-Enumeration

With LDAP data collected, prioritize:
- Full user list for password spraying campaigns
- Service accounts with SPNs for Kerberoasting
- Accounts without pre-auth for ASREPRoasting
- Domain Admins and other privileged groups for targeting
- Unconstrained delegation hosts for privilege escalation
- GPO paths for Group Policy Preference (GPP) password extraction
- Computer accounts and OS versions for targeting unpatched systems

## References

### Nmap NSE Scripts

- [ldap-rootdse](https://nmap.org/nsedoc/scripts/ldap-rootdse.html)
- [ldap-search](https://nmap.org/nsedoc/scripts/ldap-search.html)
- [ldap-brute](https://nmap.org/nsedoc/scripts/ldap-brute.html)

### Tools

- [windapsearch — Python](https://github.com/ropnop/windapsearch)
- [go-windapsearch — Go rewrite](https://github.com/ropnop/go-windapsearch)
- [NetExec](https://github.com/Pennyw0rth/NetExec)

### Official Documentation

- [RFC 4511 - LDAP Protocol](https://datatracker.ietf.org/doc/html/rfc4511)
- [Microsoft AD LDAP Matching Rules (userAccountControl bitwise filters)](https://learn.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax)

### MITRE ATT&CK

- [T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)
- [T1087.002 - Account Discovery: Domain Account](https://attack.mitre.org/techniques/T1087/002/)
