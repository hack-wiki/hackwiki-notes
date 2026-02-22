% Filename: 02-reconnaissance/enum-network/dns.md
% Display name: DNS Enumeration
% Last update: 2026-02-10
% ATT&CK Tactics: TA0043 (Reconnaissance)
% ATT&CK Techniques: T1595 (Active Scanning), T1590.002 (Gather Victim Network Information: DNS)
% Authors: @TristanInSec

# DNS Enumeration

## Overview

DNS runs on UDP 53 (queries) and TCP 53 (zone transfers and large responses). Enumeration targets record discovery, zone transfers, reverse lookups, and subdomain brute-forcing. DNS is often the single highest-value enumeration target — it maps the attack surface before anything else is touched.

## ATT&CK Mapping

- **Tactic:** TA0043 - Reconnaissance
- **Technique:** T1595 - Active Scanning
- **Technique:** T1590.002 - Gather Victim Network Information: DNS

## Prerequisites

- Network access to target DNS server(s)
- `dig`, `host`, or `nslookup` installed
- Wordlist for subdomain brute-forcing (e.g., SecLists)

## Enumeration Techniques

### Identify DNS Servers

Before enumerating records, identify authoritative nameservers for the target domain:

```bash
dig NS example.com +short
```

Expected output:
```text
ns1.example.com.
ns2.example.com.
```

Then query those nameservers directly for all subsequent enumeration — they hold the authoritative records.

```bash
host -t NS example.com
```

### Record Enumeration

Query specific record types to build a picture of the infrastructure:

```bash
# A record (IPv4 address)
dig A example.com @ns1.example.com +short

# AAAA record (IPv6 address)
dig AAAA example.com @ns1.example.com +short

# MX records (mail servers)
dig MX example.com @ns1.example.com +short

# TXT records (SPF, DKIM, verification tokens, sometimes secrets)
dig TXT example.com @ns1.example.com

# SOA record (primary nameserver, admin email, serial)
dig SOA example.com @ns1.example.com

# SRV records (service discovery — common in AD environments)
dig SRV _ldap._tcp.example.com @ns1.example.com
dig SRV _kerberos._tcp.example.com @ns1.example.com

# ANY query (request all available records — may be refused)
dig ANY example.com @ns1.example.com
```

TXT records are frequently overlooked but can leak SPF configurations, cloud provider verification tokens, and occasionally API keys or internal notes. SRV records in Active Directory environments reveal domain controllers, Kerberos, and LDAP services.

### Zone Transfer (AXFR)

A zone transfer returns every record in the zone — the single highest-value DNS finding.

```bash
dig AXFR example.com @ns1.example.com
```

Expected output on success (truncated):
```text
example.com.       86400  IN  SOA   ns1.example.com. admin.example.com. 2024010101 ...
example.com.       86400  IN  NS    ns1.example.com.
example.com.       86400  IN  NS    ns2.example.com.
example.com.       86400  IN  A     10.10.10.1
dev.example.com.   86400  IN  A     10.10.10.5
staging.example.com. 86400 IN A     10.10.10.6
```

If the transfer is refused:
```text
; Transfer failed.
```

Always attempt AXFR against every nameserver for the domain — some may be misconfigured while others are locked down.

```bash
host -l example.com ns1.example.com
host -l example.com ns2.example.com
```

### Reverse DNS Lookups

Map IP addresses back to hostnames. Useful for discovering hosts on a known subnet:

```bash
# Single reverse lookup
dig -x 10.10.10.1 +short

# Reverse lookup with host
host 10.10.10.1
```

For scanning a range, loop with a script:

```bash
for ip in $(seq 1 254); do
    host 10.10.10.$ip | grep -v "not found"
done
```

### Nmap DNS Scripts

```bash
# Nmap
# https://nmap.org/
# DNS service detection and version
nmap -sV -p 53 <target>

# Attempt zone transfer
nmap -p 53 --script dns-zone-transfer --script-args dns-zone-transfer.domain=example.com <target>

# Brute-force subdomains
nmap -p 53 --script dns-brute --script-args dns-brute.domain=example.com <target>

# Enumerate DNS service info
nmap -p 53 --script dns-nsid <target>

# Check for DNS recursion (open resolver)
nmap -p 53 --script dns-recursion <target>

# Cache snooping — check if DNS server has cached specific domains
nmap -p 53 --script dns-cache-snoop --script-args dns-cache-snoop.domains={google.com,facebook.com} <target>
```

An open recursive resolver can be abused for DNS amplification attacks and also reveals what domains internal users are resolving via cache snooping.

### Subdomain Brute-Forcing

When zone transfers fail, brute-force subdomain discovery:

```bash
# DNSRecon
# https://github.com/darkoperator/dnsrecon
dnsrecon -d example.com -t brt -D /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Full DNS enumeration (records + zone transfer + brute)
dnsrecon -d example.com -a
```

```bash
# DNSenum
# https://github.com/fwaeytens/dnsenum
dnsenum example.com
dnsenum --enum -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt example.com
```

```bash
# Fierce
# https://github.com/mschwager/fierce
fierce --domain example.com --subdomain-file /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

```bash
# Gobuster DNS mode
# https://github.com/OJ/gobuster
gobuster dns --domain example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50
```

Start with a smaller wordlist (5000 entries) for speed. Escalate to larger lists (20000, 110000) if initial results suggest a rich subdomain structure.

### Certificate Transparency Logs (Passive Subdomain Discovery)

Certificate Transparency (CT) logs record every SSL/TLS certificate issued by trusted CAs. Querying them reveals subdomains without sending a single packet to the target — often finding subdomains that brute-forcing misses.

```bash
# crt.sh — query Certificate Transparency logs (passive, no target contact)
# https://crt.sh/
curl -s "https://crt.sh/?q=%.example.com&output=json" | jq -r '.[].name_value' | sort -u

# Also effective via browser: https://crt.sh/?q=%.example.com
```

CT log querying is passive reconnaissance (T1596.003 — Search Open Technical Databases: Digital Certificates). Combine with brute-forcing for maximum subdomain coverage.

### DNS Record Type Reference

| Record | Purpose | Enumeration Value |
|--------|---------|-------------------|
| A / AAAA | IPv4 / IPv6 address | Core host mapping |
| NS | Nameserver | Zone transfer targets |
| MX | Mail server | Phishing infrastructure, internal hostnames |
| TXT | Arbitrary text | SPF, DKIM, verification tokens, leaked secrets |
| SOA | Zone authority | Admin email, primary NS, zone serial |
| SRV | Service location | AD services (LDAP, Kerberos, SIP) |
| PTR | Reverse DNS | IP-to-hostname mapping |
| CNAME | Alias | Subdomain takeover candidates (dangling CNAMEs) |

CNAME records pointing to decommissioned services (e.g., a deleted S3 bucket or Heroku app) are subdomain takeover candidates — the subdomain can potentially be claimed by an attacker.

## Post-Enumeration

With DNS data collected, prioritize:
- Mapping discovered subdomains to IP ranges for port scanning
- Identifying internal hostnames leaked via zone transfers or reverse lookups
- Checking MX records for mail server enumeration (SMTP, POP3/IMAP)
- Testing dangling CNAMEs for subdomain takeover
- Correlating SRV records with Active Directory enumeration targets

## References

### Official Documentation

- [Nmap dns-zone-transfer NSE Script](https://nmap.org/nsedoc/scripts/dns-zone-transfer.html)
- [Nmap dns-brute NSE Script](https://nmap.org/nsedoc/scripts/dns-brute.html)
- [DNSRecon](https://github.com/darkoperator/dnsrecon)
- [DNSenum](https://github.com/fwaeytens/dnsenum)
- [Fierce](https://github.com/mschwager/fierce)
- [Gobuster](https://github.com/OJ/gobuster)
- [RFC 1035 - Domain Names: Implementation and Specification](https://datatracker.ietf.org/doc/html/rfc1035)
- [RFC 5936 - DNS Zone Transfer Protocol (AXFR)](https://datatracker.ietf.org/doc/html/rfc5936)

### MITRE ATT&CK

- [T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)
- [T1590.002 - Gather Victim Network Information: DNS](https://attack.mitre.org/techniques/T1590/002/)
