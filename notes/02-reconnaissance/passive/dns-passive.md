% Filename: 02-reconnaissance/passive/dns-passive.md
% Display name: Passive DNS
% Last update: 2026-02-10
% ATT&CK Tactics: TA0043 (Reconnaissance)
% ATT&CK Techniques: T1596.001 (Search Open Technical Databases: DNS/Passive DNS)
% Authors: @TristanInSec

# Passive DNS

## Overview

Passive DNS (pDNS) databases collect DNS resolution data from sensors distributed across the internet — recursive resolvers, ISP networks, and security companies. When any device resolves `mail.example.com` to `203.0.113.10`, that resolution event is recorded and timestamped. Over time, this builds a historical map of which domains pointed to which IPs, and when.

For reconnaissance, passive DNS answers questions that live DNS cannot: what IP did this domain resolve to six months ago? What other domains shared this IP? When did a domain change hosting providers? What subdomains existed before they were decommissioned?

Unlike live DNS queries (which hit the target's authoritative servers and constitute active recon), passive DNS queries go to third-party databases. No traffic reaches the target.

## ATT&CK Mapping

- **Tactic:** TA0043 - Reconnaissance
- **Technique:** T1596.001 - Search Open Technical Databases: DNS/Passive DNS

## Prerequisites

- Internet access (no target interaction)
- Accounts on pDNS providers (free tiers available)
- `curl`, `python3`, `jq` for API queries

## Passive DNS Providers

### SecurityTrails

SecurityTrails maintains one of the largest passive DNS databases, with historical records going back years.

```bash
# Current DNS records for a domain
curl -s "https://api.securitytrails.com/v1/domain/example.com" \
  -H "APIKEY: <KEY>" | python3 -m json.tool
```

```bash
# Historical DNS A records
curl -s "https://api.securitytrails.com/v1/history/example.com/dns/a" \
  -H "APIKEY: <KEY>" | \
  python3 -c "
import sys, json
data = json.load(sys.stdin)
for record in data.get('records', []):
    first = record.get('first_seen', 'unknown')
    last = record.get('last_seen', 'unknown')
    for val in record.get('values', []):
        print(f\"{first} → {last}  {val.get('ip', 'N/A')}\")
"
```

Historical A records show IP migrations — useful for identifying shared hosting, cloud migrations, and infrastructure changes.

```bash
# Reverse DNS — find all domains that resolved to an IP
curl -s "https://api.securitytrails.com/v1/domains/list" \
  -H "APIKEY: <KEY>" \
  -H "Content-Type: application/json" \
  -d '{"filter": {"ipv4": "203.0.113.10"}}' | python3 -m json.tool
```

### VirusTotal

VirusTotal records DNS resolutions observed during its scanning operations.

```bash
# DNS resolutions for a domain
curl -s "https://www.virustotal.com/api/v3/domains/example.com/resolutions" \
  -H "x-apikey: <KEY>" | \
  python3 -c "
import sys, json
data = json.load(sys.stdin)
for item in data.get('data', []):
    attrs = item.get('attributes', {})
    print(f\"{attrs.get('date', 'N/A')}  {attrs.get('ip_address', 'N/A')}  {attrs.get('host_name', 'N/A')}\")
"
```

```bash
# Reverse lookup — domains associated with an IP
curl -s "https://www.virustotal.com/api/v3/ip_addresses/203.0.113.10/resolutions" \
  -H "x-apikey: <KEY>" | python3 -m json.tool
```

### Robtex

Robtex provides passive DNS lookups with a web interface and API.

```bash
# Web interface
https://www.robtex.com/dns-lookup/example.com
```

Robtex shows forward DNS records, reverse DNS (IP to domain), and related domains sharing the same IP or name server. The web interface includes visual graphs of domain relationships.

### DNSdumpster

DNSdumpster by HackerTarget provides passive DNS reconnaissance with network mapping.

```bash
# Web interface
https://dnsdumpster.com/
```

DNSdumpster shows DNS servers, MX records, TXT records, host records, and generates a domain map visualization. It also identifies the hosting provider and ASN for discovered IPs.

### CIRCL Passive DNS

CIRCL (Computer Incident Response Center Luxembourg) operates a public passive DNS service.

```bash
# CIRCL pDNS API
curl -s -u <USER>:<PASS> "https://www.circl.lu/pdns/query/example.com" | \
  python3 -c "
import sys, json
for line in sys.stdin:
    record = json.loads(line)
    print(f\"{record.get('time_first','?')} → {record.get('time_last','?')}  {record.get('rrtype','?')}  {record.get('rdata','?')}\")
"
```

CIRCL pDNS returns NDJSON (newline-delimited JSON). Each line is a separate record with `time_first`, `time_last`, `rrtype`, `rrname`, and `rdata` fields.

## Key Techniques

### Historical IP Tracking

Track how a domain's IP has changed over time to identify:
- Previous hosting providers (may still have data, configurations, or access)
- IP address reuse (new tenant on old IP may inherit security issues)
- Cloud migration timelines

```bash
# SecurityTrails historical A records
curl -s "https://api.securitytrails.com/v1/history/example.com/dns/a" \
  -H "APIKEY: <KEY>" | \
  python3 -c "
import sys, json
data = json.load(sys.stdin)
for r in data.get('records', []):
    for v in r.get('values', []):
        print(f\"{r.get('first_seen','?')} to {r.get('last_seen','?')}  →  {v.get('ip','?')}\")
"
```

### Reverse DNS Pivoting

Starting from a known target IP, discover all other domains hosted on the same infrastructure.

```bash
# Find domains sharing the same IP
# VirusTotal reverse resolution
curl -s "https://www.virustotal.com/api/v3/ip_addresses/203.0.113.10/resolutions?limit=40" \
  -H "x-apikey: <KEY>" | \
  python3 -c "
import sys, json
data = json.load(sys.stdin)
for item in data.get('data', []):
    print(item['attributes'].get('host_name', 'N/A'))
" | sort -u
```

Shared hosting reveals the target's neighbors. On shared infrastructure, compromising one site may provide access to others. It also reveals other domains the organization owns that may not be listed publicly.

### Name Server Correlation

Domains managed by the same organization often share name servers. Querying passive DNS for all domains using the same NS records reveals the full domain portfolio.

```bash
# SecurityTrails — domains using the same name server
curl -s "https://api.securitytrails.com/v1/domains/list" \
  -H "APIKEY: <KEY>" \
  -H "Content-Type: application/json" \
  -d '{"filter": {"ns": "ns1.example.com"}}' | python3 -m json.tool
```

### MX Record Analysis

Mail exchange records reveal email infrastructure, which may differ from web infrastructure and present separate attack surfaces.

```bash
# Historical MX records
curl -s "https://api.securitytrails.com/v1/history/example.com/dns/mx" \
  -H "APIKEY: <KEY>" | python3 -m json.tool
```

MX records pointing to Google Workspace (`aspmx.l.google.com`) vs on-premise Exchange vs third-party filtering (Proofpoint, Mimecast) reveal the email security posture and potential attack vectors.

### TXT Record Intelligence

TXT records contain SPF, DKIM, DMARC, and verification tokens that reveal third-party service integrations.

```bash
# Current TXT records (this is a live DNS query — technically active recon)
dig TXT example.com +short
```

Common findings in TXT records:
- `v=spf1` — SPF record reveals authorized email senders
- `_dmarc` — DMARC policy strength (none, quarantine, reject)
- `google-site-verification=` — Google Workspace in use
- `ms=` — Microsoft 365 verification
- `atlassian-domain-verification=` — Atlassian/Jira in use
- `docusign=` — DocuSign integration
- `facebook-domain-verification=` — Facebook Business Manager

Each verification token confirms a third-party service the organization uses — valuable for social engineering and targeted phishing.

## Post-Collection

Passive DNS findings feed into:
- IP range mapping (historical IPs reveal the full infrastructure footprint)
- Shared hosting analysis (other domains on the same IPs)
- Infrastructure timeline (when services moved, changed, or were decommissioned)
- Active DNS enumeration (verify which historical records still resolve)
- Technology profiling (MX and TXT records reveal email and SaaS stack)

## References

### Official Documentation

- [SecurityTrails API Documentation](https://docs.securitytrails.com/docs/overview)
- [VirusTotal API v3 Documentation](https://docs.virustotal.com/reference/overview)
- [CIRCL Passive DNS](https://www.circl.lu/services/passive-dns/)
- [DNSdumpster by HackerTarget](https://dnsdumpster.com/)
- [Robtex](https://www.robtex.com/)

### Pentest Guides & Research

- [Rapid7 Project Sonar — Open Data](https://opendata.rapid7.com/)

### MITRE ATT&CK

- [T1596.001 - Search Open Technical Databases: DNS/Passive DNS](https://attack.mitre.org/techniques/T1596/001/)
