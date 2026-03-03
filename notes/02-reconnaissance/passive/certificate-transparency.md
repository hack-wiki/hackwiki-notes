% Filename: 02-reconnaissance/passive/certificate-transparency.md
% Display name: Certificate Transparency
% Last update: 2026-02-10
% ATT&CK Tactics: TA0043 (Reconnaissance)
% ATT&CK Techniques: T1596.003 (Search Open Technical Databases: Digital Certificates)
% Authors: @TristanInSec

# Certificate Transparency

## Overview

Certificate Transparency (CT) is a public logging framework that records every SSL/TLS certificate issued by trusted Certificate Authorities. CAs are required to submit certificates to multiple CT logs before issuance. These logs are append-only, publicly auditable, and searchable.

For reconnaissance, CT logs are a goldmine. Every certificate contains domain names in the Subject and Subject Alternative Names (SAN) fields — including internal subdomains, staging environments, and services the organization may not realize are publicly discoverable. Because CT logging is mandatory for browser-trusted certificates, any domain with HTTPS has been logged.

CT logs capture certificates at the moment of issuance. This means you can discover subdomains before they even resolve in public DNS, if the certificate was provisioned before the DNS record went live.

## ATT&CK Mapping

- **Tactic:** TA0043 - Reconnaissance
- **Technique:** T1596.003 - Search Open Technical Databases: Digital Certificates

## Prerequisites

- Internet access (no target interaction)
- `curl` and `python3` (or `jq`) for API queries
- Browser for manual search

## CT Log Search Engines

### crt.sh

crt.sh is the most widely used CT log search engine, maintained by Sectigo. It indexes certificates from all major CT logs.

```bash
# Search for all certificates matching a domain
curl -s "https://crt.sh/?q=%25.example.com&output=json" | \
  python3 -c "
import sys, json
data = json.load(sys.stdin)
names = set()
for cert in data:
    for name in cert['name_value'].split('\n'):
        name = name.strip().lower()
        if name:
            names.add(name)
for n in sorted(names):
    print(n)
" > ct_domains.txt
```

The `%25` is URL-encoded `%`, which acts as a wildcard in crt.sh queries. This returns all certificates where any name ends with `.example.com`.

```bash
# Search for exact domain certificates (no wildcard)
curl -s "https://crt.sh/?q=example.com&output=json" | python3 -m json.tool | head -50
```

### crt.sh Output Fields

Each JSON entry contains:

| Field | Description |
|-------|-------------|
| `issuer_ca_id` | ID of the issuing CA |
| `issuer_name` | Full CA name (e.g., "C=US, O=Let's Encrypt") |
| `common_name` | CN field of the certificate |
| `name_value` | All names in the SAN field (newline-separated) |
| `not_before` | Certificate validity start date |
| `not_after` | Certificate expiration date |
| `serial_number` | Unique certificate serial |

### Filtering crt.sh Results

```bash
# Extract unique subdomains only (exclude wildcards)
curl -s "https://crt.sh/?q=%25.example.com&output=json" | \
  python3 -c "
import sys, json
data = json.load(sys.stdin)
names = set()
for cert in data:
    for name in cert['name_value'].split('\n'):
        name = name.strip().lower()
        if name and not name.startswith('*'):
            names.add(name)
for n in sorted(names):
    print(n)
"
```

```bash
# Filter for recently issued certificates only (last 90 days)
curl -s "https://crt.sh/?q=%25.example.com&output=json" | \
  python3 -c "
import sys, json
from datetime import datetime, timedelta
data = json.load(sys.stdin)
cutoff = (datetime.now() - timedelta(days=90)).strftime('%Y-%m-%dT%H:%M:%S')
for cert in data:
    if cert.get('not_before','') >= cutoff:
        print(f\"{cert['not_before'][:10]}  {cert['name_value'].split(chr(10))[0]}\")
"
```

Recent certificates reveal new infrastructure being deployed — staging servers, new applications, cloud migrations.

### Censys Certificate Search

Censys indexes CT logs and adds its own internet-wide scan data, providing richer context (associated IPs, open ports, running services).

```bash
# Censys CLI
# https://github.com/censys/censys-python
censys search "services.tls.certificates.leaf_data.names: example.com"
```

```bash
# Censys API
curl -s "https://search.censys.io/api/v2/certificates/search" \
  -H "Authorization: Basic $(echo -n '<API_ID>:<API_SECRET>' | base64)" \
  -H "Content-Type: application/json" \
  -d '{"q": "names: example.com", "per_page": 100}' | python3 -m json.tool
```

Censys enriches certificate data with host information — you get not just the domain names but the IPs they resolved to and what services were running when Censys scanned them.

### Google Certificate Transparency Search

Google operates its own CT log search:

```text
https://transparencyreport.google.com/https/certificates
```

The web interface allows searching by domain and shows certificate details, issuing CA, validity period, and all SANs. Useful for quick manual lookups.

## Wildcard Certificate Analysis

Wildcard certificates (`*.example.com`) deserve special attention. An organization using wildcards indicates:
- They have many subdomains (justifies a wildcard over individual certs)
- All subdomains share the same certificate, making individual subdomain discovery harder via TLS fingerprinting
- Internal subdomains may be in use that are not publicly documented

When you see wildcard certificates, intensify subdomain enumeration via other passive sources (DNS aggregators, Wayback Machine, search engines) since the CT log won't reveal specific subdomain names.

## CT Monitoring

CT monitoring is a defensive technique, but understanding it helps with offensive awareness — organizations that monitor CT logs may detect certificate-based reconnaissance patterns.

### Monitoring for New Certificates

```bash
# certstream — real-time CT log monitoring (not in Kali by default)
# https://github.com/CaliDog/certstream-python
pip install certstream --break-system-packages

python3 -c "
import certstream

def callback(message, context):
    if message['message_type'] == 'certificate_update':
        all_domains = message['data']['leaf_cert']['all_domains']
        for domain in all_domains:
            if 'example.com' in domain:
                print(f\"[NEW CERT] {domain}\")

certstream.listen_for_events(callback, url='wss://certstream.calidog.io/')
"
```

> **Note:** The public CaliDog certstream WebSocket (`wss://certstream.calidog.io/`) has had intermittent availability. If it is unresponsive, you can self-host the [certstream-server](https://github.com/CaliDog/certstream-server) to get the same real-time CT log feed.

This streams certificate issuance events in real-time from CT logs. For recon, it can catch new infrastructure as it comes online. For defense, it detects unauthorized certificate issuance (phishing domains mimicking your brand, certificate mis-issuance).

## Practical Workflow

1. **Start with crt.sh** — query `%.example.com` to get all historically issued certificates
2. **Extract unique subdomains** — parse SAN fields, remove wildcards, deduplicate
3. **Check issuance dates** — recent certificates indicate active or new infrastructure
4. **Cross-reference with other sources** — feed discovered subdomains into subfinder/amass for additional discovery
5. **Look for patterns** — naming conventions (dev-*, staging-*, internal-*) reveal infrastructure organization
6. **Note the CAs** — Let's Encrypt certificates are often automated and may indicate ephemeral infrastructure; DigiCert or Sectigo certificates suggest corporate-managed domains

## Post-Collection

CT log findings feed directly into:
- Subdomain enumeration (merge with other passive sources)
- Infrastructure mapping (certificate SANs often group related services)
- Phishing detection (monitor for certificates mimicking your target's domains)
- Cloud asset discovery (certificates for `*.example.com` on cloud provider IPs)

## References

### Official Documentation

- [Certificate Transparency — Google](https://certificate.transparency.dev/)
- [RFC 6962 — Certificate Transparency](https://datatracker.ietf.org/doc/html/rfc6962)
- [crt.sh — Sectigo Certificate Search](https://crt.sh/)
- [certstream GitHub Repository](https://github.com/CaliDog/certstream-python)

### OSINT Resources

- [Censys Search — Certificate Search](https://search.censys.io/)
- [Google Transparency Report — Certificate Search](https://transparencyreport.google.com/https/certificates)

### MITRE ATT&CK

- [T1596.003 - Search Open Technical Databases: Digital Certificates](https://attack.mitre.org/techniques/T1596/003/)
