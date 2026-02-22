% Filename: 02-reconnaissance/passive/osint.md
% Display name: OSINT Techniques
% Last update: 2026-02-10
% ATT&CK Tactics: TA0043 (Reconnaissance)
% ATT&CK Techniques: T1589 (Gather Victim Identity Information), T1591 (Gather Victim Org Information), T1593 (Search Open Websites/Domains)
% Authors: @TristanInSec

# OSINT Techniques

## Overview

Open Source Intelligence (OSINT) is the collection and analysis of information from publicly available sources to build a profile of a target — its people, infrastructure, technology, and organizational structure. OSINT requires no interaction with target systems. Everything comes from search engines, social media, public records, code repositories, job postings, and data breach databases.

For penetration testers, OSINT shapes the attack surface before any scanning begins. Knowing email formats, employee names, technology stacks, and third-party relationships lets you target phishing campaigns, guess credentials, and identify weak points that automated tools will miss.

## ATT&CK Mapping

- **Tactic:** TA0043 - Reconnaissance
- **Techniques:**
  - T1589 - Gather Victim Identity Information
  - T1591 - Gather Victim Org Information
  - T1593 - Search Open Websites/Domains

## Prerequisites

- Internet access (no target interaction required)
- Browser with developer tools
- OSINT tools installed (theHarvester, Recon-ng, Maltego)
- API keys for data providers (Shodan, Censys, Hunter.io — free tiers available)

## People Intelligence

### Email Harvesting

Discovering email addresses reveals naming conventions, employee identities, and potential targets for phishing or password spraying.

```bash
# theHarvester
# https://github.com/laramies/theHarvester
theHarvester -d example.com -b bing,crtsh,dnsdumpster -l 500
```

The `-b` flag specifies data sources. Common sources: `bing`, `duckduckgo`, `dnsdumpster`, `crtsh`, `certspotter`, `virustotal`. The `-l` flag limits the number of results. Note: `google` and `linkedin` were removed as valid sources in recent theHarvester versions — check `theHarvester -h` for the current list.

```bash
# Search Hunter.io for email patterns (requires API key)
curl -s "https://api.hunter.io/v2/domain-search?domain=example.com&api_key=<KEY>" | python3 -m json.tool
```

Hunter.io returns the email format (e.g., `{first}.{last}@example.com`), confidence scores, and individual addresses found publicly.

```bash
# Extract emails from search engine results manually
# Use site-specific searches in a browser:
# site:example.com "@example.com"
# site:linkedin.com "example.com" email
```

### Employee Enumeration

LinkedIn is the primary source for employee names, roles, and organizational structure. Direct scraping violates LinkedIn's ToS, so use search engine caching and public profiles.

```bash
# Google dork for LinkedIn employees
# site:linkedin.com/in "example.com"
# site:linkedin.com/in "Company Name" "Security Engineer"
```

Once names are collected, combine them with the discovered email format to generate a target email list:

```bash
# Generate email list from names (assuming first.last format)
cat names.txt | while read first last; do
  echo "${first,,}.${last,,}@example.com"
done > emails.txt
```

### Breach Data Checks

Check whether employee emails appear in known data breaches. This indicates potential credential reuse.

Services for breach lookups (use responsibly, within engagement scope):
- **Have I Been Pwned** (haveibeenpwned.com) — free email lookup, API available
- **DeHashed** (dehashed.com) — searchable breach database (paid)
- **Intelligence X** (intelx.io) — search engine for leaked data

```bash
# HIBP API check for a single email (requires API key)
curl -s -H "hibp-api-key: <KEY>" \
  "https://haveibeenpwned.com/api/v3/breachedaccount/user@example.com"
```

A non-empty response means the email appeared in at least one breach. Cross-reference with the breach name to determine what data was exposed (passwords, hashes, personal info).

## Organization Intelligence

### Technology Stack Discovery

Identifying the target's technology stack reveals potential attack vectors and narrows tool selection.

```bash
# Wappalyzer / webanalyze (Go CLI alternative — not in Kali by default)
# https://github.com/rverton/webanalyze
# go install github.com/rverton/webanalyze/cmd/webanalyze@latest
webanalyze -host example.com -crawl 2
```

```bash
# BuiltWith lookup (browser-based)
# https://builtwith.com/example.com
```

```bash
# Check HTTP headers for technology fingerprints
curl -sI https://example.com | grep -iE "server|x-powered|x-aspnet|x-generator"
```

Common indicators in headers: `Server: nginx/1.24.0`, `X-Powered-By: PHP/8.2`, `X-AspNet-Version`, `X-Generator: WordPress 6.4`.

### Job Postings

Job listings reveal internal technology, tools, and infrastructure details that are rarely documented elsewhere.

Search for:
- **Technologies mentioned** — "Experience with Kubernetes, AWS EKS, Terraform" reveals cloud infrastructure
- **Security tools** — "Splunk", "CrowdStrike", "Palo Alto" reveals defensive posture
- **Internal platforms** — "Familiarity with our internal CI/CD pipeline using Jenkins" reveals specific tooling

Sources: LinkedIn Jobs, Indeed, Glassdoor, the company's own careers page.

### Public Code Repositories

Developers frequently leak sensitive data in public repositories — API keys, internal hostnames, database credentials, infrastructure configuration.

```bash
# Search GitHub for organization repos
# https://github.com/orgs/example-org/repositories

# GitHub dork: search for secrets in an org's code
# In GitHub search:
# org:example-org password
# org:example-org api_key
# org:example-org BEGIN RSA PRIVATE KEY
# org:example-org jdbc:mysql://
```

```bash
# truffleHog — scan repos for high-entropy strings and secrets
# https://github.com/trufflesecurity/trufflehog
# Install: curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
trufflehog github --org=example-org
```

```bash
# GitDorker — automate GitHub dorking with predefined patterns
# https://github.com/obheda12/GitDorker
# git clone https://github.com/obheda12/GitDorker.git && pip install -r requirements.txt --break-system-packages
python3 GitDorker.py -t <GITHUB_TOKEN> -org example-org -d dorks/alldorksv3
```

Also check: GitLab public groups, Bitbucket public repos, and Pastebin/Ghostbin for leaked snippets referencing the target domain.

### DNS and WHOIS

WHOIS records reveal registrant information, name servers, and registration dates. While privacy protection is common, older or forgotten domains often have exposed registrant details.

```bash
whois example.com
```

Key fields: Registrant Name, Registrant Email, Name Servers, Creation/Expiry dates.

```bash
# Reverse WHOIS — find other domains registered by the same entity
# Services: ViewDNS.info, DomainTools, WhoisXMLAPI
curl -s "https://api.viewdns.info/reversewhois/?q=admin@example.com&apikey=<KEY>&output=json"
```

Reverse WHOIS is valuable for discovering subsidiaries, shadow IT domains, and infrastructure the target forgot about.

## Infrastructure Intelligence

### Shodan Reconnaissance

Shodan indexes internet-facing devices and services. It reveals open ports, software versions, SSL certificates, and default configurations — without sending any traffic to the target.

```bash
# Shodan CLI
# https://github.com/achillean/shodan-python
shodan search "hostname:example.com"
shodan host 203.0.113.10
```

```bash
# Shodan browser queries (shodan.io):
# hostname:example.com
# org:"Example Corp"
# ssl.cert.subject.cn:example.com
# net:203.0.113.0/24
```

Shodan results include open ports, running services, SSL certificate details, HTTP response headers, and known vulnerabilities (CVE references).

### Censys Reconnaissance

Censys provides similar internet scanning data with a focus on certificate and host analysis.

```bash
# Censys CLI
# https://github.com/censys/censys-python
censys search "services.tls.certificates.leaf_data.names: example.com"
censys view 203.0.113.10
```

### Archived Content

The Wayback Machine (web.archive.org) stores historical snapshots of websites. Old versions often contain pages, endpoints, or configurations that were removed but remain relevant.

```bash
# Wayback Machine CDX API — list all archived URLs for a domain
curl -s "https://web.archive.org/cdx/search/cdx?url=example.com/*&output=text&fl=original&collapse=urlkey" | sort -u > wayback_urls.txt
```

```bash
# waybackurls — extract URLs from Wayback Machine (Go tool)
# https://github.com/tomnomnom/waybackurls
# go install github.com/tomnomnom/waybackurls@latest
echo "example.com" | waybackurls | sort -u > urls.txt
```

Look for removed admin panels, old API endpoints, backup files, and configuration pages that may still be live or reveal internal structure.

## OSINT Frameworks

### Recon-ng

Recon-ng is a modular OSINT framework with a Metasploit-style interface. It automates data collection across multiple sources and stores results in a local database.

```bash
# Recon-ng
# https://github.com/lanmaster53/recon-ng
recon-ng
```

```bash
# Recon-ng
# https://github.com/lanmaster53/recon-ng
# Inside Recon-ng:
workspaces create example-engagement
modules load recon/domains-hosts/certificate_transparency
options set SOURCE example.com
run

# Other useful modules:
modules load recon/domains-contacts/whois_pocs
modules load recon/profiles-profiles/profiler
modules load recon/domains-hosts/hackertarget
```

Recon-ng stores all discovered hosts, contacts, and credentials in a SQLite database. Export with `reporting/list` or `reporting/csv`.

### SpiderFoot

SpiderFoot automates OSINT collection across 200+ data sources and correlates results into a graph.

```bash
# SpiderFoot
# https://github.com/smicallef/spiderfoot
# Web UI mode:
python3 sf.py -l 127.0.0.1:5001

# CLI scan (sf.py can run scans directly from the command line):
# SpiderFoot auto-detects target type from the input
python3 sf.py -s example.com -m sfp_dnsresolve,sfp_shodan
```

### Maltego

Maltego is a graphical link analysis tool for OSINT. It visualizes relationships between entities (people, domains, IPs, emails) using data transforms from public APIs. The Community Edition is free. Maltego is not command-line based — it runs as a desktop application with drag-and-drop entity investigation.

## Post-Collection

After gathering OSINT data:
- Deduplicate and normalize findings (consistent email format, resolved hostnames)
- Cross-reference employee names with breach databases
- Map discovered infrastructure to IP ranges for scope validation
- Feed subdomains and hostnames into active reconnaissance
- Identify high-value targets for phishing (finance, IT admins, executives)
- Document all sources for the engagement report

## References

### Official Documentation

- [theHarvester GitHub Repository](https://github.com/laramies/theHarvester)
- [Recon-ng GitHub Repository](https://github.com/lanmaster53/recon-ng)
- [SpiderFoot GitHub Repository](https://github.com/smicallef/spiderfoot)
- [truffleHog GitHub Repository](https://github.com/trufflesecurity/trufflehog)

### OSINT Resources

- [OSINT Framework (osintframework.com)](https://osintframework.com/)
- [Have I Been Pwned](https://haveibeenpwned.com/)
- [Shodan Search Engine](https://www.shodan.io/)
- [Censys Search Engine](https://search.censys.io/)
- [Wayback Machine](https://web.archive.org/)

### MITRE ATT&CK

- [T1589 - Gather Victim Identity Information](https://attack.mitre.org/techniques/T1589/)
- [T1591 - Gather Victim Org Information](https://attack.mitre.org/techniques/T1591/)
- [T1593 - Search Open Websites/Domains](https://attack.mitre.org/techniques/T1593/)
