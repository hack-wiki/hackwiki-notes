% Filename: 02-reconnaissance/passive/subdomain-enum.md
% Display name: Subdomain Enumeration
% Last update: 2026-02-10
% ATT&CK Tactics: TA0043 (Reconnaissance)
% ATT&CK Techniques: T1596.001 (Search Open Technical Databases: DNS/Passive DNS)
% Authors: @TristanInSec

# Subdomain Enumeration

## Overview

Passive subdomain enumeration discovers subdomains without sending any queries to the target's DNS infrastructure. Instead, it queries third-party data sources — certificate transparency logs, search engine indexes, web archives, and aggregator APIs — that have already collected subdomain information.

Subdomain discovery is critical because each subdomain represents a potential entry point. Forgotten staging environments, development servers, old API endpoints, and internal tools exposed to the internet are common findings. Many organizations have hundreds of subdomains, and most security teams only monitor the well-known ones.

## ATT&CK Mapping

- **Tactic:** TA0043 - Reconnaissance
- **Technique:** T1596.001 - Search Open Technical Databases: DNS/Passive DNS

## Prerequisites

- Internet access (no target interaction)
- Subdomain enumeration tools installed (subfinder, amass, assetfinder)
- API keys for data providers (optional but significantly increase results)

## Techniques

### Aggregator-Based Discovery

These tools query multiple data sources in parallel and deduplicate results. They are the fastest way to build a comprehensive subdomain list.

```bash
# Subfinder
# https://github.com/projectdiscovery/subfinder
subfinder -d example.com -o subdomains.txt
```

Subfinder queries sources including Censys, Shodan, VirusTotal, SecurityTrails, Chaos, and others. Configure API keys in `~/.config/subfinder/provider-config.yaml` for significantly more results.

```bash
# Subfinder
# https://github.com/projectdiscovery/subfinder
# All sources and verbose output
subfinder -d example.com -all -v -o subdomains.txt
```

```bash
# Amass (v5 — passive sources only)
# https://github.com/owasp-amass/amass
amass enum -d example.com
```

Amass v5 runs enumeration via `amass enum -d`. The old `-passive` flag from v3/v4 is no longer used — v5 uses data source configuration in `~/.config/amass/config.yaml` to control active vs passive behavior. Save results directly with output redirection:

```bash
# Amass
# https://github.com/owasp-amass/amass
# Save enumeration results to file
amass enum -d example.com -o amass_subs.txt
```

Configure API keys in `~/.config/amass/config.yaml`. Amass supports over 50 data sources. Refer to the [Amass GitHub repository](https://github.com/owasp-amass/amass) for the current v5 configuration format, as it changed significantly from v3/v4.

```bash
# assetfinder (not in Kali by default — install via Go)
# https://github.com/tomnomnom/assetfinder
# go install github.com/tomnomnom/assetfinder@latest
assetfinder --subs-only example.com > assetfinder_subs.txt
```

Assetfinder is fast and lightweight. It queries Certificate Transparency, VirusTotal, Facebook CT, and other sources. The `--subs-only` flag excludes the root domain from output.

### Certificate Transparency Logs

CT logs are one of the richest passive subdomain sources. Every publicly trusted SSL/TLS certificate is logged, and the Subject Alternative Names (SANs) field lists all domains the certificate covers.

```bash
# Query crt.sh (CT log search engine)
curl -s "https://crt.sh/?q=%25.example.com&output=json" | \
  python3 -c "import sys,json; print('\n'.join(set(n for c in json.load(sys.stdin) for n in c['name_value'].split('\n'))))" | \
  sort -u > ct_subs.txt
```

For in-depth CT log techniques, see the Certificate Transparency guide in this section.

### Search Engine Scraping

Search engines index subdomains as part of their web crawling. Extract them with targeted queries.

```bash
# Google dorking for subdomains
# site:*.example.com -www

# Bing dorking
# site:example.com
```

### Web Archive Extraction

The Wayback Machine stores historical snapshots that contain subdomain references in URLs, links, and redirects.

```bash
# waybackurls (Go tool — not in Kali by default)
# https://github.com/tomnomnom/waybackurls
# go install github.com/tomnomnom/waybackurls@latest
echo "example.com" | waybackurls | unfurl domains | grep "\.example\.com$" | sort -u > wayback_subs.txt
```

```bash
# unfurl — extract components from URLs (Go tool — not in Kali by default)
# https://github.com/tomnomnom/unfurl
# go install github.com/tomnomnom/unfurl@latest
# Used above to extract just the domain from each URL
```

### VirusTotal

VirusTotal maintains a database of observed subdomains from its scanning operations.

```bash
# VirusTotal API (requires free API key)
curl -s "https://www.virustotal.com/api/v3/domains/example.com/subdomains" \
  -H "x-apikey: <API_KEY>" | \
  python3 -c "import sys,json; [print(i['id']) for i in json.load(sys.stdin).get('data',[])]"
```

### SecurityTrails

SecurityTrails maintains one of the largest passive DNS and subdomain databases available.

```bash
# SecurityTrails API (requires account)
curl -s "https://api.securitytrails.com/v1/domain/example.com/subdomains" \
  -H "APIKEY: <KEY>" | \
  python3 -c "import sys,json; [print(s+'.example.com') for s in json.load(sys.stdin).get('subdomains',[])]"
```

### Rapid7 Project Sonar

Project Sonar performs internet-wide scanning and makes datasets available. The Forward DNS dataset contains billions of DNS records.

```bash
# Download and grep (datasets are large — multiple GB compressed)
# https://opendata.rapid7.com/
# Dataset filenames include a date and numeric ID prefix (e.g., YYYY-MM-DD-<epoch>-fdns_a.json.gz)
# Browse the opendata page to find the current filename, then:
zcat <downloaded-fdns_a-file>.json.gz | grep "\.example\.com" | jq -r '.name' | sort -u
```

This dataset is large and slow to process, but it catches subdomains that no other source has.

## Combining Results

Run multiple tools and merge their output for maximum coverage. No single source finds everything.

```bash
# Subfinder
# https://github.com/projectdiscovery/subfinder
# Run all tools
subfinder -d example.com -all -o sub_subfinder.txt
amass enum -d example.com -o sub_amass.txt
assetfinder --subs-only example.com > sub_assetfinder.txt
echo "example.com" | waybackurls | unfurl domains | grep "\.example\.com$" | sort -u > sub_wayback.txt

# Merge and deduplicate
cat sub_*.txt | sort -u > all_subdomains.txt
wc -l all_subdomains.txt
```

### Filtering Dead Subdomains

Passive enumeration returns historical data — some subdomains no longer resolve. Filter with DNS resolution (note: this crosses into active recon since you're querying the target's DNS):

```bash
# httpx-toolkit — check which subdomains are live (active step)
# https://github.com/projectdiscovery/httpx
# sudo apt install httpx-toolkit  (Kali package name — installs as httpx-toolkit binary)
cat all_subdomains.txt | httpx-toolkit -silent -o live_subdomains.txt
```

```bash
# dnsx — resolve subdomains (active step)
# https://github.com/projectdiscovery/dnsx
# sudo apt install dnsx  (if not installed)
cat all_subdomains.txt | dnsx -silent -a -resp -o resolved.txt
```

Mark this step clearly in your methodology as transitioning from passive to active.

## API Key Configuration

Tools produce dramatically more results with API keys configured. Free tiers are sufficient for most engagements.

**Subfinder** — `~/.config/subfinder/provider-config.yaml`:
```yaml
censys:
  - <CENSYS_API_ID>:<CENSYS_API_SECRET>
shodan:
  - <SHODAN_API_KEY>
virustotal:
  - <VT_API_KEY>
securitytrails:
  - <ST_API_KEY>
chaos:
  - <CHAOS_API_KEY>
```

**Amass v5** — `~/.config/amass/config.yaml`:

Amass v5 uses a significantly different configuration format from v3/v4. The config controls data sources, transformations, and scope. Refer to the [Amass GitHub repository](https://github.com/owasp-amass/amass) for the current config.yaml structure. API keys for data sources are configured in the `datasources` section.

## Post-Enumeration

With a deduplicated subdomain list:
- Categorize by function (mail, vpn, dev, staging, api, internal)
- Flag wildcard DNS entries (resolve a random subdomain — if it returns an IP, the domain uses wildcard DNS)
- Check for subdomain takeover potential (subdomains pointing to decommissioned cloud services)
- Feed into active reconnaissance for port scanning and service enumeration

## References

### Official Documentation

- [Subfinder GitHub Repository](https://github.com/projectdiscovery/subfinder)
- [Amass GitHub Repository](https://github.com/owasp-amass/amass)
- [assetfinder GitHub Repository](https://github.com/tomnomnom/assetfinder)
- [waybackurls GitHub Repository](https://github.com/tomnomnom/waybackurls)
- [unfurl GitHub Repository](https://github.com/tomnomnom/unfurl)
- [httpx GitHub Repository](https://github.com/projectdiscovery/httpx)

### OSINT Resources

- [crt.sh — Certificate Transparency Search](https://crt.sh/)
- [VirusTotal](https://www.virustotal.com/)
- [SecurityTrails](https://securitytrails.com/)
- [Rapid7 Project Sonar — Open Data](https://opendata.rapid7.com/)

### MITRE ATT&CK

- [T1596.001 - Search Open Technical Databases: DNS/Passive DNS](https://attack.mitre.org/techniques/T1596/001/)
