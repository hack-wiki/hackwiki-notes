% Filename: 02-reconnaissance/passive/overview.md
% Display name: Passive Reconnaissance
% Last update: 2026-02-10
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# Passive Reconnaissance

## Overview

Passive reconnaissance gathers information about a target without directly interacting with its infrastructure. No packets are sent to target systems, no login attempts are made, and no scanning occurs. All data is collected from publicly available sources — search engines, DNS records, certificate transparency logs, archived documents, and third-party databases.

This makes passive recon undetectable by the target. There are no firewall logs, no IDS alerts, and no web server access entries to reveal the reconnaissance activity. It is the first phase of any engagement and often yields enough information to shape the entire attack surface before a single probe is sent.

Passive recon is not optional. Skipping it and jumping straight to active scanning wastes time on targets that public data would have already mapped, and misses attack surface that scanners cannot find (employee emails, leaked credentials, forgotten subdomains, internal hostnames in metadata).

## Topics in This Section

- [OSINT Techniques](osint.md) — People, organization, and infrastructure intelligence from open sources
- [Google Dorking](google-dorking.md) — Search engine operators for exposing indexed sensitive content
- [Subdomain Enumeration](subdomain-enum.md) — Passive subdomain discovery via aggregators and scraping
- [Certificate Transparency](certificate-transparency.md) — Extracting subdomains and infrastructure from CT logs
- [Passive DNS](dns-passive.md) — Historical DNS resolution data from third-party databases
- [Metadata Extraction](metadata.md) — Harvesting author names, software versions, and internal paths from public documents and images

## General Approach

A typical passive recon workflow:

1. **Define scope** — confirm target domains, IP ranges, and subsidiaries that are in-scope for the engagement
2. **OSINT collection** — identify people, email formats, organizational structure, technology stack from public sources
3. **Subdomain discovery** — enumerate subdomains via CT logs, passive DNS, search engines, and aggregator APIs
4. **Google dorking** — search for exposed files, login portals, error messages, and misconfigurations indexed by search engines
5. **Metadata harvesting** — download public documents (PDFs, DOCX, XLSX) and extract embedded metadata (usernames, software, internal paths)
6. **Consolidate and deduplicate** — merge findings into a unified target profile before transitioning to active reconnaissance

Each technique feeds the next. Subdomains discovered via CT logs get checked in passive DNS for historical IPs. Metadata usernames become targets for OSINT. Google dorks confirm whether discovered assets are publicly exposed.

## Key Principles

**Leave no trace.** Passive recon should generate zero log entries on target systems. If a technique requires sending packets to the target (DNS queries to their authoritative servers, HTTP requests to their web servers), it crosses into active recon and should be logged as such in your methodology.

**Combine sources.** No single tool or technique finds everything. CT logs miss domains without HTTPS. Passive DNS misses recently registered domains. Google misses pages blocked by robots.txt. Running all techniques against the same target produces dramatically more coverage than relying on one.

**Verify scope before acting.** Passive recon frequently discovers infrastructure the client did not explicitly list — subsidiaries, acquired companies, shadow IT. Confirm with the client whether these assets are in scope before proceeding to active reconnaissance against them.

**Document everything.** Record which sources produced each finding. Engagement reports require evidence trails, and clients need to know whether a subdomain was discovered through a CT log, a Google dork, or a leaked document.

## Tools Overview

Most passive recon tools are covered in detail within the `02-reconnaissance/tools/` folder. The key tools referenced across this section include: theHarvester, Subfinder, Amass, assetfinder, Recon-ng, SpiderFoot, ExifTool, and metagoofil. API keys for services like Shodan, Censys, SecurityTrails, and VirusTotal significantly increase the volume of results — configure them before starting an engagement.
