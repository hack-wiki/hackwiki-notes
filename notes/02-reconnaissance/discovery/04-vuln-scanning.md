% Filename: 02-reconnaissance/discovery/04-vuln-scanning.md
% Display name: Step 4 - Vulnerability Scanning
% Last update: 2026-02-10
% ATT&CK Tactics: TA0043 (Reconnaissance)
% ATT&CK Techniques: T1595.002 (Vulnerability Scanning)
% Authors: @TristanInSec

# Vulnerability Scanning

## Overview

Vulnerability scanning automates the detection of known weaknesses in identified services. This is the final discovery phase step — after host discovery, port scanning, and fingerprinting have established what exists, vuln scanning determines what might be exploitable. Results require manual validation; scanners produce false positives.

## ATT&CK Mapping

- **Tactic:** TA0043 - Reconnaissance
- **Technique:** T1595.002 - Vulnerability Scanning

## Prerequisites

- Service versions identified from fingerprinting phase
- Nmap with NSE scripts installed
- Nuclei or dedicated vulnerability scanner (for broader coverage)
- Engagement authorization confirmed (vuln scanning is noisy and detectable)

## Nmap NSE Vulnerability Scripts

Nmap ships with NSE script categories specifically for vulnerability detection.

### Script Categories

```bash
# Nmap
# https://nmap.org/
# Run all vulnerability detection scripts
nmap -sV --script vuln -p <open_ports> <target>

# Run safe scripts (low risk of disruption)
nmap -sV --script "safe and vuln" -p <open_ports> <target>

# Combine vulnerability and exploit scripts
nmap -sV --script "vuln or exploit" -p <open_ports> <target>
```

The `vuln` category includes scripts that check for known CVEs and misconfigurations. The `exploit` category includes scripts that attempt actual exploitation (use with caution — may trigger alerts or cause instability).

### Targeted NSE Scanning

Rather than running all `vuln` scripts, target specific services:

```bash
# Nmap
# https://nmap.org/
# SMB vulnerabilities (EternalBlue, MS17-010, MS08-067)
nmap -sV -p 445 --script smb-vuln-* <target>

# SSL/TLS vulnerabilities (Heartbleed, POODLE, CCS Injection)
nmap -sV -p 443 --script ssl-heartbleed,ssl-poodle,ssl-ccs-injection <target>

# HTTP vulnerabilities (Shellshock, path traversal)
nmap -sV -p 80,443 --script http-vuln-* <target>

# DNS vulnerabilities (zone transfer, cache snooping)
nmap -sV -p 53 --script dns-zone-transfer,dns-cache-snoop <target>
```

### SMB Vulnerability Scanning

SMB vulnerabilities are high-impact targets on internal networks:

```bash
# Nmap
# https://nmap.org/
# Check for MS17-010 (EternalBlue)
nmap -p 445 --script smb-vuln-ms17-010 <target>

# Check for MS08-067 (Conficker)
nmap -p 445 --script smb-vuln-ms08-067 <target>

# Enumerate SMB shares and permissions (not vuln, but feeds into exploitation)
nmap -p 445 --script smb-enum-shares,smb-enum-users <target>

# SMB security mode check (signing, encryption)
nmap -p 445 --script smb-security-mode <target>
```

Expected output for MS17-010:
```text
| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
```

### SSL/TLS Vulnerability Scanning

```bash
# Nmap
# https://nmap.org/
# Heartbleed (CVE-2014-0160)
nmap -p 443 --script ssl-heartbleed <target>

# Enumerate supported ciphers (identify weak ciphers)
nmap -p 443 --script ssl-enum-ciphers <target>

# Check certificate details
nmap -p 443 --script ssl-cert <target>
```

```bash
# SSLyze — dedicated SSL/TLS analysis
# https://github.com/nabla-c0d3/sslyze
sslyze <target>:443
```

```bash
# testssl.sh — comprehensive SSL/TLS testing
# https://github.com/drwetter/testssl.sh
./testssl.sh <target>:443
```

testssl.sh is the most thorough SSL/TLS scanner available — it checks for all known protocol vulnerabilities, cipher weaknesses, and certificate issues in a single run.

## Nuclei

Nuclei is a template-based vulnerability scanner that checks for known CVEs, misconfigurations, default credentials, and exposed panels using a community-maintained template library.

> **Note:** nuclei is not installed on Kali by default. Install with `sudo apt install -y nuclei` or download from [GitHub releases](https://github.com/projectdiscovery/nuclei/releases). Alternatively, install via Go: `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`.

```bash
# Nuclei
# https://github.com/projectdiscovery/nuclei
# Scan with all templates
nuclei -u http://<target>/ -o nuclei_results.txt

# Scan with specific severity levels
nuclei -u http://<target>/ -severity critical,high -o nuclei_critical.txt

# Scan with specific template tags
nuclei -u http://<target>/ -tags cve -o nuclei_cves.txt

# Scan multiple targets from a file
nuclei -l urls.txt -severity critical,high -o nuclei_batch.txt

# Update templates before scanning
nuclei -update-templates
```

### Nuclei Template Categories

```bash
# Nuclei
# https://github.com/projectdiscovery/nuclei
# CVE-specific checks
nuclei -u http://<target>/ -tags cve

# Default credential checks
nuclei -u http://<target>/ -tags default-login

# Exposed panels and admin interfaces
nuclei -u http://<target>/ -tags panel

# Technology-specific templates
nuclei -u http://<target>/ -tags wordpress
nuclei -u http://<target>/ -tags apache
nuclei -u http://<target>/ -tags nginx
```

Always run `nuclei -update-templates` before scanning to get the latest vulnerability checks. New CVE templates are typically added within days of public disclosure.

### Nuclei Considerations

Nuclei sends HTTP requests that may trigger WAF rules or rate limiting. For production environments:

```bash
# Nuclei
# https://github.com/projectdiscovery/nuclei
# Rate-limited scan
nuclei -u http://<target>/ -rate-limit 50 -severity critical,high

# Use specific headers (e.g., authorization)
nuclei -u http://<target>/ -H "Authorization: Bearer <token>"
```

## Dedicated Vulnerability Scanners

Nmap NSE and Nuclei are effective for targeted checks, but dedicated vulnerability scanners provide broader coverage with maintained vulnerability databases, compliance checks, authenticated scanning, and reporting engines. These tools are essential for thorough assessments.

### OpenVAS / Greenbone (Open Source)

OpenVAS (Open Vulnerability Assessment Scanner) is the open-source vulnerability scanner maintained by Greenbone Networks. It uses the Greenbone Community Feed — a continuously updated database of Network Vulnerability Tests (NVTs). Management is done through the Greenbone Security Assistant (GSA) web interface.

```bash
# OpenVAS / Greenbone Vulnerability Management (GVM)
# https://greenbone.github.io/docs/latest/
# Install on Kali Linux
sudo apt install gvm
sudo gvm-setup

# Start GVM services
sudo gvm-start

# Access web interface
# Default: https://localhost:9392
# Credentials are shown after gvm-setup completes
```

```bash
# OpenVAS / Greenbone Vulnerability Management (GVM)
# https://greenbone.github.io/docs/latest/
# Check GVM service status
sudo gvm-check-setup

# Update vulnerability feed (NVTs)
sudo greenbone-feed-sync
```

**Scan workflow via GSA web interface:**

1. **Create a Target** — define IP addresses or ranges and optional credentials for authenticated scanning
2. **Select a Scan Configuration** — choose from built-in profiles:
   - *Full and fast* — recommended default; runs all NVTs with optimized timing
   - *Full and very deep* — thorough scan; slower but checks more edge cases
   - *Full and very deep ultimate* — most comprehensive; may cause service disruption
3. **Create a Task** — combine target + scan configuration + schedule
4. **Launch and monitor** — results populate in real time with severity ratings (CVSS)
5. **Export reports** — PDF, CSV, XML, or TXT formats for documentation

**Authenticated scanning** significantly improves accuracy. OpenVAS supports SSH credentials (Linux), SMB credentials (Windows), and SNMP community strings for deeper inspection of installed packages, patch levels, and local configurations.

**Limitations:** The Greenbone Community Feed updates less frequently than commercial feeds. Some checks available in the Greenbone Enterprise Feed (paid) are not included. For critical infrastructure assessments, consider supplementing with commercial tools.

### Nessus (Commercial)

[Nessus](https://www.tenable.com/products/nessus) by Tenable is the industry standard for vulnerability assessment. It provides the largest commercial vulnerability database, authenticated and unauthenticated scanning, compliance auditing (PCI DSS, CIS benchmarks, HIPAA), and detailed remediation guidance. Configuration and scan management is done through its web interface (default: `https://localhost:8834`).

**Key scan types:** Host Discovery, Basic Network Scan, Advanced Scan (fully customizable), Credentialed Patch Audit, Web Application Tests, Malware Scan.

**Editions:**
- *Nessus Essentials* — free permanently, limited to 16 IPs (no time limit; verify current terms at tenable.com)
- *Nessus Essentials Plus* — low-cost annual license, 20 IPs, real-time plugin updates
- *Nessus Professional* — full-featured for individual consultants and pentesters
- *Tenable.io / Tenable.sc* — enterprise platform with asset management and dashboards

### Other Commercial Scanners

Several other commercial vulnerability management platforms are widely used in enterprise environments:

- **[Rapid7 InsightVM / Nexpose](https://www.rapid7.com/products/insightvm/)** — real-time vulnerability management with live dashboards, agent-based and agentless scanning, and native integration with Metasploit for validation. InsightVM is the cloud-hosted version; Nexpose is the on-premises deployment.
- **[Qualys VMDR](https://www.qualys.com/apps/vulnerability-management-detection-response/)** — cloud-native platform with a massive vulnerability knowledgebase, continuous monitoring, asset inventory, and TruRisk scoring for prioritization.
- **[Acunetix](https://www.acunetix.com/)** — web application vulnerability scanner with strong coverage for OWASP Top 10, DAST scanning, and API security testing. Focused on web targets rather than network-wide assessment.
- **[Burp Suite Professional](https://portswigger.net/burp/pro)** — while primarily a web application testing proxy, its active scanner is one of the best for detecting web vulnerabilities including injection, XSS, and authentication flaws.

**When to use which:** OpenVAS or Nessus Essentials/Essentials Plus for lab and self-study. Nessus Professional for client engagements. Enterprise platforms (InsightVM, Qualys, Tenable.io) for organizations managing vulnerability programs at scale. Acunetix and Burp Suite for web application-focused assessments.

## Practical Scanning Workflow

```bash
# Phase 1: Quick NSE vuln scan on all identified services
# Nmap
# https://nmap.org/
nmap -sV --script vuln -p <all_open_ports> <target> -oA vuln_nse

# Phase 2: Targeted checks on high-value services
nmap -p 445 --script smb-vuln-* <target> -oA vuln_smb
nmap -p 443 --script ssl-heartbleed,ssl-enum-ciphers <target> -oA vuln_ssl

# Phase 3: Nuclei for web services
# Nuclei
# https://github.com/projectdiscovery/nuclei
nuclei -u http://<target>/ -severity critical,high -o nuclei_results.txt

# Phase 4: Review and validate
# All scanner results require manual validation before reporting
```

## Result Validation

Scanner output is a starting point, not a final answer. Before adding a vulnerability to your report:

1. Confirm the service version matches the vulnerable range
2. Check if the vulnerability applies to the specific configuration (e.g., some CVEs only affect certain modules or features)
3. Attempt manual verification where safe to do so
4. Check for compensating controls (WAF, network segmentation, patching)
5. Cross-reference with multiple sources (NVD, vendor advisory, Exploit-DB)

False positives in vulnerability reports waste client time and damage credibility. A shorter, validated findings list is more valuable than a raw scanner dump.

## References

### Official Documentation

- [Nmap NSE Script Documentation](https://nmap.org/nsedoc/)
- [Nmap NSE vuln Category Scripts](https://nmap.org/nsedoc/categories/vuln.html)
- [Nuclei GitHub Repository](https://github.com/projectdiscovery/nuclei)
- [Nuclei Templates Repository](https://github.com/projectdiscovery/nuclei-templates)
- [testssl.sh GitHub Repository](https://github.com/drwetter/testssl.sh)
- [SSLyze GitHub Repository](https://github.com/nabla-c0d3/sslyze)

### Vulnerability Scanners

- [OpenVAS / Greenbone Documentation](https://greenbone.github.io/docs/latest/)
- [Nessus by Tenable](https://www.tenable.com/products/nessus)
- [Rapid7 InsightVM](https://www.rapid7.com/products/insightvm/)
- [Qualys VMDR](https://www.qualys.com/apps/vulnerability-management-detection-response/)
- [Acunetix](https://www.acunetix.com/)
- [Burp Suite Professional](https://portswigger.net/burp/pro)

### CVE References

- [CVE-2017-0143 - MS17-010 EternalBlue](https://nvd.nist.gov/vuln/detail/CVE-2017-0143)
- [CVE-2014-0160 - Heartbleed](https://nvd.nist.gov/vuln/detail/CVE-2014-0160)
- [CVE-2008-4250 - MS08-067](https://nvd.nist.gov/vuln/detail/CVE-2008-4250)

### MITRE ATT&CK

- [T1595.002 - Vulnerability Scanning](https://attack.mitre.org/techniques/T1595/002/)
