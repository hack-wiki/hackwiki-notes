% Filename: 02-reconnaissance/enum-web/http.md
% Display name: HTTP Enumeration
% Last update: 2026-02-10
% ATT&CK Tactics: TA0043 (Reconnaissance)
% ATT&CK Techniques: T1595.003 (Wordlist Scanning)
% Authors: @TristanInSec

# HTTP Enumeration

## Overview

HTTP (TCP 80) and HTTPS (TCP 443) are the most common attack surface in any engagement. Web enumeration targets technology identification, directory/file discovery, virtual host enumeration, CMS detection, and misconfiguration hunting. Thorough HTTP enumeration often reveals the initial foothold — exposed admin panels, backup files, version info leaks, or default credentials.

## ATT&CK Mapping

- **Tactic:** TA0043 - Reconnaissance
- **Technique:** T1595.003 - Wordlist Scanning

## Prerequisites

- Network access to target TCP 80/443
- Tools: curl, Nmap, nikto, gobuster/feroxbuster/ffuf, whatweb
- Wordlists: SecLists (`/usr/share/seclists/`) recommended

## Enumeration Techniques

### Service Detection

```bash
# Nmap
# https://nmap.org/
nmap -sV -p 80,443 <target>

# Full HTTP script scan
nmap -sV -p 80,443 --script=http-enum,http-headers,http-methods,http-title <target>
```

### HTTP Response Analysis

Inspect headers, redirects, and server banners manually:

```bash
# Grab banner and headers
curl -I http://<target>

# Full response with headers
curl -i http://<target>

# Follow redirects and show headers
curl -i -L http://<target>

# View rendered page as text
curl http://<target> -s -L | html2text -width '99' | uniq

# Check robots.txt
curl http://<target>/robots.txt -s | html2text

# Check common files
curl -s http://<target>/sitemap.xml
curl -s http://<target>/.well-known/security.txt
curl -s http://<target>/README.md
curl -s http://<target>/CHANGELOG.md
```

Key headers to note:

| Header | Reveals |
|--------|---------|
| Server | Web server software and version |
| X-Powered-By | Backend language/framework (PHP, ASP.NET, Express) |
| X-AspNet-Version | Exact .NET version |
| Set-Cookie | Session management, httponly/secure flags |
| X-Frame-Options | Clickjacking protection status |
| Content-Security-Policy | CSP configuration |
| WWW-Authenticate | Authentication scheme (Basic, NTLM, Kerberos) |

### Technology Fingerprinting

```bash
# whatweb
# https://github.com/urbanadventurer/WhatWeb
whatweb http://<target>

# Aggressive mode (more requests, more info)
whatweb -a 3 http://<target>

# Multiple targets
whatweb -i targets.txt
```

WhatWeb identifies CMS, web frameworks, JavaScript libraries, server software, and analytics tools from HTTP responses.

```bash
# wafw00f (WAF detection)
# https://github.com/EnableSecurity/wafw00f
wafw00f http://<target>

# Test all WAF signatures
wafw00f -a http://<target>
```

### Nmap HTTP NSE Scripts

```bash
# Nmap
# https://nmap.org/

# Technology and content enumeration
nmap -p 80,443 --script http-enum <target>
nmap -p 80,443 --script http-headers <target>
nmap -p 80,443 --script http-methods --script-args http-methods.url-path='/' <target>
nmap -p 80,443 --script http-title <target>
nmap -p 80,443 --script http-server-header <target>
nmap -p 80,443 --script http-robots.txt <target>

# Security checks
nmap -p 80,443 --script http-cookie-flags <target>
nmap -p 80,443 --script http-cors <target>
nmap -p 80,443 --script http-auth,http-auth-finder <target>

# Discovery
nmap -p 80,443 --script http-backup-finder <target>
nmap -p 80,443 --script http-config-backup <target>
nmap -p 80,443 --script http-git <target>
nmap -p 80,443 --script http-sitemap-generator <target>
nmap -p 80,443 --script http-default-accounts <target>

# Vulnerability checks
nmap -p 80,443 --script http-shellshock --script-args uri=/cgi-bin/admin.cgi <target>
nmap -p 80,443 --script http-php-version <target>
```

### Web Application Scanning

```bash
# nikto
# https://github.com/sullo/nikto
nikto -host http://<target>

# With specific port
nikto -host http://<target> -port 8080

# Scan HTTPS
nikto -host https://<target> -ssl

# Save output
nikto -host http://<target> -output nikto_results.txt
```

Nikto checks for server misconfigurations, default files, outdated software, and known vulnerabilities. It is noisy — not suitable for stealth engagements.

### Directory and File Brute-Forcing

Core technique for discovering hidden content. Use multiple tools with different wordlists for thorough coverage.

**Common wordlists on Kali:**

| Wordlist | Path |
|----------|------|
| SecLists common | `/usr/share/seclists/Discovery/Web-Content/common.txt` |
| SecLists directory-list-2.3 medium | `/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt` |
| SecLists raft-medium | `/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt` |
| SecLists CGIs | `/usr/share/seclists/Discovery/Web-Content/CGIs.txt` |
| DirB common | `/usr/share/dirb/wordlists/common.txt` |
| wfuzz general | `/usr/share/wfuzz/wordlist/general/common.txt` |

```bash
# gobuster (directory mode)
# https://github.com/OJ/gobuster
gobuster dir -u http://<target>/ -w /usr/share/seclists/Discovery/Web-Content/common.txt
gobuster dir -u http://<target>/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,html,txt -t 50

# Filter by status codes (whitelist)
# -b '' clears the default 404 blacklist so -s whitelist takes effect (blacklist overrides whitelist when set)
gobuster dir -u http://<target>/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -s '200,204,301,302,307,403' -b ''
```

> **Note:** feroxbuster is not installed on Kali by default. Install with `sudo apt install -y feroxbuster` or download from [GitHub](https://github.com/epi052/feroxbuster).

```bash
# feroxbuster (recursive by default, faster)
# https://github.com/epi052/feroxbuster
feroxbuster -u http://<target>/ -w /usr/share/seclists/Discovery/Web-Content/common.txt

# With extensions and thread control
feroxbuster -u http://<target>/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,html,txt,bak -t 50

# Filter by status code (each code requires a separate -C flag)
feroxbuster -u http://<target>/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -C 404 -C 403
```

```bash
# ffuf (fast, flexible)
# https://github.com/ffuf/ffuf
ffuf -u http://<target>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt

# With extensions
ffuf -u http://<target>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -e .php,.html,.txt,.bak

# Filter by response size (useful against custom 404 pages)
ffuf -u http://<target>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -fs 4242

# Filter by status code
ffuf -u http://<target>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -fc 404,403
```

```bash
# wfuzz
# https://github.com/xmendez/wfuzz
wfuzz -c -z file,/usr/share/wfuzz/wordlist/general/common.txt --hc 404 http://<target>/FUZZ

# With proxy
wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/common.txt -p 127.0.0.1:8080 --hc 404 http://<target>/FUZZ

# Slow scan (rate limiting)
wfuzz -c -w /usr/share/wfuzz/wordlist/general/common.txt -t 1 -s 1 --hc 404 http://<target>/FUZZ
```

```bash
# dirb (classic, simple)
# https://dirb.sourceforge.net/
dirb http://<target>/ /usr/share/dirb/wordlists/common.txt
```

### Virtual Host Discovery

Enumerate subdomains served by the same web server via Host header manipulation:

```bash
# gobuster (vhost mode)
# https://github.com/OJ/gobuster
gobuster vhost -u http://<target>/ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain

# ffuf (vhost fuzzing)
# https://github.com/ffuf/ffuf
ffuf -u http://<target>/ -H "Host: FUZZ.<domain>" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs <baseline_size>
```

For ffuf vhost discovery, first measure the baseline response size for a non-existent host, then use `-fs` to filter it out.

### CMS Detection and Enumeration

```bash
# wpscan (WordPress)
# https://github.com/wpscanteam/wpscan
wpscan --url http://<target>/ -e vp,vt,u

# Aggressive plugin detection
wpscan --url http://<target>/ -e ap --plugins-detection aggressive

# With API token (for vulnerability data)
wpscan --url http://<target>/ -e vp,vt,u --api-token <YOUR_TOKEN>
```

WordPress NSE scripts:

```bash
# Nmap
# https://nmap.org/
nmap -p 80,443 --script http-wordpress-enum <target>
nmap -p 80,443 --script http-wordpress-brute <target>
nmap -p 80,443 --script http-wordpress-users <target>
```

Manual WordPress checks:

```bash
# Version detection
curl -s http://<target>/readme.html
curl -s http://<target>/wp-links-opml.php
curl -s http://<target>/license.txt

# User enumeration
curl -s http://<target>/?author=1
curl -s http://<target>/wp-json/wp/v2/users

# Plugin/theme detection
curl -s http://<target>/wp-content/plugins/
curl -s http://<target>/wp-content/themes/
```

### Parameter Discovery

Hidden or undocumented GET/POST parameters can expose debug interfaces, admin functionality, or bypass input validation. Parameter discovery fuzzes the target with common parameter names and detects which ones change the response.

```bash
# Arjun
# https://github.com/s0md3v/Arjun
# Discover GET parameters
arjun -u http://<target>/page

# Discover POST parameters
arjun -u http://<target>/page -m POST

# Discover JSON body parameters
arjun -u http://<target>/api/endpoint -m JSON

# Use a custom wordlist
arjun -u http://<target>/page -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt

# Rate-limited scan with delay
arjun -u http://<target>/page -d 1 --rate-limit 10

# Passive parameter collection (Wayback Machine, CommonCrawl, OTX)
arjun -u http://<target>/page --passive

# Output to file
arjun -u http://<target>/page -oT params.txt
arjun -u http://<target>/page -o params.json
```

```bash
# ffuf
# https://github.com/ffuf/ffuf
# GET parameter fuzzing — detect parameters that change the response
ffuf -u "http://<target>/page?FUZZ=test" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -fs <baseline_size>

# POST parameter fuzzing
ffuf -u http://<target>/page \
  -X POST -d "FUZZ=test" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -fs <baseline_size>
```

For ffuf parameter fuzzing, first measure the baseline response size without any extra parameters, then use `-fs` to filter it out. Parameters that produce a different response size are likely valid.

### Metasploit Modules

```bash
# Metasploit
# https://www.metasploit.com/
# Directory scanner
auxiliary/scanner/http/dir_scanner

# File scanner
auxiliary/scanner/http/files_dir

# HTTP version detection
auxiliary/scanner/http/http_version

# HTTP login testing
auxiliary/scanner/http/http_login

# WordPress scanner
auxiliary/scanner/http/wordpress_scanner

# Tomcat manager login
auxiliary/scanner/http/tomcat_mgr_login

# Apache Struts (CVE-2017-5638)
exploit/multi/http/struts2_content_type_ognl
```

## Post-Enumeration

With HTTP enumeration results, prioritize:
- Admin panels or management interfaces — test default credentials
- Exposed version info — search for known CVEs
- Directory listings — look for backup files (.bak, .old, .zip), source code, configs
- robots.txt disallowed paths — often contain sensitive directories
- .git or .svn directories — source code disclosure via `git-dumper` or manual extraction
- Authentication pages — test for SQLi, brute-force, default credentials
- File upload functionality — test for unrestricted upload vulnerabilities
- API endpoints — check for unauthenticated access, IDOR, verbose errors
- Virtual hosts discovered — enumerate each separately

## References

### Official Documentation

- [Nmap http-enum NSE Script](https://nmap.org/nsedoc/scripts/http-enum.html)
- [Nmap http-methods NSE Script](https://nmap.org/nsedoc/scripts/http-methods.html)
- [Nmap http-robots.txt NSE Script](https://nmap.org/nsedoc/scripts/http-robots.txt.html)
- [Nmap http-shellshock NSE Script](https://nmap.org/nsedoc/scripts/http-shellshock.html)
- [WhatWeb](https://github.com/urbanadventurer/WhatWeb)
- [wafw00f](https://github.com/EnableSecurity/wafw00f)
- [Nikto](https://github.com/sullo/nikto)
- [Gobuster](https://github.com/OJ/gobuster)
- [Feroxbuster](https://github.com/epi052/feroxbuster)
- [ffuf](https://github.com/ffuf/ffuf)
- [wfuzz](https://github.com/xmendez/wfuzz)
- [WPScan](https://github.com/wpscanteam/wpscan)
- [SecLists](https://github.com/danielmiessler/SecLists)

### MITRE ATT&CK

- [T1595.003 - Active Scanning: Wordlist Scanning](https://attack.mitre.org/techniques/T1595/003/)
