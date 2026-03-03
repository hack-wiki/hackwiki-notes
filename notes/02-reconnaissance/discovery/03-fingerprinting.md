% Filename: 02-reconnaissance/discovery/03-fingerprinting.md
% Display name: Step 3 - OS & Service Fingerprinting
% Last update: 2026-02-10
% ATT&CK Tactics: TA0043 (Reconnaissance)
% ATT&CK Techniques: T1595 (Active Scanning)
% Authors: @TristanInSec

# OS & Service Fingerprinting

## Overview

Fingerprinting identifies the exact operating system and service versions running on a target. This determines which exploits apply, which enumeration techniques to use, and what the attack surface looks like. Service version detection reveals the software behind each port; OS fingerprinting reveals the underlying platform.

## ATT&CK Mapping

- **Tactic:** TA0043 - Reconnaissance
- **Technique:** T1595 - Active Scanning

## Prerequisites

- Open ports discovered from port scanning phase
- Root/sudo for OS fingerprinting (requires raw sockets)
- Nmap installed

## Service Version Detection

### Nmap Service Probes

Nmap's `-sV` flag sends protocol-specific probes to open ports and matches responses against its `nmap-service-probes` database.

```bash
# Nmap
# https://nmap.org/
# Standard service version detection
nmap -sV -p <open_ports> <target>

# Increase version detection intensity (0-9, default 7)
nmap -sV --version-intensity 9 -p <open_ports> <target>

# Light version detection (faster, fewer probes)
nmap -sV --version-light -p <open_ports> <target>

# Attempt all probes regardless of port
nmap -sV --version-all -p <open_ports> <target>
```

Expected output:
```text
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http        Apache httpd 2.4.52 ((Ubuntu))
443/tcp  open  ssl/http    nginx 1.18.0
3306/tcp open  mysql       MySQL 8.0.32-0ubuntu0.22.04.2
```

The `VERSION` column is what you need for vulnerability research. Exact version strings can be cross-referenced with CVE databases.

Version intensity controls how many probes Nmap sends. Default 7 is usually sufficient. Increase to 9 for stubborn services that respond to less common probes. Use `--version-light` (intensity 2) for speed when you only need basic service identification.

### Banner Grabbing (Manual)

When Nmap detection fails or you need raw verification, grab banners manually:

```bash
# Netcat banner grab
nc -nv <target> <port>

# Telnet banner grab (works for text-based protocols)
telnet <target> <port>
```

For HTTP:
```bash
curl -sI http://<target>/
```

Expected output:
```text
HTTP/1.1 200 OK
Server: Apache/2.4.52 (Ubuntu)
X-Powered-By: PHP/8.1.2
```

HTTP response headers frequently leak server software, framework versions, and language runtimes. The `Server` and `X-Powered-By` headers are the most common sources.

For SSL/TLS services:
```bash
# OpenSSL
# https://www.openssl.org/
openssl s_client -connect <target>:443 </dev/null 2>/dev/null | grep -E "subject|issuer|Protocol|Cipher"
```

```bash
# OpenSSL
# https://www.openssl.org/
# Extract full certificate details
openssl s_client -connect <target>:443 </dev/null 2>/dev/null | openssl x509 -noout -text | head -30
```

SSL certificates reveal hostnames (Subject CN and SAN), issuer, and validity period. Internal certificates often expose internal domain naming conventions.

### Protocol-Specific Probes

Some services require protocol-aware interactions to extract version information:

```bash
# SSH version (visible in banner)
nc -nv <target> 22

# Expected: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6

# SMTP banner
nc -nv <target> 25

# Expected: 220 mail.example.com ESMTP Postfix (Ubuntu)

# FTP banner
nc -nv <target> 21

# Expected: 220 (vsFTPd 3.0.5)
```

Service banners are Tier 1 reliable — the service itself reports its version. However, administrators can modify banners to mislead.

## OS Fingerprinting

### Nmap OS Detection

Nmap OS fingerprinting analyzes TCP/IP stack behavior (window sizes, TTL values, TCP options, DF bit, ISN patterns) and compares against its `nmap-os-db` database of known OS fingerprints.

```bash
# Nmap
# https://nmap.org/
# OS detection
sudo nmap -O -p <open_ports> <target>

# OS detection with aggressive guess when exact match fails
sudo nmap -O --osscan-guess -p <open_ports> <target>

# Skip OS detection on hosts that lack both an open and closed TCP port
sudo nmap -O --osscan-limit -p <open_ports> <target>
```

Expected output:
```text
OS details: Linux 5.4 - 5.15 (Ubuntu)
Network Distance: 2 hops
```

OS detection requires at least one open **and** one closed (RST-responding) TCP port to work effectively. "Closed" here means actively refusing the connection with RST — filtered ports (no response) do not count. A target with one open port and all others filtered still produces degraded OS detection results.

`--osscan-guess` makes Nmap report its best guess even when confidence is low. This is useful for narrowing the OS family (Linux vs. Windows vs. FreeBSD) when exact versions are ambiguous.

### TTL-Based OS Inference

Different operating systems use characteristic default TTL values. While not definitive (TTL decreases with each hop), it provides a quick hint:

| Default TTL | OS Family |
|-------------|-----------|
| 64 | Linux, macOS, FreeBSD |
| 128 | Windows |
| 255 | Cisco IOS, Solaris |

```bash
ping -c 1 <target> | grep "ttl="
```

A response with `ttl=127` likely traversed one hop from a Windows host (128 - 1). Factor in hop count from `traceroute` for accuracy.

### Combined Discovery and Fingerprinting

The most common real-world Nmap invocation combines service detection, OS fingerprinting, and default scripts:

```bash
# Nmap
# https://nmap.org/
# "Swiss army knife" scan — version + OS + default scripts
sudo nmap -sV -sC -O -p <open_ports> <target> -oA full_fingerprint

# Aggressive scan (enables -sV, -sC, -O, --traceroute)
sudo nmap -A -p <open_ports> <target> -oA aggressive_scan
```

The `-A` flag is shorthand for `-sV -sC -O --traceroute`. Convenient for CTF and lab environments. On real engagements, prefer specifying each flag individually for better control over what runs.

## Web Technology Fingerprinting

Web services warrant additional fingerprinting beyond HTTP headers.

```bash
# whatweb — identifies CMS, frameworks, JavaScript libraries
# https://github.com/urbanadventurer/WhatWeb
whatweb http://<target>/

# Example output:
# http://10.10.10.5/ [200 OK] Apache[2.4.52], Country[RESERVED][ZZ],
# HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)],
# JQuery[3.6.0], PHP[8.1.2], WordPress[6.1.1]
```

```bash
# Wappalyzer CLI — removed from npm, no longer functional
# Use the browser extension or whatweb instead
# https://www.wappalyzer.com/
```

```bash
# Nmap HTTP NSE scripts for technology detection
# Nmap
# https://nmap.org/
nmap -sV -p 80,443 --script http-headers,http-server-header,http-generator <target>
```

### Nmap HTTP Fingerprinting Scripts

```bash
# Nmap
# https://nmap.org/
# Detect web application firewalls
nmap -p 80,443 --script http-waf-detect <target>

# HTTP methods detection (PUT, DELETE, etc.)
nmap -p 80,443 --script http-methods <target>

# SSL/TLS cipher enumeration
nmap -p 443 --script ssl-enum-ciphers <target>
```

## Passive Fingerprinting

Identify OS and services without sending probes by analyzing intercepted traffic.

```bash
# p0f — passive OS fingerprinting from network traffic
# https://github.com/p0f/p0f
sudo p0f -i eth0
```

p0f analyzes TCP SYN packet characteristics (window size, MSS, options order) from traffic passing through the interface. Useful when active scanning is prohibited or when monitoring a SPAN port.

## Practical Workflow

```bash
# Nmap
# https://nmap.org/
# After port scanning identified open ports:
# 1. Service version detection
nmap -sV --version-intensity 7 -p 22,80,443,3306 <target> -oA versions

# 2. OS fingerprinting
sudo nmap -O --osscan-guess -p 22,80,443,3306 <target> -oA os_detect

# 3. Web tech fingerprinting (if HTTP/HTTPS found)
# whatweb
# https://github.com/urbanadventurer/WhatWeb
whatweb http://<target>/

# 4. Manual banner verification for key services
nc -nv <target> 22
curl -sI http://<target>/
```

## References

### Official Documentation

- [Nmap Service and Version Detection](https://nmap.org/book/vscan.html)
- [Nmap OS Detection](https://nmap.org/book/osdetect.html)
- [Nmap Service Probes Database](https://nmap.org/book/vscan-fileformat.html)
- [WhatWeb GitHub Repository](https://github.com/urbanadventurer/WhatWeb)
- [p0f GitHub Repository](https://github.com/p0f/p0f)

### MITRE ATT&CK

- [T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)
