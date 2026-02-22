% Filename: 02-reconnaissance/enum-web/overview.md
% Display name: Web Enumeration
% Last update: 2026-02-09
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# Web Enumeration

## Overview

Web services are the most common attack surface in penetration testing. HTTP/HTTPS enumeration targets technology identification, directory and file discovery, virtual host enumeration, CMS detection, and TLS configuration analysis. Thorough web enumeration frequently reveals the initial foothold — exposed admin panels, backup files, WebDAV write access, or misconfigured authentication.

## Topics in This Section

- [HTTP Enumeration](http.md) — Banner grabbing, directory brute-forcing, CMS detection, nikto, gobuster, feroxbuster, ffuf
- [HTTPS / TLS Enumeration](https-tls.md) — Certificate inspection, cipher suite analysis, protocol testing, sslscan, sslyze
- [WebDAV Enumeration](webdav.md) — File upload testing, davtest, cadaver, PROPFIND/PUT/MOVE operations
- [WebSocket Enumeration](websocket.md) — WebSocket detection, message interception, websocat, Burp Suite

## General Approach

1. **Service detection** — Nmap version scan to identify web server software and version
2. **Technology fingerprinting** — whatweb, wafw00f to identify CMS, frameworks, WAFs
3. **TLS analysis** — Certificate SANs for additional hostnames, cipher/protocol checks
4. **Content discovery** — Directory/file brute-forcing with multiple wordlists and tools
5. **Virtual host enumeration** — Discover additional sites hosted on the same server
6. **CMS enumeration** — wpscan for WordPress, specialized tools for Drupal/Joomla
7. **Application scanning** — nikto for misconfigurations and known vulnerabilities
8. **Manual review** — robots.txt, source code, JavaScript files, API endpoints

For web application attack techniques (injection, XSS, file inclusion, etc.), see `04-web-testing/`.
