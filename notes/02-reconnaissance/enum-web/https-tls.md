% Filename: 02-reconnaissance/enum-web/https-tls.md
% Display name: HTTPS / TLS Enumeration
% Last update: 2026-02-19
% ATT&CK Tactics: TA0043 (Reconnaissance)
% ATT&CK Techniques: T1595 (Active Scanning)
% Authors: @TristanInSec

# HTTPS / TLS Enumeration

## Overview

HTTPS (TCP 443) wraps HTTP in TLS encryption. TLS enumeration targets certificate details (domains, expiry, issuer), supported cipher suites, protocol versions, and known vulnerabilities (Heartbleed, POODLE, ROBOT). Certificate Subject Alternative Names (SANs) frequently reveal additional hostnames and subdomains. Weak TLS configurations remain common in enterprise environments, especially on legacy systems.

## ATT&CK Mapping

- **Tactic:** TA0043 - Reconnaissance
- **Technique:** T1595 - Active Scanning

## Prerequisites

- Network access to target TCP 443 (or other TLS-wrapped ports)
- Tools: sslscan, sslyze, testssl.sh, Nmap, or OpenSSL

## Enumeration Techniques

### Certificate Inspection

```bash
# OpenSSL — view certificate details
# -servername sets SNI; required on virtual-hosted servers to get the right certificate
openssl s_client -connect <target>:443 -servername <target> </dev/null 2>/dev/null | openssl x509 -noout -text

# Extract Subject Alternative Names (SANs)
openssl s_client -connect <target>:443 -servername <target> </dev/null 2>/dev/null | openssl x509 -noout -ext subjectAltName

# Certificate dates (expiry check)
openssl s_client -connect <target>:443 -servername <target> </dev/null 2>/dev/null | openssl x509 -noout -dates

# Certificate chain
openssl s_client -connect <target>:443 -servername <target> -showcerts </dev/null 2>/dev/null
```

SANs are critical — they often reveal internal hostnames, additional subdomains, and wildcard patterns that expand the attack surface.

### sslscan

```bash
# sslscan
# https://github.com/rbsec/sslscan
sslscan <target>

# Specific port
sslscan <target>:8443

# Show certificate details
sslscan --show-certificate <target>
```

sslscan tests all supported SSL/TLS protocol versions, cipher suites, and certificate details. It highlights weak ciphers, expired certificates, and known vulnerabilities with color-coded output.

### sslyze

```bash
# sslyze
# https://github.com/nabla-c0d3/sslyze
sslyze <target>

# Full scan with Mozilla intermediate config check
sslyze --mozilla_config intermediate <target>

# Check for specific vulnerabilities
sslyze --heartbleed --openssl_ccs --robot <target>

# JSON output
sslyze --json_out results.json <target>
```

sslyze provides detailed TLS configuration analysis including cipher suite ordering, certificate validation, and vulnerability checks.

### testssl.sh

```bash
# testssl.sh
# https://github.com/drwetter/testssl.sh
# Not on Kali by default — install from source:
git clone https://github.com/drwetter/testssl.sh.git
cd testssl.sh

./testssl.sh <target>

# Quick check (skip some tests)
./testssl.sh --fast <target>

# Specific checks
./testssl.sh --vulnerable <target>
./testssl.sh --headers <target>
./testssl.sh --protocols <target>

# HTML report
./testssl.sh --htmlfile report.html <target>
```

testssl.sh is a comprehensive TLS testing tool that runs entirely from bash. It tests protocols, cipher suites, server preferences, header configuration, and all known TLS vulnerabilities.

### Nmap TLS NSE Scripts

```bash
# Nmap
# https://nmap.org/

# Cipher suite enumeration
nmap -p 443 --script ssl-enum-ciphers <target>

# Certificate details
nmap -p 443 --script ssl-cert <target>

# Server time from TLS handshake
nmap -p 443 --script ssl-date <target>

# Vulnerability checks
nmap -p 443 --script ssl-heartbleed <target>
nmap -p 443 --script ssl-poodle <target>

# Combined scan
nmap -p 443 --script ssl-enum-ciphers,ssl-cert,ssl-heartbleed,ssl-poodle <target>
```

### Protocol Version Testing

Manually test which TLS/SSL versions are accepted:

```bash
# Test specific protocol versions (include -servername to avoid virtual-host mismatches)
openssl s_client -connect <target>:443 -servername <target> -tls1
openssl s_client -connect <target>:443 -servername <target> -tls1_1
openssl s_client -connect <target>:443 -servername <target> -tls1_2
openssl s_client -connect <target>:443 -servername <target> -tls1_3
```

A connection that succeeds indicates the server accepts that protocol version. SSLv2 and SSLv3 are considered broken. TLS 1.0 and 1.1 are deprecated. TLS 1.2 and 1.3 are current standards.

### Key Vulnerabilities to Check

| Vulnerability | Impact | NSE Script / Tool |
|---------------|--------|-------------------|
| Heartbleed (CVE-2014-0160) | Memory disclosure from OpenSSL | `ssl-heartbleed` / sslscan |
| POODLE (CVE-2014-3566) | SSLv3 padding oracle | `ssl-poodle` / sslyze |
| ROBOT | RSA decryption oracle | sslyze `--robot` |
| CRIME | TLS compression side-channel | sslscan (compression check) |
| BREACH | HTTP body compression side-channel (distinct from CRIME; different mitigation) | testssl.sh |
| BEAST (CVE-2011-3389) | CBC IV predictability (SSL 3.0 / TLS 1.0) | testssl.sh |
| DROWN (CVE-2016-0800) | SSLv2 cross-protocol attack — can affect servers with SSLv2 disabled if the RSA key is shared with a server that has SSLv2 enabled | testssl.sh |
| Weak ciphers | NULL, EXPORT, RC4, DES | `ssl-enum-ciphers` / sslscan |
| Self-signed certificate | No trusted CA verification | `ssl-cert` / openssl |

## Post-Enumeration

With TLS enumeration results, prioritize:
- SANs from certificates — enumerate each discovered hostname separately
- Wildcard certificates — attempt to discover additional subdomains
- Weak ciphers or protocols — note for reporting, may enable downgrade attacks
- Expired or self-signed certificates — may indicate test/dev environments with weaker security
- Certificate issuer — internal CA certificates suggest internal infrastructure
- Mismatched CN/SAN — may reveal original hostname behind a CDN or proxy

## References

### Official Documentation

- [Nmap ssl-enum-ciphers NSE Script](https://nmap.org/nsedoc/scripts/ssl-enum-ciphers.html)
- [Nmap ssl-cert NSE Script](https://nmap.org/nsedoc/scripts/ssl-cert.html)
- [Nmap ssl-heartbleed NSE Script](https://nmap.org/nsedoc/scripts/ssl-heartbleed.html)
- [Nmap ssl-poodle NSE Script](https://nmap.org/nsedoc/scripts/ssl-poodle.html)
- [sslscan](https://github.com/rbsec/sslscan)
- [sslyze](https://github.com/nabla-c0d3/sslyze)
- [testssl.sh](https://github.com/drwetter/testssl.sh)
- [RFC 8446 - TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446)

### Pentest Guides & Tutorials

- [sslyze: Audits SSL/TLS Configurations (awjunaid.com)](https://awjunaid.com/kali-linux/sslyze-audits-ssl-tls-configurations/)

### CVE References

- [CVE-2014-0160 - Heartbleed (OpenSSL Memory Disclosure)](https://nvd.nist.gov/vuln/detail/CVE-2014-0160)
- [CVE-2014-3566 - POODLE (SSLv3 Padding Oracle)](https://nvd.nist.gov/vuln/detail/CVE-2014-3566)

### MITRE ATT&CK

- [T1595 - Active Scanning](https://attack.mitre.org/techniques/T1595/)
