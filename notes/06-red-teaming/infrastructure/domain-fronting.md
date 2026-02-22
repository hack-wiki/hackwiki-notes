% Filename: 06-red-teaming/infrastructure/domain-fronting.md
% Display name: Domain Fronting
% Last update: 2026-02-11
% ATT&CK Tactics: TA0011 (Command and Control)
% ATT&CK Techniques: T1090.004 (Proxy: Domain Fronting)
% Authors: @TristanInSec

# Domain Fronting

## Overview

Domain fronting hides C2 traffic behind high-reputation domains (e.g., cdn.microsoft.com, cloudfront.net) by exploiting the difference between the DNS hostname and the HTTP Host header. The TLS SNI shows a legitimate domain, but the HTTP Host header inside the encrypted tunnel points to the attacker's origin. Network monitoring sees traffic to a trusted CDN — not the C2 server. Many CDN providers have since blocked this technique, but variations still work.

## ATT&CK Mapping

- **Tactic:** TA0011 - Command and Control
- **Technique:** T1090.004 - Proxy: Domain Fronting

## Prerequisites

- CDN provider that hosts both the attacker's origin and a high-reputation domain
- C2 framework that supports custom Host headers

## Techniques

### How Domain Fronting Works

```text
1. Attacker registers an origin server on a CDN (e.g., AWS CloudFront)
   CDN distribution: d1234.cloudfront.net → attacker's team server

2. Beacon on the target makes HTTPS request:
   DNS/TLS SNI: d9999.cloudfront.net  (legitimate CloudFront domain, same CDN)
   HTTP Host:   d1234.cloudfront.net   (attacker's CDN distribution)

   NOTE: Both domains must be on the SAME CDN provider. The front domain
   (in SNI) must also be a CloudFront-hosted domain — a domain from a
   different CDN (e.g., cdn.microsoft.com on Azure CDN) will NOT work with
   a CloudFront distribution.

3. The CDN edge node receives the request:
   - TLS terminates, sees Host: d1234.cloudfront.net
   - Routes to the attacker's origin server

4. Network monitoring sees:
   - DNS query for d9999.cloudfront.net  ← looks like CloudFront traffic
   - HTTPS traffic to CloudFront IP range ← looks legitimate
   - Cannot see Host header (encrypted inside TLS)
```

### AWS CloudFront (Historically Common)

```text
Setup:
1. Create CloudFront distribution pointing to team server
2. Note the CloudFront domain: d1234.cloudfront.net
3. Find a high-reputation domain also on CloudFront
   (e.g., some *.amazonaws.com or customer domains)
4. Configure C2 beacon:
   - Connect to: <high-reputation-domain>
   - Host header: d1234.cloudfront.net

Note: AWS has implemented mitigations against domain fronting.
CloudFront now validates that the Host header matches the
distribution's configured domain names.
```

### Azure CDN

```text
Azure CDN has been used for domain fronting through
azureedge.net distributions. Similar concept:

1. Create Azure CDN profile with custom origin
2. Find legitimate azureedge.net domain
3. Route traffic through the legitimate domain
   while Host header points to attacker's CDN endpoint

Note: Microsoft has implemented restrictions on this as well.
```

### Current State and Alternatives

Domain fronting has become harder as CDN providers enforce Host header validation. Alternatives that achieve similar goals:

```text
Domain borrowing:
  - Use expired or hijacked subdomains on high-reputation domains
  - CNAME takeover of cloud resources (S3 buckets, Azure apps)

Redirector through CDN:
  - Register a CDN distribution with your domain
  - Traffic appears to go to legitimate CDN IP ranges
  - Not true "fronting" but still leverages CDN reputation

Cloud function routing:
  - Deploy a serverless function (AWS Lambda, Azure Function)
  - Function acts as a proxy to the team server
  - Traffic goes to cloud provider APIs (trusted)

Legitimate cloud services:
  - C2 over Microsoft Graph API (OneDrive, Teams)
  - C2 over Google APIs (Gmail, Drive)
  - C2 over Slack/Discord webhooks
  - These use legitimate HTTPS to trusted domains
```

### C2 Configuration for Domain Fronting

Most C2 frameworks support custom Host headers:

```text
Cobalt Strike (Malleable C2 profile):
  http-get {
    set uri "/api/update";
    client {
      header "Host" "d1234.cloudfront.net";
    }
  }

Sliver:
  Use --http-host flag for HTTP C2

General pattern:
  The beacon connects to the fronted domain
  but sets Host header to the attacker's CDN endpoint
```

## Detection Methods

### Network-Based Detection

- Mismatch between TLS SNI and HTTP Host header (requires SSL inspection)
- High volume of HTTPS traffic to CDN endpoints that don't match normal business usage
- Unusual CDN traffic patterns (regular interval, consistent payload sizes)

### Host-Based Detection

- Processes making HTTPS connections to CDN domains with custom Host headers
- curl or PowerShell with explicit Host header manipulation

## Mitigation Strategies

- **SSL/TLS inspection** — decrypt outbound HTTPS to detect Host header mismatches
- **CDN allowlisting** — only allow traffic to specific CDN distributions your organization uses
- **Cloud proxy (CASB)** — inspect and control traffic to cloud services
- **JA3 fingerprinting** — detect C2 TLS client fingerprints even through CDN

## References

### MITRE ATT&CK

- [T1090.004 - Proxy: Domain Fronting](https://attack.mitre.org/techniques/T1090/004/)
