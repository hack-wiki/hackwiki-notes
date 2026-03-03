% Filename: 06-red-teaming/operations/opsec.md
% Display name: Operational Security
% Last update: 2026-02-11
% ATT&CK Tactics: TA0005 (Defense Evasion)
% ATT&CK Techniques: T1036 (Masquerading)
% Authors: @TristanInSec

# Operational Security

## Overview

Operational security (OPSEC) is the discipline of minimizing indicators that reveal red team activity to defenders. Poor OPSEC leads to early detection and blown engagements. Good OPSEC means the red team operates at the same noise level as normal business activity — blending in rather than standing out. OPSEC applies to infrastructure, tooling, network behavior, and host artifacts.

## ATT&CK Mapping

- **Tactic:** TA0005 - Defense Evasion
- **Technique:** T1036 - Masquerading

## Techniques

### Infrastructure OPSEC

```text
Domain selection:
  - Register domains that match the target's industry (not "evil-c2.xyz")
  - Age domains 2+ weeks before use (fresh domains get flagged)
  - Categorize domains via web proxies (Bluecoat, McAfee) as business-related
  - Use separate domains for phishing vs. C2 vs. payload hosting

IP reputation:
  - Use cloud providers the target already trusts (Azure, AWS, GCP)
  - Avoid known-bad IP ranges
  - Use residential proxies for OSINT to avoid IP-based blocking
  - Rotate IPs if one gets burned

SSL/TLS:
  - Use valid certificates (Let's Encrypt or commercial)
  - Self-signed certs are an immediate IOC
  - Match TLS profiles to legitimate traffic (JA3/JA3S fingerprints)
```

### Network OPSEC

```text
C2 traffic:
  - Use HTTPS on port 443 (blends with normal web traffic)
  - Set beacon jitter to 20-50% (avoid perfectly regular intervals)
  - Use long sleep times (60-300 seconds) during passive phases
  - Shorten sleep only when actively working, then reset
  - Route C2 through redirectors — never expose the team server

Traffic patterns:
  - Avoid large data transfers during off-hours
  - Match working hours of the target timezone
  - Use domain fronting or CDN to mask C2 destination
  - DNS C2 should mimic normal DNS query patterns (not 1000 TXT queries/min)

Lateral movement:
  - Use protocols already in the environment (SMB, WinRM, RDP)
  - Avoid tools that create unusual services (PsExec creates PSEXESVC)
  - Prefer WMI or DCOM over PsExec for lower detection footprint
  - Move during business hours when similar traffic is normal
```

### Host OPSEC

```text
Process behavior:
  - Inject into processes that normally make network connections
    (explorer.exe, svchost.exe, browser processes)
  - Avoid spawning cmd.exe or powershell.exe from unusual parents
  - Use direct syscalls to avoid API hooking by EDR
  - Clean up artifacts (event logs, prefetch, MFT entries) where possible

File system:
  - Avoid writing to disk when possible (in-memory execution)
  - If files must be written, use standard locations (C:\Windows\Temp\)
  - Timestomp files to match surrounding directory entries
  - Use filenames that blend in (svchost.exe, update.exe, not beacon.exe)

Authentication:
  - Use stolen credentials, not created accounts
  - Avoid password spraying — generates lockouts and alerts
  - Use Kerberos over NTLM when possible (NTLM triggers more alerts)
  - Limit failed authentication attempts
```

### Tooling OPSEC

```text
Payload preparation:
  - Compile payloads fresh — don't reuse across engagements
  - Strip debug symbols and metadata
  - Test against the target's AV/EDR in a lab before deploying
  - Use unique C2 profiles per engagement
  - Sign binaries if possible (code signing certs)

Indicator management:
  - Track all IOCs generated during the engagement
  - Document every domain, IP, hash, user agent, and file name used
  - This becomes part of the final report for blue team deconfliction
```

### Communication OPSEC

```text
Red team internal:
  - Use encrypted channels for team communication (Signal, private Matrix)
  - Never discuss engagement details on unencrypted channels
  - Store engagement data on encrypted volumes
  - Destroy engagement data per client agreement after reporting

Credential handling:
  - Store captured credentials encrypted
  - Limit who on the team has access to sensitive credentials
  - Never exfiltrate real sensitive data — prove access, screenshot, leave
```

### Common OPSEC Failures

| Failure | Detection Trigger |
|---------|------------------|
| Default Cobalt Strike profile | Known JA3 hash, default URI patterns |
| PsExec for lateral movement | PSEXESVC service creation event |
| cmd.exe spawned from Word | Suspicious parent-child process chain |
| C2 beacon every 60s exactly | Perfect interval = not human traffic |
| Fresh domain registered same week | Domain age reputation check |
| PowerShell with `-enc` flag | Common detection rule trigger |
| Scanning from the beachhead | Port scan alerts from internal host |

## Detection Methods

### How Blue Teams Catch OPSEC Failures

- JA3/JA3S TLS fingerprint matching against known C2 profiles
- Parent-child process relationship analysis
- Beacon interval analysis (regularity detection)
- Domain age and reputation scoring
- User agent anomaly detection
- Unusual authentication patterns (time, source, frequency)

## References

### MITRE ATT&CK

- [T1036 - Masquerading](https://attack.mitre.org/techniques/T1036/)
