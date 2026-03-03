% Filename: 01-fundamentals/mitre-attack/tactics.md
% Display name: ATT&CK Tactics
% Last update: 2026-02-10
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# ATT&CK Tactics

## Overview

Tactics represent the adversary's tactical objective — the "why" behind an action. Each tactic answers a question: Why is the adversary doing this? To gain initial access. To escalate privileges. To move laterally. To exfiltrate data.

The MITRE ATT&CK Enterprise matrix organizes 14 tactics in a rough left-to-right attack progression, from pre-compromise reconnaissance through post-exploitation impact. Adversaries do not follow them sequentially — they loop, skip, and revisit tactics as needed. The ordering reflects a general operational flow, not a rigid kill chain.

## Key Concepts

### The 14 Enterprise Tactics

Each tactic has a unique ID (TA-prefix) and contains multiple techniques that achieve the tactical objective.

### TA0043 — Reconnaissance

The adversary gathers information about the target before attacking. This includes identifying target infrastructure, employees, technologies, and vulnerabilities through passive and active means.

Examples: OSINT gathering, port scanning, social media research, DNS enumeration, job posting analysis.

### TA0042 — Resource Development

The adversary acquires or builds resources to support operations. This happens before initial access and includes infrastructure setup, tool development, and capability procurement.

Examples: registering domains for phishing, purchasing VPS infrastructure, developing custom malware, compromising third-party accounts, obtaining code signing certificates.

### TA0001 — Initial Access

The adversary gains a foothold in the target environment. This is the first point of entry — the transition from external to internal.

Examples: spearphishing attachments, exploiting public-facing applications, supply chain compromise, valid account usage, drive-by compromise.

### TA0002 — Execution

The adversary runs malicious code on the target system. Execution is often combined with other tactics — the adversary needs to execute something to establish persistence, escalate privileges, or move laterally.

Examples: PowerShell, command-line interface, Windows Management Instrumentation (WMI), scheduled tasks, user execution of malicious files.

### TA0003 — Persistence

The adversary maintains access across restarts, credential changes, and other disruptions. Persistence mechanisms survive system reboots and ensure the adversary can return.

Examples: registry run keys, scheduled tasks, creating local accounts, modifying startup scripts, implanting web shells, DLL hijacking.

### TA0004 — Privilege Escalation

The adversary gains higher-level permissions. Escalation typically moves from standard user to administrator/root, or from local admin to domain admin.

Examples: exploiting SUID binaries, kernel exploits, token manipulation, abusing sudo misconfigurations, exploiting vulnerable services, leveraging group policy.

### TA0005 — Defense Evasion

The adversary avoids detection throughout the operation. Evasion techniques operate alongside other tactics — the adversary evades detection while persisting, escalating, and moving laterally.

Examples: obfuscating scripts, disabling security tools, clearing logs, timestomping files, process injection, masquerading as legitimate processes, using living-off-the-land binaries (LOLBins).

### TA0006 — Credential Access

The adversary steals credentials — passwords, hashes, tokens, tickets. Credentials enable lateral movement and privilege escalation without exploiting vulnerabilities.

Examples: dumping LSASS memory, Kerberoasting, brute-force attacks, keylogging, extracting credentials from configuration files, password spraying.

### TA0007 — Discovery

The adversary explores the environment to understand what they have access to and what is reachable. Discovery maps the internal landscape — accounts, systems, network topology, security controls, and data locations.

Examples: network share enumeration, account discovery, system information gathering, group policy discovery, domain trust enumeration.

### TA0008 — Lateral Movement

The adversary moves through the environment to reach additional systems. Lateral movement uses stolen credentials, exploitation, or legitimate remote access tools to pivot between hosts.

Examples: pass-the-hash, pass-the-ticket, remote desktop (RDP), SMB/Windows Admin Shares, SSH hijacking, WinRM.

### TA0009 — Collection

The adversary gathers data of interest from target systems. Collection focuses on identifying and staging data before exfiltration — documents, emails, databases, credentials, and intellectual property.

Examples: data from local drives, screenshots, keylogging, email collection, data from network shared drives, clipboard data, data from information repositories.

### TA0011 — Command and Control (C2)

The adversary communicates with compromised systems to control them remotely. C2 channels must blend into normal traffic to avoid detection.

Examples: HTTPS beacons, DNS tunneling, web service C2 (using legitimate platforms like Slack or GitHub), encrypted channels, domain fronting, protocol tunneling.

### TA0010 — Exfiltration

The adversary steals data from the target environment. Exfiltration moves collected data out of the network through various channels, often with compression or encryption to avoid DLP systems.

Examples: exfiltration over C2 channel, exfiltration over alternative protocol, exfiltration to cloud storage, scheduled transfers, physical medium exfiltration.

### TA0040 — Impact

The adversary disrupts, degrades, or destroys systems and data. Impact techniques achieve the adversary's final objective when destruction or disruption — rather than data theft — is the goal.

Examples: data encryption for ransomware, data destruction, defacement, denial of service, resource hijacking (cryptomining), account access removal.

### Tactic Ordering

The matrix flows left-to-right in a general operational sequence:

```text
Reconnaissance → Resource Development → Initial Access → Execution →
Persistence → Privilege Escalation → Defense Evasion → Credential Access →
Discovery → Lateral Movement → Collection → C2 → Exfiltration → Impact
```

Key points about ordering:
- **Reconnaissance** and **Resource Development** happen before any target interaction (pre-compromise)
- **Defense Evasion** applies throughout the entire operation, not just at one point
- **Exfiltration** and **Impact** are often the adversary's final objectives, but not always — some operations focus purely on long-term access (espionage)
- Adversaries loop back frequently — discovery leads to lateral movement, which leads to more discovery

### ATT&CK Beyond Enterprise

ATT&CK covers multiple technology domains:

| Matrix | Scope |
|--------|-------|
| Enterprise | Windows, Linux, macOS, cloud (Azure AD, AWS, GCP, etc.), network, containers |
| Mobile | Android and iOS |
| ICS | Industrial Control Systems |

The Enterprise matrix is the most widely used. Each matrix has its own set of tactics and techniques tailored to the platform.

## Practical Examples

### Mapping a Simple Attack to Tactics

A typical web application compromise maps across multiple tactics:

| Step | Action | Tactic |
|------|--------|--------|
| 1 | Scan target for open ports and services | TA0043 — Reconnaissance |
| 2 | Exploit vulnerable web application | TA0001 — Initial Access |
| 3 | Execute reverse shell | TA0002 — Execution |
| 4 | Enumerate local system and users | TA0007 — Discovery |
| 5 | Find SUID binary and escalate to root | TA0004 — Privilege Escalation |
| 6 | Install SSH key for persistence | TA0003 — Persistence |
| 7 | Dump /etc/shadow and crack hashes | TA0006 — Credential Access |
| 8 | SSH to internal database server | TA0008 — Lateral Movement |
| 9 | Export customer database | TA0009 — Collection |
| 10 | Transfer data out via HTTPS | TA0010 — Exfiltration |

### Using Tactic IDs in Reports

When writing pentest reports, tag every finding with its ATT&CK tactic and technique:

```text
Finding: SQL Injection in /api/login endpoint
ATT&CK Mapping:
  - Tactic: TA0001 (Initial Access)
  - Technique: T1190 (Exploit Public-Facing Application)
```

This allows defenders to map your findings directly to their detection matrix and prioritize remediation.

## References

### Official Documentation

- [MITRE ATT&CK Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
- [MITRE ATT&CK Tactics Overview](https://attack.mitre.org/tactics/enterprise/)
- [MITRE ATT&CK Getting Started](https://attack.mitre.org/resources/getting-started/)
