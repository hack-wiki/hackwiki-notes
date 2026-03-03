% Filename: 06-red-teaming/operations/campaign-planning.md
% Display name: Campaign Planning
% Last update: 2026-02-11
% ATT&CK Tactics: TA0043 (Reconnaissance)
% ATT&CK Techniques: T1591 (Gather Victim Org Information)
% Authors: @TristanInSec

# Campaign Planning

## Overview

Campaign planning defines the scope, objectives, threat model, and rules of engagement before a red team operation begins. A well-planned campaign aligns the red team's activities with the organization's security goals, ensures legal authorization, and establishes clear communication channels. Planning directly determines whether the engagement produces actionable results or just a list of findings.

## ATT&CK Mapping

- **Tactic:** TA0043 - Reconnaissance
- **Technique:** T1591 - Gather Victim Org Information

## Techniques

### Defining Objectives

Red team objectives should focus on answering security questions, not just "get Domain Admin":

- **Detection testing** — can the SOC detect lateral movement within 4 hours?
- **Response testing** — does the IR team follow their playbook when a C2 beacon is found?
- **Control validation** — can an attacker exfiltrate sensitive data despite DLP controls?
- **Crown jewel access** — can an attacker reach PCI data / source code / executive email?

### Rules of Engagement (RoE)

Document and get signed approval for:

```text
1. Scope
   - In-scope IP ranges, domains, systems
   - Explicitly out-of-scope systems (production databases, medical devices, etc.)
   - Authorized attack types (phishing, physical, network, web)

2. Boundaries
   - No denial-of-service
   - No destructive actions (ransomware simulation without encryption)
   - No access to specific data types (PII, patient records)
   - Working hours restrictions (if any)

3. Authorization
   - Signed authorization letter from executive sponsor
   - Emergency contacts (red team lead, blue team lead, legal)
   - Deconfliction process — how to verify if detected activity is the red team
   - "Get out of jail free" letter for physical engagements

4. Communication
   - Status update frequency
   - Immediate notification triggers (critical vulns, active breach detected)
   - Secure communication channel between red team and stakeholders
```

### Threat Model Selection

Choose an adversary profile to emulate:

| Threat Actor Type | TTPs | Dwell Time | Sophisttic. |
|-------------------|------|------------|-------------|
| Opportunistic criminal | Phishing, commodity malware, ransomware | Days | Low |
| Targeted criminal (FIN groups) | Spear-phishing, custom tools, POS malware | Weeks | Medium |
| Nation-state (APT) | Zero-days, supply chain, custom implants | Months | High |
| Insider threat | Legitimate access, data exfiltration | Ongoing | Varies |

Use MITRE ATT&CK to map the selected threat actor's known TTPs and build your attack plan around them.

### Infrastructure Planning

Before the engagement begins, plan and build:

```text
- C2 framework selection (Sliver, Cobalt Strike, Mythic, Havoc)
- Domain acquisition and categorization (1-2 weeks lead time)
- SSL certificate setup (Let's Encrypt or purchased)
- Redirector deployment (cloud VPS, CDN)
- Payload development and testing
- Communication channels (encrypted chat for the red team)
- Data handling procedures (how captured data is stored/destroyed)
```

### Attack Plan

Structure the operation in phases:

```text
Phase 1: Reconnaissance (Week 1)
  - OSINT on target organization
  - Identify external attack surface
  - Map employee roles for phishing targets

Phase 2: Initial Access (Week 2)
  - Deploy phishing campaign OR exploit external service
  - Establish initial C2 beacon

Phase 3: Post-Exploitation (Weeks 2-3)
  - Enumerate internal environment
  - Escalate privileges
  - Establish persistence
  - Move laterally toward objectives

Phase 4: Actions on Objectives (Weeks 3-4)
  - Access crown jewels
  - Demonstrate data exfiltration
  - Document detection gaps

Phase 5: Reporting (Week 5)
  - Compile timeline of actions
  - Document detection vs. non-detection
  - Deliver findings and recommendations
```

### Deconfliction

Establish a process to confirm whether detected activity belongs to the red team:

```text
- Unique deconfliction code known only to red team lead and designated blue team contact
- Dedicated phone number or encrypted channel
- Red team logs all actions with timestamps for correlation
- Never reveal red team actions to SOC analysts during the engagement
```

## Detection Methods

### How Blue Teams Detect Planning

- Registration of new domains similar to the organization's branding
- SSL certificate transparency logs revealing new attacker domains
- Reconnaissance activity (LinkedIn scraping, job posting enumeration)

## References

### MITRE ATT&CK

- [T1591 - Gather Victim Org Information](https://attack.mitre.org/techniques/T1591/)
