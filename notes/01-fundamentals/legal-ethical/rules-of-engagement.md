% Filename: 01-fundamentals/legal-ethical/rules-of-engagement.md
% Display name: Rules of Engagement
% Last update: 2026-02-11
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# Rules of Engagement

## Overview

Rules of Engagement (RoE) define the technical and operational boundaries of a penetration test. They specify what can be tested, when, how, and what actions require prior approval. The RoE protects both the tester (from exceeding authorization) and the client (from unacceptable disruption). Every engagement must have agreed-upon RoE before any technical activity begins.

## Key Concepts

### Purpose of Rules of Engagement

The RoE translates the legal authorization and business requirements into concrete operational boundaries. Without clear RoE, testers risk:

- Testing systems outside the authorized scope
- Disrupting production services during business hours
- Triggering incident response unnecessarily
- Using techniques that violate the client's risk tolerance
- Causing data loss or corruption without a recovery plan

### RoE Components

### Scope Definition

The scope defines exactly which assets are authorized for testing.

**In-scope assets must be explicitly listed:**

```text
Category          Examples
----------------  ------------------------------------------
Network ranges    10.10.10.0/24, 172.16.0.0/16
Domains           example.com, *.staging.example.com
Applications      https://app.example.com, internal ERP
IP addresses      Specific host IPs for targeted testing
Physical sites    Building A (3rd floor server room)
Personnel         Specific departments for social engineering
Cloud accounts    AWS account 123456789012
Wireless          SSIDs: CorpWiFi, GuestWiFi
```

**Out-of-scope must also be explicit:**

```text
Category          Examples                        Reason
----------------  ----------------------------    -------------------------
Production DB     db-prod.internal                Business continuity risk
Third-party SaaS  salesforce.com, office365.com   Not owned by client
Partner systems   partner-api.example.com         Separate legal entity
Network segments  10.10.20.0/24                   Finance department excluded
Specific hosts    10.10.10.1 (core router)        Stability critical
```

### Testing Windows

Define when testing can occur to minimize business impact.

```text
Category              Window                        Approval
--------------------  ----------------------------  -----------------
Network scanning      Business hours OK             Pre-approved
Exploitation          After hours: 18:00-06:00      Pre-approved
Denial of service     Never / by specific approval  Requires signoff
Social engineering    Business hours only            Pre-approved
Physical access       Coordinated with security      Case-by-case
Production systems    Maintenance windows only       Case-by-case
```

### Authorized Techniques

Different engagements authorize different techniques. The RoE must clearly state what is and is not allowed.

```text
Technique                   Typical RoE Status
--------------------------  -------------------------------------------
Port scanning               Usually allowed
Vulnerability scanning      Usually allowed (may exclude aggressive scans)
Manual exploitation         Allowed with scope restrictions
Automated exploitation      Often restricted or requires approval
Password attacks            Allowed with lockout awareness
Social engineering          Must be explicitly authorized per technique
Phishing                    Requires separate authorization and target list
Physical access testing     Requires separate authorization
Denial of service           Almost always prohibited
Data exfiltration (proof)   Limited volume, no real sensitive data
Pivoting to new systems     May require notification before proceeding
Wireless testing            Must be explicitly authorized
```

### Communication Plan

How the tester communicates with the client during the engagement.

**Essential contacts:**

```text
Role                    Contact              Purpose
----------------------  -------------------  ---------------------------
Primary contact         Name, phone, email   Day-to-day coordination
Technical lead          Name, phone, email   Scope questions, access issues
Emergency contact       Name, phone (24/7)   Critical findings, incidents
Incident response       IR team lead         If testing triggers IR
Executive sponsor       Name, email          Escalation if needed
```

**Communication triggers — when to contact the client immediately:**

- Critical vulnerability discovered (RCE, active breach, data exposure)
- System instability or crash caused by testing
- Evidence of prior compromise (real attacker already present)
- Testing accidentally impacts out-of-scope systems
- Discovery of illegal content
- Scope boundary uncertainty

**Communication channels:**

```text
Sensitivity         Channel                     Use For
-----------------   -------------------------   -------------------------
Low                 Email                       Status updates, logistics
Medium              Encrypted email (PGP/S/MIME) Finding summaries
High                Phone call                  Critical findings, incidents
Findings delivery   Encrypted file transfer     Reports, evidence
```

### Evidence Handling

Rules for how test evidence and client data are managed.

**During the engagement:**
- Store all evidence on encrypted storage
- Do not exfiltrate real client data (PII, financial data, credentials) — screenshot or hash instead
- If real data is inadvertently captured, notify the client and delete it per their instructions
- Maintain chain of custody for all evidence

**After the engagement:**
- Deliver all evidence to the client
- Delete client data from tester systems per the agreed retention policy
- Typical retention: 30-90 days after final report delivery
- Securely wipe testing VMs, notes, and captured data

### Engagement Types and RoE Differences

Different engagement types require different RoE constraints:

### Black Box

Tester receives minimal information (company name, target scope). Simulates an external attacker with no insider knowledge.

```text
Provided:     Target scope (IPs/domains), authorization letter
Not provided: Network diagrams, credentials, source code
RoE notes:    Full recon phase included; OSINT authorized;
              social engineering may be in scope
```

### Gray Box

Tester receives partial information (credentials, network diagrams, API documentation). Simulates an attacker with some insider access.

```text
Provided:     Target scope, low-privilege credentials, basic architecture docs
Not provided: Admin credentials, source code
RoE notes:    Skip basic recon; focus on authenticated testing;
              test privilege escalation paths
```

### White Box

Tester receives full information (source code, admin credentials, architecture documentation). Maximizes test coverage in limited time.

```text
Provided:     Full access — credentials, source code, network diagrams
Not provided: Nothing withheld
RoE notes:    Focus on depth over breadth; source code review included;
              test all privilege levels
```

### Red Team

Simulates a real-world adversary with minimal restrictions. Goal is to test detection and response capabilities, not just find vulnerabilities.

```text
Provided:     Objective (e.g., "access CEO email", "exfiltrate customer DB")
Not provided: Most internal details (adversary simulation)
RoE notes:    Social engineering, physical access, phishing typically authorized;
              only the executive sponsor and a small trusted group know;
              blue team is NOT informed (tests detection capability)
```

### Deconfliction

Deconfliction prevents the penetration test from being mistaken for a real attack. The tester's activities may trigger security alerts, and the incident response team needs a way to distinguish testing from genuine threats — without the blue team knowing the test is happening (in red team scenarios).

```text
Approach          Method                           When to Use
----------------  -------------------------------  ----------------------
Trusted agent     One person on the blue team       Red team engagements
                  can verify "is this our test?"
IP whitelisting   Tester IPs provided to SOC        Standard pentests
                  (for awareness, not exclusion)
Code word         Shared phrase to identify tester   Physical engagements
                  if confronted by internal staff
Get-out-of-jail   Signed authorization letter tester  Physical/social eng.
letter (GOJ)      carries at all times — required     engagements; if law
                  for law enforcement encounters       enforcement is called
Timestamping      Tester logs all actions with       All engagements
                  timestamps for correlation
```

## Practical Examples

### RoE Document Template

```text
=== RULES OF ENGAGEMENT ===

Engagement: [Client Name] Penetration Test
Date: YYYY-MM-DD
Version: 1.0

1. SCOPE
   In-scope:  [list networks, domains, applications]
   Out-of-scope: [list exclusions]

2. TESTING WINDOWS
   Network scanning: [hours]
   Exploitation: [hours]
   Social engineering: [hours]
   Prohibited times: [blackout dates]

3. AUTHORIZED TECHNIQUES
   [List of authorized and prohibited techniques]

4. COMMUNICATION
   Primary contact: [name, phone, email]
   Emergency contact: [name, phone]
   Critical finding notification: [process]
   Status updates: [frequency and channel]

5. EVIDENCE HANDLING
   Storage: [encrypted, location]
   Retention: [days after report delivery]
   Deletion: [secure wipe method]

6. DECONFLICTION
   Tester source IPs: [list]
   Trusted agent: [name, contact]
   Code word: [phrase]

7. STOP CONDITIONS
   [What triggers an immediate halt to testing]

8. SIGNATURES
   Tester: _________________ Date: _________
   Client: _________________ Date: _________
```

### Stop Conditions

Define when the tester must immediately pause and contact the client:

```text
Condition                                   Action
------------------------------------------  -------------------------
Production system becomes unresponsive       Stop, notify, assist recovery
Evidence of active compromise by real        Stop, notify emergency contact
  attacker discovered
Testing accidentally impacts out-of-scope    Stop, notify, document
  systems
Illegal content discovered                   Stop, notify, preserve evidence
Client requests immediate halt               Stop all activity
Lockout threshold reached on shared          Stop password attacks
  accounts
```

## References

### Standards and Frameworks

- [NIST SP 800-115 — Technical Guide to Information Security Testing and Assessment](https://csrc.nist.gov/pubs/sp/800/115/final)
- [Penetration Testing Execution Standard (PTES)](https://pentest-standard.readthedocs.io/en/latest/)
- [ISO/IEC 27001 — Information Security Management](https://www.iso.org/standard/75281.html)
- [PCI DSS Document Library](https://www.pcisecuritystandards.org/document_library/)

### Legislation

- [18 U.S.C. § 1030 — Computer Fraud and Abuse Act (CFAA)](https://www.law.cornell.edu/uscode/text/18/1030)
