% Filename: 12-defensive/incident-response/01-preparation.md
% Display name: Step 1 - Preparation
% Last update: 2026-02-11
% Authors: @TristanInSec

# IR Preparation

## Overview

Preparation is the most important phase of incident response. Organizations
that invest in preparation respond faster, contain threats more effectively,
and recover with less damage. Preparation includes building an IR team,
developing playbooks, establishing communication plans, deploying monitoring
tools, and conducting regular exercises.

## IR Team Structure

```text
Core IR team roles:

IR Manager / Incident Commander:
  - Leads the response, makes escalation decisions
  - Coordinates across teams, manages communications
  - Ensures documentation and chain of custody

Triage Analyst:
  - First responder for alerts and initial assessment
  - Determines severity, scope, and whether to escalate

Forensic Analyst:
  - Collects and analyzes evidence (disk, memory, network)
  - Preserves chain of custody for legal proceedings
  - Identifies indicators of compromise (IOCs)

Threat Intelligence Analyst:
  - Attributes the attack, identifies the threat actor
  - Provides context on TTPs and known campaigns
  - Shares IOCs with the community (if appropriate)

Communications Lead:
  - Internal notifications (management, legal, HR)
  - External communications (customers, regulators, media)
  - Coordinates with law enforcement if required

Supporting roles (on-call):
  - System administrators (for containment and recovery)
  - Network engineers (for network isolation)
  - Legal counsel (for regulatory and liability guidance)
  - HR (for insider threat incidents)
```

## IR Playbooks

```text
A playbook documents the step-by-step process for responding to a
specific incident type. Each playbook should include:

1. Trigger conditions — what activates this playbook
2. Severity classification — how to determine priority
3. Initial response steps — first 30 minutes
4. Investigation steps — what evidence to collect
5. Containment actions — how to stop the spread
6. Eradication steps — how to remove the threat
7. Recovery steps — how to restore normal operations
8. Communication templates — pre-written notifications
9. Escalation criteria — when to involve management/legal/law enforcement

Common playbooks:
  - Malware infection
  - Ransomware
  - Phishing / credential compromise
  - Data breach / exfiltration
  - Insider threat
  - DDoS attack
  - Web application compromise
  - Unauthorized access
```

## Communication Plan

```text
Internal communication:

Severity levels:
  SEV-1 (Critical): Active data breach, ransomware, or widespread compromise
    → Notify: CISO, CIO, legal, executive team
    → Timeline: Within 1 hour of confirmation
  SEV-2 (High): Confirmed compromise with limited scope
    → Notify: CISO, IT management, affected teams
    → Timeline: Within 4 hours
  SEV-3 (Medium): Suspicious activity under investigation
    → Notify: Security team lead
    → Timeline: Within 24 hours
  SEV-4 (Low): Minor policy violation or false positive
    → Notify: Logged, reviewed in weekly meeting

Communication channels:
  - Out-of-band communication (assume normal channels are compromised)
  - Dedicated phone bridge or encrypted messaging (Signal, etc.)
  - Do NOT discuss incident details via email if email is compromised

External communication:
  - Legal counsel reviews all external communications
  - Regulatory notification timelines (GDPR: 72 hours, HIPAA: 60 days)
  - Law enforcement notification criteria
  - Customer notification templates
```

## IR Toolkit

```text
Jump bag / IR toolkit (pre-staged):

Evidence collection:
  - Write-blocker (hardware or software)
  - External drives (sanitized, encrypted)
  - RAM acquisition tools (LiME, WinPmem, DumpIt)
  - Disk imaging tools (dd, dc3dd, FTK Imager)
  - Chain of custody forms

Analysis tools:
  - Live CD/USB with forensic tools (SIFT, Kali)
  - Volatility (memory analysis)
  - The Sleuth Kit (disk analysis)
  - Wireshark / tshark (network analysis)
  - YARA rules (malware detection)

Network tools:
  - Portable network tap
  - Managed switch (for mirroring)
  - Network cables
  - tcpdump / tshark

Documentation:
  - Incident response forms
  - Chain of custody forms
  - Evidence labels and bags
  - Camera (for photographing physical evidence)
  - Notebooks and pens
```

## Exercises and Testing

```text
Exercise types:

Tabletop exercise:
  - Discussion-based walkthrough of a scenario
  - No actual technical response
  - Tests decision-making and communication
  - Frequency: Quarterly

Technical exercise:
  - Simulated attack in a test environment
  - Team performs actual triage, containment, and analysis
  - Tests tooling and technical procedures
  - Frequency: Semi-annually

Full-scale exercise:
  - Realistic simulation involving multiple teams
  - Includes communications, legal, management
  - Tests entire IR process end-to-end
  - Frequency: Annually

Purple team exercise:
  - Red team executes known TTPs
  - Blue team detects and responds in real time
  - Measures detection coverage and response time
  - Frequency: As needed
```

## References

### Further Reading

- [NIST SP 800-61: Computer Security Incident Handling Guide](https://csrc.nist.gov/pubs/sp/800/61/r2/final)
- [SANS Incident Response Process](https://www.sans.org/white-papers/33901/)
