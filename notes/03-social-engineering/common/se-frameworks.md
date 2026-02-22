% Filename: 03-social-engineering/common/se-frameworks.md
% Display name: SE Frameworks & Lifecycle
% Last update: 2026-02-11
% ATT&CK Tactics: TA0001 (Initial Access), TA0043 (Reconnaissance)
% ATT&CK Techniques: T1566 (Phishing), T1598 (Phishing for Information)
% Authors: @TristanInSec

# SE Frameworks & Lifecycle

## Overview

Social engineering attacks follow predictable lifecycles regardless of the
specific vector (phishing, vishing, physical). Understanding these models
helps pentesters design realistic campaigns and helps defenders recognize
attack patterns at each phase.

## Rules of Engagement for SE Testing

> **Before any social engineering test:** Ensure the following are documented
> in the signed rules of engagement (RoE):

- **Explicit SE authorization** — general pentest scope does not cover SE
- **Target list or targeting criteria** — who can and cannot be targeted
- **Allowable pretexts** — what scenarios are approved (e.g., IT helpdesk, vendor)
- **Prohibited actions** — threats, intimidation, emotional manipulation, targeting executives' families
- **Payload restrictions** — no destructive payloads, no real malware
- **Data handling** — how captured credentials and PII will be stored and destroyed
- **Physical SE boundaries** — which facilities, which hours, what to do if confronted
- **Emergency contacts** — client-side POC reachable during testing
- **Employee welfare** — SE tests should evaluate defenses, not humiliate individuals
- **Reporting** — findings reported at organizational level, not naming individuals

## The Social Engineering Attack Cycle

The Social-Engineer.org Framework defines a four-phase attack cycle:

### Phase 1 — Information Gathering

Collect intelligence about the target organization and individuals. Sources
include company websites, social media, job postings, press releases, and
public records. The goal is identifying attack vectors, key personnel, and
organizational processes that can be exploited.

### Phase 2 — Establish Rapport

Build a relationship or create a believable pretext. The attacker develops
trust with the target, either through brief interactions (a single phone call)
or extended engagement (weeks of email correspondence). Pretexts must match
the attacker's knowledge level and the target's expectations.

### Phase 3 — Exploitation

Use gathered information and established trust to achieve an objective —
extracting credentials, gaining physical access, or convincing the target to
execute a payload. Effective exploitation feels natural to the target and does
not trigger suspicion.

### Phase 4 — Execution

Complete the objective and exit without alerting the target. In penetration
testing, this means documenting what was achieved, preserving evidence, and
reporting to the client. The exit strategy is as important as the entry.

The cycle is iterative — complex engagements may repeat phases multiple times
to escalate access or move laterally within an organization.

## ATT&CK Mapping

MITRE ATT&CK maps social engineering across multiple tactics:

### Reconnaissance (TA0043)

| Technique | ID | Description |
|---|---|---|
| Phishing for Information | T1598 | Gathering intelligence via phishing (not access) |
| Spearphishing Service | T1598.001 | Info gathering via third-party platforms |
| Spearphishing Attachment | T1598.002 | Deceptive attachments to harvest information |
| Spearphishing Link | T1598.003 | Links to fake pages to harvest credentials |
| Spearphishing Voice | T1598.004 | Voice-based phishing to collect information |

### Initial Access (TA0001)

| Technique | ID | Description |
|---|---|---|
| Phishing | T1566 | Delivering malicious content via electronic messages |
| Spearphishing Attachment | T1566.001 | Malicious file attachments |
| Spearphishing Link | T1566.002 | Malicious URLs to specific targets |
| Spearphishing via Service | T1566.003 | Phishing via social media or messaging platforms |
| Spearphishing Voice | T1566.004 | Voice phishing including callback phishing |
| Trusted Relationship | T1199 | Exploiting established business relationships |

### Execution (TA0002)

| Technique | ID | Description |
|---|---|---|
| User Execution | T1204 | Relying on user action to run malicious content |
| Malicious Link | T1204.001 | Tricking users into clicking harmful links |
| Malicious File | T1204.002 | Tricking users into opening dangerous files |

### Lateral Movement (TA0008)

| Technique | ID | Description |
|---|---|---|
| Internal Spearphishing | T1534 | Using compromised internal accounts to phish other users |

## Legal Framework

Social engineering testing operates under the same legal framework as
technical penetration testing, with additional considerations:

- **Written authorization** must explicitly cover social engineering methods
- **Privacy laws** vary by jurisdiction — recording phone calls may require
  two-party consent depending on the state or country
- **Employee rights** — in some jurisdictions, employers must inform employees
  that SE testing may occur (without specifying when or how)
- **Data protection** — captured credentials and PII must be handled according
  to applicable regulations (GDPR, CCPA, etc.)
- **Physical access laws** — unauthorized building entry can trigger criminal
  trespass charges even during authorized tests if documentation is inadequate

The Penetration Testing Execution Standard (PTES) addresses social engineering
in pre-engagement scoping: pretexts must be approved in writing before testing
begins, with regional legal considerations documented.

## Ethical Boundaries

Even with authorization, SE testers should observe ethical limits:

- **No emotional manipulation** — avoid pretexts involving personal tragedy, family emergencies, or threats
- **No targeting of personal accounts** — only test corporate/work-related channels
- **Proportional pressure** — if a target becomes visibly distressed, disengage
- **Organizational reporting** — report findings at department/team level, not against specific individuals
- **Data minimization** — capture only what is needed to prove the finding; destroy unnecessary data promptly

## References

### Frameworks

- [Social-Engineer.org Framework — Attack Vectors](https://www.social-engineer.org/framework/attack-vectors/)
- [Social-Engineer.org Framework — Attack Cycle](https://www.social-engineer.org/framework/attack-vectors/attack-cycle/)
- [PTES — Pre-engagement Interactions](https://pentest-standard.readthedocs.io/en/latest/preengagement_interactions.html)

### MITRE ATT&CK

- [T1566 — Phishing](https://attack.mitre.org/techniques/T1566/)
- [T1598 — Phishing for Information](https://attack.mitre.org/techniques/T1598/)
- [T1199 — Trusted Relationship](https://attack.mitre.org/techniques/T1199/)
- [T1204 — User Execution](https://attack.mitre.org/techniques/T1204/)
- [T1534 — Internal Spearphishing](https://attack.mitre.org/techniques/T1534/)

### Standards

- [NIST SP 800-61r3 — Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
