% Filename: 01-fundamentals/legal-ethical/authorization.md
% Display name: Authorization and Legal Framework
% Last update: 2026-02-11
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# Authorization and Legal Framework

## Overview

Authorization is the legal foundation of all security testing. Without explicit written permission, penetration testing is indistinguishable from criminal hacking under the law. This applies regardless of intent — "I was just testing" is not a legal defense. Every engagement must have documented authorization before any technical work begins. Understanding the legal landscape protects both the tester and the organization.

## Key Concepts

### Written Authorization

A penetration test requires explicit written permission from the asset owner before any scanning, enumeration, or exploitation occurs. Verbal agreements are insufficient — they provide no legal protection if disputes arise.

**What written authorization must include:**
- Identity of the authorizing party (name, title, organization)
- Confirmation they have authority to authorize testing of the target systems
- Scope of authorized activities (networks, systems, applications)
- Timeframe for testing (start date, end date, testing windows)
- Types of testing permitted (network, web application, social engineering, physical)
- Any restrictions or exclusions (production systems, specific IPs, denial of service)
- Emergency contact information
- Signatures from both parties with dates

**Common authorization documents:**
- **Statement of Work (SOW)** — defines the engagement scope, deliverables, timeline, and cost
- **Master Services Agreement (MSA)** — overarching legal contract between parties
- **Rules of Engagement (RoE)** — technical boundaries and operational constraints
- **Authorization Letter / Permission to Test** — explicit written consent from the asset owner
- **Non-Disclosure Agreement (NDA)** — protects confidential information discovered during testing

### Who Can Authorize Testing

Not everyone in an organization has the authority to authorize penetration testing. Testing assets without proper authorization from the correct authority is still unauthorized access.

```text
Authority Level        Can Authorize                    Cannot Authorize
--------------------   ------------------------------   -------------------------
Asset Owner            Their own systems/networks       Third-party hosted assets
CISO / CTO             Organization's infrastructure    Cloud provider infrastructure
Department Head        Their department's systems       Other departments' assets
Cloud Tenant Admin     Tenant-level resources           Cloud provider's platform
Bug Bounty Program     Explicitly listed scope          Out-of-scope assets
```

**Third-party considerations:**
- Cloud-hosted assets (AWS, Azure, GCP) — the customer can authorize testing of their tenant, but must comply with the cloud provider's penetration testing policy
- Managed service providers — both the MSP and the end client may need to authorize
- Shared hosting — testing one tenant's application must not impact others
- Parent/subsidiary companies — each legal entity may require separate authorization

### Key Legislation

Laws governing unauthorized computer access vary by jurisdiction. Penalties range from fines to imprisonment.

### United States — Computer Fraud and Abuse Act (CFAA)

The primary US federal law (18 U.S.C. § 1030) criminalizing unauthorized access to computer systems.

**Key provisions:**
- Accessing a computer without authorization or exceeding authorized access
- Obtaining information from protected computers (any computer connected to the internet)
- Causing damage through unauthorized access (including denial of service)
- Trafficking in passwords or access credentials

**Penalties (vary significantly by subsection):**
- Basic unauthorized access (§1030(a)(2), no aggravating factors): up to 1 year
- Unauthorized access for financial gain or to commit another crime: up to 5 years
- National security violations (§1030(a)(1)): up to 10 years
- Causing serious bodily injury: up to 20 years
- Civil liability for damages caused

**What this means for pentesters:**
- Written authorization is the dividing line between legal testing and a federal crime
- Exceeding the scope of authorization (testing systems not listed in the agreement) is still a CFAA violation
- Even well-intentioned testing without authorization can result in prosecution

### United Kingdom — Computer Misuse Act (CMA) 1990

**Key offenses:**
- Section 1: Unauthorized access to computer material (up to 2 years)
- Section 2: Unauthorized access with intent to commit further offenses (up to 5 years)
- Section 3: Unauthorized acts impairing computer operation (up to 10 years)
- Section 3ZA: Unauthorized acts causing serious damage (up to 14 years; up to life imprisonment where the act causes or risks serious damage to human welfare involving loss of life or injury, or damage to national security)

### European Union — General Data Protection Regulation (GDPR)

GDPR is not a computer crime law but directly impacts penetration testing when personal data is involved:

- Discovering personal data during testing triggers data protection obligations
- Test data must be handled according to GDPR requirements (minimization, storage limitation)
- Data breaches discovered during testing may trigger notification requirements
- GDPR Article 33 requires notifying the supervisory authority **within 72 hours** of becoming aware of a breach — the engagement contract must specify who is responsible for starting this clock
- The engagement contract should address data handling responsibilities

### Other Notable Laws

```text
Jurisdiction       Law                              Focus
-----------------  -------------------------------  ---------------------------
Australia          Criminal Code Act 1995 §477-478  Unauthorized access, modification
Canada             Criminal Code §342.1-342.2       Unauthorized use of computers
Germany            StGB §202a-202c                  Data espionage, interception
Japan              Act on Prohibition of             Unauthorized access
                   Unauthorized Computer Access
```

### Cloud Provider Testing Policies

Major cloud providers have specific policies for penetration testing on their platforms:

- **AWS** — no longer requires pre-approval for most testing on customer-owned resources; prohibited activities include DNS zone walking, DoS/DDoS, and port flooding
- **Azure** — no pre-approval required for testing against customer-owned resources; standard penetration testing rules apply; DoS testing requires separate engagement through approved partners
- **GCP** — no pre-approval required for testing against customer-owned resources; must comply with Acceptable Use Policy; no DoS testing against GCP infrastructure

Policies change — always verify the current policy before testing.

### Liability and Insurance

Professional penetration testers carry specific insurance:

- **Professional Liability (Errors & Omissions)** — covers claims of negligence or inadequate work
- **Cyber Liability Insurance** — covers accidental damage to client systems during testing
- **General Liability** — covers physical damage (relevant for physical security assessments)

The engagement contract should clearly define liability limits, indemnification clauses, and insurance requirements.

## Practical Examples

### Pre-Engagement Checklist

Before starting any technical work:

```text
[ ] Signed authorization letter / permission to test on file
[ ] Scope document reviewed and understood
[ ] Rules of engagement agreed upon
[ ] NDA signed by both parties
[ ] Emergency contacts documented
[ ] Third-party authorizations obtained (cloud providers, MSPs)
[ ] Testing windows confirmed
[ ] Out-of-scope systems clearly documented
[ ] Insurance coverage verified
[ ] Communication channels established (secure email, encrypted chat)
```

### Scope Verification

Before every scan, confirm the target is in scope:

```text
Authorized scope:     10.10.10.0/24
                      web.example.com
                      api.example.com

Out of scope:         10.10.11.0/24 (production network)
                      mail.example.com
                      *.third-party.com

Testing window:       Mon-Fri 18:00-06:00
                      Weekends: any time

Restrictions:         No denial of service
                      No social engineering against executives
                      No physical access testing
```

### When Authorization Is Ambiguous

If there is any doubt about whether a system is in scope:

1. **Stop testing that system immediately**
2. Document what you observed and how you reached it
3. Contact the project lead or client emergency contact
4. Wait for written confirmation before proceeding
5. Never assume — "probably in scope" is not authorization

## References

### Legislation

- [18 U.S.C. § 1030 — Computer Fraud and Abuse Act (CFAA)](https://www.law.cornell.edu/uscode/text/18/1030)
- [Computer Misuse Act 1990 (UK)](https://www.legislation.gov.uk/ukpga/1990/18/contents)
- [General Data Protection Regulation (GDPR)](https://gdpr-info.eu/)
- [DOJ Computer Crime and Intellectual Property Section](https://www.justice.gov/criminal/criminal-ccips)

### Standards and Frameworks

- [NIST SP 800-115 — Technical Guide to Information Security Testing and Assessment](https://csrc.nist.gov/pubs/sp/800/115/final)
- [Penetration Testing Execution Standard (PTES)](https://pentest-standard.readthedocs.io/en/latest/)
- [ISO/IEC 27001 — Information Security Management](https://www.iso.org/standard/75281.html)

### Ethics Codes

- [ISC2 Code of Ethics](https://www.isc2.org/ethics)
- [EC-Council Code of Ethics](https://www.eccouncil.org/code-of-ethics/)
