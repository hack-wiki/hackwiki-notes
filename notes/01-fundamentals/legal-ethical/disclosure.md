% Filename: 01-fundamentals/legal-ethical/disclosure.md
% Display name: Vulnerability Disclosure
% Last update: 2026-02-11
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# Vulnerability Disclosure

## Overview

Vulnerability disclosure is the process of reporting security flaws to the responsible parties so they can be fixed before exploitation. How a vulnerability is disclosed affects whether it gets patched, how quickly attackers can exploit it, and whether the reporter faces legal risk. Penetration testers encounter disclosure decisions on both contracted engagements (report to the client) and independent research (report to a vendor or the public).

## Key Concepts

### Disclosure Models

There are three primary models for vulnerability disclosure. Each has trade-offs between speed of patching, public safety, and researcher protection.

### Coordinated Disclosure (Responsible Disclosure)

The researcher reports the vulnerability privately to the vendor and allows a reasonable timeframe for patching before any public disclosure. This is the industry standard.

**Process:**

```text
1. Researcher discovers vulnerability
2. Researcher contacts vendor privately (security@, security.txt, bug bounty)
3. Vendor acknowledges receipt (expected within 5 business days)
4. Vendor develops and tests a patch
5. Vendor releases the patch
6. Researcher publishes details (after patch is available)
```

**Standard timeline:**
- Industry norm: 90 days from initial report to public disclosure
- Google Project Zero: 90 days; Project Zero may offer a 14-day grace extension if a fix is expected within those 14 days; details are published 30 days after the fix is made available
- CERT/CC: 45 days
- If the vendor is unresponsive or refuses to patch, the researcher may disclose after the deadline

**When to use:** Most situations. Gives the vendor time to fix the issue while maintaining accountability through a disclosure deadline.

### Full Disclosure

The researcher publishes complete vulnerability details publicly without prior notification to the vendor. The logic is that public pressure forces faster patching and that users deserve to know about risks immediately.

**Risks:**
- Attackers can exploit the vulnerability before a patch exists
- May violate laws in some jurisdictions
- Can damage the researcher's professional reputation
- Burns the vendor relationship

**When it may be justified:**
- Vendor has been notified but refuses to acknowledge or fix the vulnerability
- Vendor has a pattern of suppressing vulnerability reports
- The vulnerability is already being exploited in the wild

### Private Disclosure (No Disclosure)

The vulnerability is reported to the vendor and never published publicly. The vendor patches silently.

**Drawbacks:**
- No accountability — vendor may delay or deprioritize the fix
- Other researchers may discover and disclose the same vulnerability
- Security community cannot learn from the issue
- No public record helps defenders detect exploitation attempts

**When appropriate:**
- Critical infrastructure where public disclosure creates disproportionate risk
- Contractual obligation (some pentest engagements require non-disclosure)

### Finding the Right Contact

Reporting a vulnerability requires reaching the right person. Sending a vulnerability report to a generic support inbox often fails.

**Where to look (in order):**

1. **security.txt** — standardized file at `/.well-known/security.txt` (RFC 9116)
2. **Bug bounty program** — check HackerOne, Bugcrowd, or the vendor's website
3. **security@ email** — `security@<domain>` is the conventional address
4. **PSIRT page** — large vendors maintain Product Security Incident Response Teams
5. **CERT/CC** — acts as a coordinator when the vendor is unresponsive

```bash
# Check for security.txt (RFC 9116)
curl -sL https://example.com/.well-known/security.txt

# Common security.txt fields:
# Contact: security@example.com
# Encryption: https://example.com/pgp-key.txt
# Policy: https://example.com/security-policy
# Preferred-Languages: en
# Expires: 2026-12-31T23:59:59.000Z
```

### Writing a Vulnerability Report

A good vulnerability report is clear, reproducible, and professional. Poor reports get ignored.

**Essential components:**

```text
1. Summary
   One-paragraph description: what the vulnerability is, where it exists,
   and what an attacker can do with it.

2. Affected System
   Product name, version, URL, endpoint, or component.

3. Severity Assessment
   CVSS score (if applicable), or qualitative rating with justification.

4. Reproduction Steps
   Numbered, step-by-step instructions that allow the vendor to
   reproduce the vulnerability independently. Include:
   - Environment setup
   - Exact HTTP requests, commands, or inputs
   - Expected vs actual behavior
   - Screenshots or proof-of-concept code

5. Impact
   What can an attacker achieve? Data theft, code execution, privilege
   escalation, denial of service, etc. Include realistic attack scenarios.

6. Suggested Fix
   Optional but appreciated. Propose a remediation approach.

7. Timeline
   State your disclosure deadline (e.g., 90 days from report date).

8. Researcher Contact
   Name/handle, email, PGP key for encrypted communication.
```

**Report quality matters:**
- Include proof — claims without evidence are ignored
- Be specific — "the login page is vulnerable" vs "POST /api/login accepts SQL injection in the username parameter via `' OR 1=1--`"
- Be professional — accusatory or threatening language guarantees a bad outcome
- Encrypt sensitive reports — use PGP when a public key is available

### CVE Process

CVE (Common Vulnerabilities and Exposures) provides standardized identifiers for publicly known vulnerabilities.

**How a CVE is assigned:**

```text
1. Researcher discovers vulnerability
2. Researcher (or vendor) requests a CVE ID from a CNA
   (CVE Numbering Authority — MITRE, vendors like Microsoft/Red Hat, etc.)
3. CNA assigns a CVE ID (CVE-YYYY-N+, where N+ is 4 or more digits)
4. CVE entry is populated with description, affected versions, references
5. CVE is published in the NVD (National Vulnerability Database) with CVSS score
```

**Who can request a CVE:**
- The vendor (most common — vendors are often their own CNA)
- The researcher (through MITRE or a relevant CNA)
- Coordinators (CERT/CC, CISA)

### Bug Bounty Programs

Many organizations offer financial rewards for vulnerability reports through structured programs.

**Key platforms:**
- HackerOne — largest platform, hosts programs for major companies
- Bugcrowd — managed and self-service programs
- Vendor-run programs — Google, Microsoft, Apple, Meta run their own

**Bug bounty scope rules:**
- Only test systems explicitly listed in the program scope
- Follow the program's rules — violations can result in bans or legal action
- Duplicate reports (someone reported it first) typically receive no reward
- Out-of-scope findings may still be accepted but without payment
- Some programs require non-disclosure until the fix is deployed

### Pentest Engagement Disclosure

On contracted penetration tests, disclosure follows the engagement agreement — not the public disclosure models above.

**Standard pentest reporting flow:**

```text
1. Testing completed within authorized scope and timeframe
2. Draft report delivered to client (findings, evidence, remediation)
3. Client reviews and requests clarification
4. Final report delivered
5. Remediation period (client fixes issues)
6. Optional: retest to verify fixes
7. Report remains confidential (per NDA)
```

**Key differences from independent research:**
- All findings belong to the client (per the contract)
- No public disclosure unless the client explicitly authorizes it
- Findings in third-party software (discovered during the engagement) may warrant separate coordinated disclosure to the vendor — discuss with the client first
- Retain evidence only as long as the contract permits

## Practical Examples

### Disclosure Timeline Template

```text
Day 0:    Vulnerability discovered
Day 1:    Initial report sent to vendor (encrypted, via security.txt contact)
Day 5:    Follow-up if no acknowledgment received
Day 7:    Escalate to CERT/CC if vendor remains unresponsive
Day 45:   Status check — request patch timeline
Day 80:   Final notice — inform vendor of disclosure date
Day 90:   Public disclosure (with or without patch)
```

### Handling Unresponsive Vendors

```text
Attempt   Action                              Wait
--------  ----------------------------------  -----------
1         Email security@ and security.txt    7 days
2         Resend with read receipt request     7 days
3         Contact via social media / LinkedIn  7 days
4         Report to CERT/CC as coordinator     30 days
5         Publish advisory                     —
```

Document every contact attempt with dates and content. This record protects the researcher if the vendor later claims they were not notified.

## References

### Standards and Guidelines

- [RFC 9116 — A File Format to Aid in Security Vulnerability Disclosure (security.txt)](https://datatracker.ietf.org/doc/html/rfc9116)
- [RFC 2350 — Expectations for Computer Security Incident Response](https://datatracker.ietf.org/doc/html/rfc2350)
- [CISA Coordinated Vulnerability Disclosure Process](https://www.cisa.gov/coordinated-vulnerability-disclosure-process)
- [CERT/CC Vulnerability Disclosure Policy](https://certcc.github.io/certcc_disclosure_policy/)

### Bug Bounty Platforms

- [HackerOne Disclosure Guidelines](https://www.hackerone.com/disclosure-guidelines)

### Legislation

- [18 U.S.C. § 1030 — Computer Fraud and Abuse Act (CFAA)](https://www.law.cornell.edu/uscode/text/18/1030)
