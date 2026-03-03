% Filename: 06-red-teaming/operations/reporting.md
% Display name: Reporting
% Last update: 2026-02-17
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# Reporting

## Overview

The red team report is the primary deliverable of an engagement. Unlike pentest reports that list vulnerabilities with severity ratings, red team reports tell the story of an attack — what the team did, what was detected, and what was missed. The report should be actionable for both technical defenders and executive leadership. A brilliant engagement with a poor report is a wasted engagement.

## Techniques

### Report Structure

```text
1. Executive Summary (1-2 pages)
   - Engagement objective and scope
   - Key findings in business terms
   - Overall security posture assessment
   - Top 3-5 recommendations

2. Engagement Overview
   - Timeline (start/end dates)
   - Threat model emulated
   - Rules of engagement summary
   - Team members involved

3. Attack Narrative
   - Chronological story of the operation
   - Each phase: what was attempted, what succeeded, what was detected
   - Screenshots and evidence for each step
   - ATT&CK technique mapping for every action

4. Detection Analysis
   - What the SOC/blue team detected
   - What was missed and why
   - Time-to-detect for each phase
   - Detection coverage score (ATT&CK heatmap)

5. Findings and Recommendations
   - Each finding: description, impact, evidence, remediation
   - Prioritized by risk (not just CVSS)
   - Short-term vs. long-term remediation
   - Detection engineering recommendations

6. Technical Appendix
   - Full timeline with timestamps
   - IOCs generated (domains, IPs, hashes, user agents)
   - Tools and techniques used
   - Raw evidence and logs
```

### Attack Narrative Writing

The narrative should read like a story, not a vulnerability list:

```text
BAD:
  "Finding 1: Weak password on service account svc_backup (Password1).
   Risk: High."

GOOD:
  "On Day 3, the team Kerberoasted the svc_backup service account
   (T1558.003) and cracked its password offline in 4 minutes using
   hashcat with the rockyou wordlist. This account had local admin
   rights on 47 servers including the file server containing PCI
   cardholder data. The SOC did not alert on the TGS request spike.

   Recommendation: Rotate svc_backup to a 25+ character password or
   migrate to a Group Managed Service Account (gMSA). Enable detection
   for high-volume Kerberos TGS requests (Event 4769)."
```

### Detection Scorecard

Create a matrix comparing red team actions to blue team detections:

```text
| Day/Time | Red Team Action | ATT&CK | Detected? | Time to Detect |
|----------|----------------|--------|-----------|----------------|
| Day 1 09:00 | Phishing email sent | T1566.001 | Yes | 2 hours |
| Day 1 11:30 | Payload executed | T1204.002 | No | — |
| Day 1 12:00 | C2 beacon established | T1071.001 | No | — |
| Day 2 10:15 | Kerberoasting | T1558.003 | No | — |
| Day 2 14:00 | Lateral movement (WMI) | T1047 | Yes | 6 hours |
| Day 3 09:30 | DCSync | T1003.006 | Yes | 45 min |
```

### ATT&CK Heatmap

Use the ATT&CK Navigator to visualize detection coverage:

```text
Color coding:
  - Green: Detected and alerted
  - Yellow: Logged but no alert (detection gap)
  - Red: Not logged at all (visibility gap)
  - Gray: Not tested during this engagement

Export the navigator layer as part of the report appendix.
```

### Evidence Collection During the Engagement

Log everything as you go — reconstructing later is error-prone:

```text
For each action, capture:
  - Timestamp (UTC)
  - Source and destination hosts
  - Tool/command used
  - ATT&CK technique ID
  - Screenshot of the result
  - Whether the action was detected (check with deconfliction if needed)

Use a shared log (Markdown file, wiki, or C2 framework's built-in logging):

  [2026-02-10 14:23 UTC] Operator: Tristan
  Host: WS01 -> DC01
  Action: impacket-secretsdump DCSync (T1003.006)
  Result: Obtained krbtgt hash
  Detected: Unknown at this time
```

### Delivery and Debrief

```text
1. Technical debrief (SOC/IR team)
   - Walk through the attack narrative step by step
   - Discuss each detection gap
   - Provide IOCs for retroactive hunting
   - Review and improve detection rules together

2. Executive debrief (CISO/leadership)
   - Focus on business impact, not technical details
   - "An attacker could access X data in Y days without detection"
   - Prioritized recommendations with estimated effort
   - Compare to previous engagements (trend analysis)

3. Report delivery
   - Encrypt the report (contains sensitive IOCs and attack paths)
   - Deliver via secure channel (not unencrypted email)
   - Agree on data retention and destruction timeline
```

## References

### Official Documentation

- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)

