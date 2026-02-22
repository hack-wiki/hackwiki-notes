% Filename: 12-defensive/incident-response/02-identification.md
% Display name: Step 2 - Identification
% Last update: 2026-02-11
% Authors: @TristanInSec

# Identification

## Overview

Identification is the phase where a potential security event is detected,
validated, and classified as an incident. This includes initial detection
from monitoring systems, alert triage, scope assessment, evidence
preservation, and severity classification. The goal is to quickly determine
whether an incident has occurred, how severe it is, and what systems are
affected.

## Detection Sources

```text
How incidents are typically detected:

Automated detection:
  - SIEM alerts (correlation rules, anomaly detection)
  - IDS/IPS alerts (Suricata, Snort)
  - Endpoint detection (EDR alerts, antivirus)
  - Email security (phishing detection, sandboxing)
  - DLP alerts (data loss prevention)

Human detection:
  - User reports ("I clicked a suspicious link")
  - IT helpdesk ("This system is behaving strangely")
  - Threat intelligence (IOC matching, dark web monitoring)
  - Audit findings (compliance review, penetration test results)

External notification:
  - Law enforcement contact
  - CERT notification
  - Vendor/partner notification
  - Media report or public disclosure
```

## Initial Triage

```text
First 30 minutes after detection:

1. Validate the alert
   - Is this a true positive or false positive?
   - Check multiple data sources for corroboration
   - Do NOT modify or clean the affected system yet

2. Identify affected systems
   - Which hosts are involved?
   - Which users/accounts are affected?
   - What data is potentially impacted?

3. Determine attack vector
   - How did the attacker gain access?
   - Phishing? Exploit? Credential theft? Insider?

4. Assess current status
   - Is the attack ongoing or historical?
   - Is the attacker still present?
   - Is data actively being exfiltrated?

5. Classify severity
   - Based on data sensitivity, scope, and business impact
   - Assign initial severity level (SEV-1 through SEV-4)
```

## Evidence Preservation

```text
Evidence preservation priorities (order of volatility):

1. CPU registers, cache         (most volatile — lost immediately)
2. Memory (RAM)                 (lost on reboot)
3. Network connections          (ephemeral, capture now)
4. Running processes            (state changes continuously)
5. Disk contents                (persists but can be overwritten)
6. Remote logging data          (may rotate or be deleted)
7. Physical configuration       (least volatile)
8. Archival media               (backups, offline storage)

Critical first steps:
  - Do NOT shut down compromised systems (preserves memory)
  - Capture memory dump BEFORE any other action
  - Screenshot active sessions and running processes
  - Record network connections (netstat / ss output)
  - Document exact time and timezone of all actions
  - Begin chain of custody documentation
```

### Live Data Collection

```bash
# Collect volatile data from a live Linux system
# Run each command and redirect output to evidence file

# Current date/time and timezone
date -u > /evidence/$(hostname)_triage.txt
echo "---" >> /evidence/$(hostname)_triage.txt

# Logged-in users
who >> /evidence/$(hostname)_triage.txt
echo "---" >> /evidence/$(hostname)_triage.txt

# Running processes
ps auxef >> /evidence/$(hostname)_triage.txt
echo "---" >> /evidence/$(hostname)_triage.txt

# Network connections
ss -tlnp >> /evidence/$(hostname)_triage.txt
ss -ulnp >> /evidence/$(hostname)_triage.txt
echo "---" >> /evidence/$(hostname)_triage.txt

# Network interfaces
ip addr >> /evidence/$(hostname)_triage.txt
echo "---" >> /evidence/$(hostname)_triage.txt

# Routing table
ip route >> /evidence/$(hostname)_triage.txt
echo "---" >> /evidence/$(hostname)_triage.txt

# DNS configuration
cat /etc/resolv.conf >> /evidence/$(hostname)_triage.txt
echo "---" >> /evidence/$(hostname)_triage.txt

# Recent authentication
last -20 >> /evidence/$(hostname)_triage.txt
echo "---" >> /evidence/$(hostname)_triage.txt

# Crontabs
crontab -l 2>/dev/null >> /evidence/$(hostname)_triage.txt
```

## Scope Assessment

```text
Determine the scope of the incident:

Horizontal scope (breadth):
  - How many systems are affected?
  - Which network segments are involved?
  - Are multiple sites/locations affected?

Vertical scope (depth):
  - What level of access does the attacker have?
  - User-level? Admin-level? Domain admin?
  - Are backup systems compromised?

Temporal scope:
  - When did the initial compromise occur?
  - How long has the attacker been in the environment?
  - What is the timeline of attacker activity?

Data scope:
  - What data has been accessed or exfiltrated?
  - Is PII, PHI, financial, or classified data involved?
  - What is the regulatory impact?
```

## Incident Classification

| Category | Examples | Typical Severity |
|---|---|---|
| Malware | Ransomware, trojan, worm | SEV-1 to SEV-3 |
| Unauthorized access | Credential theft, brute force | SEV-1 to SEV-3 |
| Data breach | Exfiltration, exposure | SEV-1 |
| Insider threat | Malicious or negligent employee | SEV-1 to SEV-2 |
| Denial of service | DDoS, resource exhaustion | SEV-2 to SEV-3 |
| Web compromise | Defacement, web shell | SEV-2 to SEV-3 |
| Policy violation | Unauthorized software, misuse | SEV-3 to SEV-4 |

## References

### Further Reading

- [NIST SP 800-61: Computer Security Incident Handling Guide](https://csrc.nist.gov/pubs/sp/800/61/r2/final)
