% Filename: 12-defensive/threat-hunting/methodology.md
% Display name: Hunting Methodology
% Last update: 2026-02-19
% Authors: @TristanInSec

# Hunting Methodology

## Overview

Threat hunting methodology provides a structured approach to proactively
searching for threats that evade automated detection. Rather than waiting for
alerts, hunters form hypotheses about attacker behavior, identify relevant
data sources, and analyze data to confirm or deny the hypothesis. This file
covers hunting frameworks, data sources, hypothesis development, and
documentation practices.

## Hypothesis-Driven Hunting

```text
The hypothesis-driven approach:

1. Form a hypothesis
   - Based on threat intelligence, ATT&CK techniques, or known TTPs
   - Example: "An attacker using Kerberoasting would generate TGS requests
     with RC4 encryption for service accounts"

2. Identify data sources
   - What telemetry would show evidence of this behavior?
   - Example: Windows Event ID 4769 with encryption type 0x17 (RC4)

3. Define search criteria
   - What specific patterns indicate malicious activity?
   - How to distinguish from normal behavior?
   - Example: TGS requests with RC4 for high-value SPNs from
     non-service-account sources

4. Execute the hunt
   - Query SIEM, EDR, or raw logs
   - Filter and analyze results
   - Investigate anomalies

5. Document findings
   - Record results (positive or negative)
   - If threat found: escalate to incident response
   - If no threat: document as evidence of absence
   - Create detection rules from successful hunts
```

## Hunting Frameworks

### MITRE ATT&CK-Based Hunting

```text
Use ATT&CK as a structured guide for hunt hypotheses:

1. Select a tactic (e.g., Persistence)
2. Choose a technique (e.g., T1053 — Scheduled Task/Job)
3. Identify sub-techniques (e.g., T1053.005 — Scheduled Task)
4. Map to data sources (Event ID 4698, Sysmon ID 1 with schtasks.exe)
5. Build hunt query
6. Analyze results

Track coverage:
  - Which ATT&CK techniques have been hunted?
  - Which techniques have detection rules?
  - Which techniques have no visibility (gaps)?
```

### TaHiTI (Targeted Hunting integrating Threat Intelligence)

```text
TaHiTI methodology:

1. Trigger — what initiates the hunt?
   - New threat intelligence (new malware family, APT report)
   - Gap analysis (ATT&CK coverage gaps)
   - Anomaly from automated detection
   - Environmental change (new systems, merger, cloud migration)

2. Intelligence — what do we know?
   - Threat actor TTPs
   - Known IOCs (may be stale)
   - Behavioral patterns (more durable than IOCs)
   - Environmental context

3. Hypothesis — what are we looking for?
   - Structured statement about expected attacker behavior
   - Measurable and testable

4. Hunt — search the data
   - Query formulation
   - Data analysis
   - Anomaly investigation

5. Findings — what did we learn?
   - Threats found (or not)
   - Detection gaps identified
   - New detection rules created
   - Process improvements
```

## Data Sources for Hunting

### Endpoint Telemetry

| Data Source | Key Fields | Hunt Use |
|---|---|---|
| Process creation | Process name, command line, parent, user | Unusual processes, LOLBins |
| DLL loading | DLL path, signing status | DLL hijacking, unsigned loads |
| Network connections | Process, destination IP/port | C2 beaconing, tunneling |
| File creation | Path, name, hash | Malware staging, web shells |
| Registry changes | Key, value, process | Persistence mechanisms |
| DNS queries | Domain, process | C2 communication, tunneling |
| Authentication | User, source, type | Lateral movement, credential abuse |

### Network Telemetry

| Data Source | Key Fields | Hunt Use |
|---|---|---|
| Firewall logs | Source, destination, port, action | Policy violations, scanning |
| IDS alerts | Signature, source, destination | Known attack patterns |
| DNS logs | Query, response, client | Tunneling, DGA domains |
| Proxy logs | URL, user agent, response | C2, exfiltration |
| NetFlow | Source, destination, bytes, duration | Beaconing, large transfers |

## Hunt Techniques

### Stack Counting (Frequency Analysis)

```text
Stack counting identifies outliers by frequency:

1. Collect all instances of a data field (e.g., all processes, all DNS queries)
2. Count occurrences of each unique value
3. Sort by frequency
4. Investigate the rare items (low-frequency = unusual = potentially malicious)

Example: rare processes across all endpoints
  - If 10,000 endpoints run chrome.exe but only 1 runs notmalware.exe,
    notmalware.exe deserves investigation

Example: rare outbound connections
  - If 99% of DNS queries go to known domains, the 1% going to
    newly registered domains may be C2
```

### Long-Tail Analysis

```text
Long-tail analysis focuses on the least common items in a dataset:

Steps:
1. Aggregate a data field across the environment
2. Sort by count (ascending)
3. Focus on items that appear very few times
4. Investigate those items for malicious indicators

Applications:
  - Processes: Rare process names or hashes
  - Services: Unusual service names or paths
  - Scheduled tasks: Tasks on very few machines
  - DNS: Domains queried by very few hosts
  - User agents: Rare user agent strings in proxy logs
```

### Baseline Deviation

```text
Identify deviations from established normal behavior:

1. Establish baseline
   - Normal working hours for each user
   - Typical processes per system role (server vs. workstation)
   - Normal network destinations per host
   - Typical authentication patterns

2. Detect deviations
   - Login at 3 AM for a user who works 9-5
   - PowerShell execution on a server that never runs PowerShell
   - Outbound connection to a country with no business presence
   - Admin account authenticating from a workstation
```

## Hunt Documentation

```text
Document every hunt, regardless of findings:

Hunt record:
  - Hunt ID and date
  - Hypothesis
  - ATT&CK technique(s) targeted
  - Data sources queried
  - Time period searched
  - Query/search logic used
  - Findings (positive or negative)
  - New IOCs discovered
  - Detection rules created
  - Recommendations
  - Analyst name

Track metrics:
  - Number of hunts conducted per quarter
  - Percentage resulting in confirmed threats
  - Percentage resulting in new detection rules
  - ATT&CK technique coverage over time
  - Mean time from hunt initiation to finding
```

## References

### Further Reading

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [TaHiTI Threat Hunting Methodology](https://www.betaalvereniging.nl/en/safety/tahiti/)

> **Note:** When referencing Sysmon in hunt queries, qualify by schema version and active configuration. Field names and EventType values differ between schema releases.
