% Filename: 12-defensive/threat-hunting/overview.md
% Display name: Threat Hunting Overview
% Last update: 2026-02-19
% Authors: @TristanInSec

# Threat Hunting

## Overview

Threat hunting is the proactive search for threats that have evaded existing
detection mechanisms. Unlike reactive detection (waiting for alerts), hunting
starts with a hypothesis about attacker behavior and uses data analysis to
confirm or deny the hypothesis. Effective hunting requires deep knowledge of
attacker techniques and available telemetry.

## Topics

- [Hunting Methodology](methodology.md) — hypothesis-driven hunting,
  data sources, frameworks, and hunt documentation
- [Windows Threat Hunting](hunting-windows.md) — hunting techniques for
  Windows environments using event logs, Sysmon, and endpoint telemetry

## Hunting Workflow

```text
1. Hypothesize  → "Attackers may be using scheduled tasks for persistence"
2. Data source  → Identify relevant logs (Event ID 4698, Sysmon ID 1)
3. Collect      → Query SIEM or endpoint data for the time period
4. Analyze      → Filter, correlate, look for anomalies
5. Validate     → Confirm malicious activity or refine hypothesis
6. Document     → Record findings, create detection rules, update playbooks
```

> **Note:** Sysmon event IDs and field names are schema-version-dependent. Qualify any Sysmon-based hunt queries by the schema version deployed in your environment.
