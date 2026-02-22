% Filename: 12-defensive/detection/overview.md
% Display name: Detection & Monitoring
% Last update: 2026-02-11
% Authors: @TristanInSec

# Detection & Monitoring

## Overview

Detection and monitoring form the foundation of defensive security — without
visibility into what is happening on systems and networks, threats go
unnoticed until damage is done. This section covers log analysis fundamentals,
platform-specific log sources, network-based detection, and rule-based
detection with Sigma and YARA.

## Topics

- [Log Analysis Fundamentals](log-analysis.md) — centralized logging, log
  formats, SIEM concepts, and analysis workflows
- [Windows Log Analysis](windows-logs.md) — Event Log sources, key security
  events, PowerShell logging, and detection patterns
- [Linux Log Analysis](linux-logs.md) — syslog, journald, auditd, and
  authentication log analysis
- [Network Monitoring](network-monitoring.md) — IDS/IPS with Suricata,
  network traffic analysis, and flow monitoring
- [Sigma & YARA Rules](sigma-yara.md) — writing and deploying detection
  rules for log-based and file-based indicators

## Detection Workflow

```text
1. Collect    → Centralize logs from endpoints, servers, network devices
2. Normalize  → Parse into consistent format (timestamps, field names)
3. Correlate  → Match events across sources (host + network + auth)
4. Detect     → Apply rules (Sigma, Suricata, YARA) and anomaly baselines
5. Alert      → Triage alerts, reduce false positives, escalate confirmed
6. Respond    → Hand off to incident response (see incident-response/)
```
