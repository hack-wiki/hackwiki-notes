% Filename: 12-defensive/detection/log-analysis.md
% Display name: Log Analysis Fundamentals
% Last update: 2026-02-11
% Authors: @TristanInSec

# Log Analysis Fundamentals

## Overview

Log analysis is the process of collecting, normalizing, and examining log data
from multiple sources to detect security events, investigate incidents, and
maintain audit trails. Effective log analysis requires centralized collection,
consistent parsing, and knowledge of what normal looks like so that anomalies
stand out.

## Log Sources

### Host-Based Sources

| Source | Platform | Key Events |
|---|---|---|
| Windows Event Logs | Windows | Authentication, process creation, service changes |
| Syslog / journald | Linux | Authentication, service events, kernel messages |
| auditd | Linux | Syscall auditing, file access, user actions |
| PowerShell logs | Windows | Script execution, module loading |
| Application logs | Both | Web server access, database queries, application errors |

### Network-Based Sources

| Source | Key Events |
|---|---|
| Firewall logs | Allowed/denied connections, NAT translations |
| IDS/IPS alerts | Signature matches, protocol anomalies |
| DNS logs | Query records, resolution failures |
| Proxy logs | HTTP requests, blocked URLs, user agents |
| NetFlow / IPFIX | Connection metadata, traffic volumes |

## Centralized Logging

### Syslog Forwarding

```bash
# rsyslog — forward all logs to a central server
# /etc/rsyslog.conf or /etc/rsyslog.d/50-remote.conf

# Forward over TCP (reliable)
# *.* @@syslog-server.example.com:514

# Forward over UDP (traditional)
# *.* @syslog-server.example.com:514

# Forward specific facilities
# auth,authpriv.* @@syslog-server.example.com:514
# kern.* @@syslog-server.example.com:514

# Test syslog forwarding
logger -p auth.info "Test log message from $(hostname)"
```

### Log Formats

```text
Common Log Format (CLF) — web server access logs:
  127.0.0.1 - frank [10/Oct/2026:13:55:36 -0700] "GET /index.html HTTP/1.0" 200 2326

Combined Log Format — CLF + referer and user-agent:
  127.0.0.1 - frank [10/Oct/2026:13:55:36 -0700] "GET /index.html HTTP/1.0" 200 2326 "http://www.example.com" "Mozilla/5.0"

Syslog (RFC 5424):
  <priority>version timestamp hostname app-name procid msgid structured-data msg
  <34>1 2026-01-15T12:00:00.000Z server01 sshd 12345 - - Failed password for root from 10.0.0.1

JSON structured logging:
  {"timestamp":"2026-01-15T12:00:00Z","host":"server01","service":"sshd","event":"auth_failure","user":"root","src":"10.0.0.1"}
```

## SIEM Concepts

A Security Information and Event Management (SIEM) system collects,
normalizes, correlates, and alerts on log data from across the environment.

### SIEM Architecture

```text
Data Sources                    SIEM Platform               Outputs
┌──────────────┐
│ Endpoints    │──┐
│ Servers      │  │         ┌──────────────────┐       ┌─────────────┐
│ Network      │──┼────────→│ Collection       │──────→│ Dashboards  │
│ Cloud        │  │         │ Normalization    │       │ Alerts      │
│ Applications │──┘         │ Correlation      │       │ Reports     │
└──────────────┘            │ Storage/Search   │       │ Cases       │
                            └──────────────────┘       └─────────────┘
```

### Common SIEM Platforms

| Platform | Type | Notes |
|---|---|---|
| Splunk | Commercial | SPL query language, wide ecosystem |
| Elastic Security | Open / Commercial | ELK stack (Elasticsearch, Logstash, Kibana) |
| Microsoft Sentinel | Cloud | Azure-native, KQL query language |
| Wazuh | Open source | OSSEC-based, agent + manager architecture |
| Graylog | Open / Commercial | Graylog query language, pipeline processing |

## Log Analysis Workflow

### Initial Triage

```bash
# Quick log statistics — count events by type
# For syslog-format logs:
awk '{print $5}' /var/log/syslog | sort | uniq -c | sort -rn | head -20

# Count log entries per hour
awk '{print $1, substr($3,1,2)":00"}' /var/log/auth.log | sort | uniq -c | sort -rn

# Find time range of a log file
head -1 /var/log/auth.log
tail -1 /var/log/auth.log
```

### Pattern-Based Analysis

```bash
# Search for known-bad indicators
grep -iE "failed|error|denied|unauthorized|invalid" /var/log/auth.log

# Extract unique IP addresses from logs
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' /var/log/auth.log | sort -u

# Extract unique usernames from authentication logs
grep "Failed password" /var/log/auth.log | awk '{print $(NF-5)}' | sort | uniq -c | sort -rn

# Find events in a time window
awk '/Jan 15 14:0[0-9]/' /var/log/auth.log
```

### Statistical Analysis

```bash
# Top source IPs by failed login count
grep "Failed password" /var/log/auth.log | \
  grep -oE 'from [0-9.]+' | awk '{print $2}' | sort | uniq -c | sort -rn | head -20

# Events per minute (detect bursts)
awk '{print $1, $2, substr($3,1,5)}' /var/log/auth.log | sort | uniq -c | sort -rn | head -20

# Unique user-agent strings from web logs
awk -F'"' '{print $6}' /var/log/apache2/access.log | sort | uniq -c | sort -rn | head -20
```

## Log Retention

| Log Type | Recommended Retention | Regulatory Notes |
|---|---|---|
| Authentication logs | 1 year minimum | PCI DSS requires 1 year |
| Firewall / IDS logs | 90 days - 1 year | HIPAA applies 6-year documentation retention as audit log best practice |
| System / application | 90 days - 1 year | SOX requires 7 years for financial |
| DNS / proxy logs | 90 days | Useful for threat hunting |
| Full packet capture | 7-30 days | Storage intensive |

## References

### Further Reading

- [NIST SP 800-92: Guide to Computer Security Log Management](https://csrc.nist.gov/pubs/sp/800/92/final)
