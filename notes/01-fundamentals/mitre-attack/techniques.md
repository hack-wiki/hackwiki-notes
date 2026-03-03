% Filename: 01-fundamentals/mitre-attack/techniques.md
% Display name: ATT&CK Techniques
% Last update: 2026-02-10
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# ATT&CK Techniques

## Overview

Techniques describe "how" an adversary achieves a tactical objective. While tactics answer "why" (e.g., the adversary wants to escalate privileges), techniques answer "how" (e.g., the adversary exploits a SUID binary). Each technique belongs to one or more tactics and includes a description, procedure examples from real-world incidents, detection guidance, and mitigations.

Techniques are identified by T-numbers (e.g., T1059 — Command and Scripting Interpreter). Sub-techniques provide more specific variants (e.g., T1059.001 — PowerShell). Procedures are the specific implementations observed in the wild — how a particular threat group used a technique in an actual operation.

## Key Concepts

### Technique Structure

Every ATT&CK technique page contains:

| Section | What It Tells You |
|---------|-------------------|
| Description | What the technique is and how it works |
| Sub-Techniques | More specific variants (when applicable) |
| Procedure Examples | Real-world usage by threat groups and malware |
| Mitigations | Defensive measures that reduce risk |
| Detection | How to identify this technique in telemetry |
| References | Source reports and research |

### Techniques vs Sub-Techniques

Sub-techniques break down a broad technique into specific variants. The parent technique describes the general approach; sub-techniques describe specific implementations.

Example — T1059 (Command and Scripting Interpreter):

| ID | Name | Description |
|----|------|-------------|
| T1059 | Command and Scripting Interpreter | Adversary uses command-line interfaces or scripting to execute commands |
| T1059.001 | PowerShell | Execution via PowerShell |
| T1059.003 | Windows Command Shell | Execution via cmd.exe |
| T1059.004 | Unix Shell | Execution via Bash, sh, or other Unix shells |
| T1059.005 | Visual Basic | Execution via VBScript or VBA macros |
| T1059.006 | Python | Execution via Python interpreter |

Not every technique has sub-techniques. Some techniques are specific enough on their own (e.g., T1190 — Exploit Public-Facing Application).

### Techniques Across Multiple Tactics

Some techniques appear under more than one tactic because the same action can serve different objectives. For example:

| Technique | Tactics |
|-----------|---------|
| T1053 — Scheduled Task/Job | Execution, Persistence, Privilege Escalation |
| T1078 — Valid Accounts | Initial Access, Persistence, Privilege Escalation, Defense Evasion |
| T1055 — Process Injection | Defense Evasion, Privilege Escalation |

T1078 (Valid Accounts) maps to four tactics because stolen credentials serve multiple purposes — gaining initial access, persisting in the environment, escalating privileges, and blending in with legitimate activity.

### Procedure Examples

Procedures are the specific, observed implementations of a technique. They tie abstract techniques to real adversary behavior.

For example, under T1003 (OS Credential Dumping):
- **APT28** used Mimikatz to dump credentials from LSASS memory

Procedure examples make techniques concrete. They show how real attackers actually use a technique, not just how it could theoretically be used.

### Key Technique Categories

The following are some of the most commonly encountered technique areas in penetration testing. These are representative examples — not an exhaustive list.

**Initial Access Techniques:**

| ID | Name | Common Usage |
|----|------|-------------|
| T1190 | Exploit Public-Facing Application | Web app exploitation (SQLi, RCE) |
| T1566 | Phishing | Spearphishing with attachments, links, or via services |
| T1078 | Valid Accounts | Using stolen or default credentials |
| T1195 | Supply Chain Compromise | Compromising software update mechanisms |

**Execution Techniques:**

| ID | Name | Common Usage |
|----|------|-------------|
| T1059 | Command and Scripting Interpreter | Shell commands, PowerShell, Python |
| T1053 | Scheduled Task/Job | Cron jobs, Windows Task Scheduler |
| T1047 | Windows Management Instrumentation | Remote execution via WMI |

**Privilege Escalation Techniques:**

| ID | Name | Common Usage |
|----|------|-------------|
| T1068 | Exploitation for Privilege Escalation | Kernel exploits, service exploits |
| T1548 | Abuse Elevation Control Mechanism | Sudo misconfig, UAC bypass |
| T1134 | Access Token Manipulation | Token impersonation on Windows |

**Credential Access Techniques:**

| ID | Name | Common Usage |
|----|------|-------------|
| T1003 | OS Credential Dumping | LSASS dump, SAM extraction, /etc/shadow |
| T1558 | Steal or Forge Kerberos Tickets | Kerberoasting, Golden Ticket |
| T1110 | Brute Force | Password spraying, credential stuffing |

**Lateral Movement Techniques:**

| ID | Name | Common Usage |
|----|------|-------------|
| T1021 | Remote Services | RDP, SSH, SMB, WinRM |
| T1550 | Use Alternate Authentication Material | Pass-the-hash, pass-the-ticket |
| T1570 | Lateral Tool Transfer | Moving tools between compromised hosts |

### Technique IDs in Practice

ATT&CK IDs follow a consistent format:

| Format | Example | Meaning |
|--------|---------|---------|
| TA00XX | TA0001 | Tactic (Initial Access) |
| T1XXX | T1059 | Technique (Command and Scripting Interpreter) |
| T1XXX.00X | T1059.001 | Sub-technique (PowerShell) |
| GXXXX | G0007 | Threat group (APT28) |
| SXXXX | S0002 | Software (Mimikatz) |
| MXXXX | M1036 | Mitigation (Account Use Policies) |

### Data Sources and Detection

Each technique lists data sources — the telemetry needed to detect it. Data sources tell defenders what to log and monitor.

Example — T1059.001 (PowerShell):
- **Process creation** — monitor for powershell.exe launches
- **Command execution** — log PowerShell script block logging (Event ID 4104)
- **Module loading** — track suspicious module imports

Data sources help security teams answer: "Can we detect this technique with our current logging?" If the answer is no, the data source tells them what to enable.

### Mitigations

Mitigations are preventive measures mapped to techniques. They answer: "How do we reduce the risk of this technique?"

Example mitigations for T1059 (Command and Scripting Interpreter):
- **M1042 — Disable or Remove Feature or Program**: Remove unnecessary scripting interpreters
- **M1049 — Antivirus/Antimalware**: Detect known malicious scripts
- **M1038 — Execution Prevention**: Application whitelisting to block unauthorized interpreters

## Practical Examples

### Reading a Technique Page

When examining a technique page on attack.mitre.org:

1. **Read the description** — understand what the technique does
2. **Check sub-techniques** — determine if a more specific variant applies
3. **Review procedure examples** — see how real adversaries used it
4. **Check detection guidance** — identify what telemetry is needed
5. **Review mitigations** — determine what preventive controls apply
6. **Note the data sources** — verify your logging covers them

### Mapping Pentest Findings to Techniques

```text
Finding: Gained root via writable cron job
Mapping:
  Tactic: TA0004 (Privilege Escalation)
  Technique: T1053.003 (Scheduled Task/Job: Cron)
  
Finding: Extracted domain hashes via DCSync
Mapping:
  Tactic: TA0006 (Credential Access)
  Technique: T1003.006 (OS Credential Dumping: DCSync)
  
Finding: Moved to file server using stolen NTLM hash
Mapping:
  Tactic: TA0008 (Lateral Movement)
  Technique: T1550.002 (Use Alternate Authentication Material: Pass the Hash)
```

## References

### Official Documentation

- [MITRE ATT&CK Techniques Overview](https://attack.mitre.org/techniques/enterprise/)
- [MITRE ATT&CK Sub-Techniques FAQ](https://attack.mitre.org/resources/faq/)
- [MITRE ATT&CK Data Sources](https://attack.mitre.org/datasources/)
