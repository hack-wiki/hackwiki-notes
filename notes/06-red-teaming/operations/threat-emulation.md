% Filename: 06-red-teaming/operations/threat-emulation.md
% Display name: Threat Emulation
% Last update: 2026-02-11
% ATT&CK Tactics: TA0001 (Initial Access)
% ATT&CK Techniques: T1195 (Supply Chain Compromise)
% Authors: @TristanInSec

# Threat Emulation

## Overview

Threat emulation replicates the tactics, techniques, and procedures (TTPs) of specific threat actors to test whether an organization's defenses can detect and respond to realistic attacks. Unlike generic penetration testing, threat emulation is intelligence-driven — the red team follows a known adversary's playbook. MITRE ATT&CK provides the framework for mapping adversary behavior to testable techniques.

## ATT&CK Mapping

- **Tactic:** TA0001 - Initial Access
- **Technique:** T1195 - Supply Chain Compromise

## Techniques

### MITRE ATT&CK Navigator

The ATT&CK Navigator visualizes which techniques a threat actor uses:

```text
1. Go to https://mitre-attack.github.io/attack-navigator/
2. Create a new layer
3. Search for the threat group (e.g., APT29, FIN7, Lazarus)
4. Highlight their known techniques
5. Use this as the red team's attack plan
```

Common threat groups for emulation:

| Group | Industry Target | Key TTPs |
|-------|----------------|----------|
| APT29 (Cozy Bear) | Government, think tanks | Spear-phishing, WMI, PowerShell, token manipulation |
| APT28 (Fancy Bear) | Government, military | Spear-phishing, credential harvesting, OAuth abuse |
| FIN7 | Retail, hospitality | Spear-phishing, JScript, Carbanak, POS malware |
| Lazarus | Finance, crypto | Spear-phishing, custom malware, supply chain |
| Wizard Spider | Healthcare, enterprise | Phishing, TrickBot, Ryuk/Conti ransomware chain |

### MITRE Caldera

Caldera is an open-source automated adversary emulation platform:

```bash
# MITRE Caldera
# https://github.com/mitre/caldera

# Clone and start (Docker)
git clone https://github.com/mitre/caldera.git --recursive
cd caldera
docker compose up -d

# Access web UI at http://localhost:8888
# Default credentials: red/admin or blue/admin
```

Caldera features:
- Pre-built adversary profiles mapped to ATT&CK
- Automated agent deployment and TTP execution
- Ability chains (sequences of ATT&CK techniques)
- Blue team detection scoring

### Atomic Red Team

Atomic Red Team provides small, focused tests for individual ATT&CK techniques:

```powershell
# Atomic Red Team
# https://github.com/redcanaryco/atomic-red-team

# Install the execution framework (PowerShell)
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam

# List available tests for a technique
Invoke-AtomicTest T1059.001 -ShowDetails

# Run a specific atomic test
Invoke-AtomicTest T1059.001 -TestNumbers 1

# Run all tests for a technique
Invoke-AtomicTest T1059.001

# Cleanup after test
Invoke-AtomicTest T1059.001 -Cleanup
```

### Building an Emulation Plan

```text
1. Select the threat actor based on:
   - Client's industry and geography
   - Known active threats to the organization
   - Client request or threat intelligence

2. Map TTPs from ATT&CK:
   - Initial Access: How does the actor gain entry?
   - Execution: What do they run first?
   - Persistence: How do they maintain access?
   - Lateral Movement: How do they spread?
   - Collection/Exfil: What do they steal and how?

3. Build the kill chain:
   - Match each TTP to a tool or technique the red team will use
   - Identify which TTPs the blue team SHOULD detect
   - Plan detection checkpoints throughout the operation

4. Execute and measure:
   - Log every action with timestamp
   - After the engagement, compare red team timeline to blue team detections
   - Identify detection gaps (TTPs that went unnoticed)
```

### Example: APT29 Emulation

```text
Phase 1 — Initial Access
  - Spear-phishing with malicious link (T1566.002)
  - HTML smuggling for payload delivery (T1027.006)

Phase 2 — Execution
  - PowerShell execution (T1059.001)
  - User execution of malicious file (T1204.002)

Phase 3 — Persistence
  - Registry Run key (T1547.001)
  - Scheduled task (T1053.005)

Phase 4 — Discovery
  - System information discovery (T1082)
  - Domain trust discovery (T1482)

Phase 5 — Lateral Movement
  - WMI execution (T1047) for remote command execution
  - Pass the ticket (T1550.003)

Phase 6 — Collection & Exfiltration
  - Data staged to local drive (T1074.001)
  - Exfiltration over C2 channel (T1041)
```

## Detection Methods

### Measuring Detection Coverage

After the emulation, score each technique:

| Score | Meaning |
|-------|---------|
| Detected + Alerted | SOC saw the alert and investigated |
| Detected, Not Alerted | Logs captured it but no alert fired |
| Logged, Not Detected | Telemetry exists but no detection rule |
| Not Logged | No telemetry captured the activity |

## References

### Official Documentation

- [MITRE ATT&CK](https://attack.mitre.org/)
- [MITRE Caldera](https://github.com/mitre/caldera)
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)

### MITRE ATT&CK

- [T1195 - Supply Chain Compromise](https://attack.mitre.org/techniques/T1195/)
