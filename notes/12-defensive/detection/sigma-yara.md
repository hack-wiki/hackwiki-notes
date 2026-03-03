% Filename: 12-defensive/detection/sigma-yara.md
% Display name: Sigma & YARA Rules
% Last update: 2026-02-19
% Authors: @TristanInSec

# Sigma & YARA Rules

## Overview

Sigma and YARA are two complementary detection rule formats. Sigma provides
vendor-agnostic detection rules for log events (similar to Snort/Suricata
rules but for SIEM data), while YARA provides pattern-matching rules for
files and memory. Both enable sharing detection logic across tools and
organizations.

## Sigma Rules

### Sigma Rule Format

```yaml
# Sigma rule structure
# https://github.com/SigmaHQ/sigma

title: Suspicious PowerShell Download Cradle
id: a1234567-89ab-cdef-0123-456789abcdef
status: experimental
description: Detects PowerShell commands commonly used to download and execute payloads
author: Example Author
date: 2026/01/15
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'Invoke-WebRequest'
            - 'Invoke-Expression'
            - 'Net.WebClient'
            - 'DownloadString'
            - 'DownloadFile'
            - 'Start-BitsTransfer'
        Image|endswith: '\powershell.exe'
    condition: selection
falsepositives:
    - Legitimate administrative scripts
level: high
tags:
    - attack.execution
    - attack.t1059.001
```

### Sigma Detection Logic

```yaml
# Detection operators:

# Logical AND — all conditions must match
detection:
    selection1:
        EventID: 4688
    selection2:
        CommandLine|contains: 'mimikatz'
    condition: selection1 and selection2

# Logical OR — any condition matches
detection:
    selection:
        EventID:
            - 4624
            - 4625
    condition: selection

# NOT — exclude events
detection:
    selection:
        EventID: 4688
    filter:
        User: 'SYSTEM'
    condition: selection and not filter

# String modifiers:
#   |contains     — substring match
#   |startswith   — prefix match
#   |endswith     — suffix match
#   |re           — regex match
#   |all          — all values must match (AND within field)
#   |base64       — match base64-encoded value
```

### Sigma CLI

```bash
# sigma-cli
# https://github.com/SigmaHQ/sigma-cli

# Convert a Sigma rule to Splunk SPL
sigma convert -t splunk -p splunk_windows rule.yml

# Convert to Elastic/Kibana query
sigma convert -t lucene -p ecs_windows rule.yml

# Convert to Microsoft Sentinel (KQL)
# (requires: sigma plugin install kusto)
sigma convert -t kusto -p microsoft_365_defender rule.yml

# List available backends
sigma list targets

# List available processing pipelines
sigma list pipelines

# Validate a Sigma rule
sigma check rule.yml

# Convert all rules in a directory
sigma convert -t splunk -p splunk_windows -o output/rules.spl rules/
```

### Example Sigma Rules

```yaml
# Detect scheduled task creation via schtasks
title: Scheduled Task Creation via schtasks
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains: '/create'
    condition: selection
level: medium
```

```yaml
# Detect new service installed (persistence)
title: Suspicious New Service Installation
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
    filter_known:
        ServiceName:
            - 'Windows Update'
            - 'Background Intelligent Transfer Service'
    condition: selection and not filter_known
level: medium
```

```yaml
# Detect Linux reverse shell
title: Linux Reverse Shell Command
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - '/dev/tcp/'
            - 'mkfifo'
            - 'nc -e'
            - 'ncat -e'
    condition: selection
level: high
```

## YARA Rules

### YARA Rule Format

```text
// YARA
// https://virustotal.github.io/yara/

rule Example_Malware_Detection
{
    meta:
        description = "Detects example malware based on known strings"
        author = "Analyst"
        date = "2026-01-15"
        severity = "high"

    strings:
        $s1 = "malicious_function" ascii
        $s2 = { 4D 5A 90 00 }          // MZ header hex pattern
        $s3 = /https?:\/\/[a-z0-9]+\.example\.com/ nocase

    condition:
        $s2 at 0 and ($s1 or $s3)
}
```

### YARA String Types

```text
// Text strings
$text1 = "plain text"
$text2 = "case insensitive" nocase
$text3 = "wide string" wide          // UTF-16
$text4 = "both encodings" ascii wide

// Hex strings (byte patterns)
$hex1 = { 4D 5A 90 00 }              // Exact bytes
$hex2 = { 4D 5A ?? 00 }              // Wildcard byte
$hex3 = { 4D 5A [2-4] 00 }           // Jump (2-4 bytes)
$hex4 = { 4D 5A ( 90 | 91 ) 00 }     // Alternatives

// Regular expressions
$re1 = /https?:\/\/[a-z0-9.]+/
$re2 = /[A-Za-z0-9+\/]{50,}={0,2}/   // Base64 pattern
```

### YARA Conditions

```text
// Count-based
condition:
    2 of ($s*)                          // At least 2 of all $s strings
    all of ($s*)                        // All $s strings must match
    any of them                         // Any string matches

// File attributes
condition:
    filesize < 500KB and $s1
    uint16(0) == 0x5A4D and $s1        // PE file (MZ header)
    uint32(0) == 0x464C457F and $s1    // ELF file

// String location
condition:
    $s1 at 0                            // String at offset 0
    $s1 in (0..1024)                    // String within first 1KB

// Imports (PE files, requires pe module)
import "pe"
condition:
    pe.imports("kernel32.dll", "VirtualAlloc") and
    pe.imports("kernel32.dll", "WriteProcessMemory")
```

### Running YARA

```bash
# YARA
# https://virustotal.github.io/yara/

# Scan a single file
yara rules.yar suspect_file.exe

# Scan a directory recursively
yara -r rules.yar /evidence/malware/

# Scan with multiple rule files
yara -r rules1.yar rules2.yar /evidence/

# Show matching strings
yara -s rules.yar suspect_file.exe

# Show metadata
yara -m rules.yar suspect_file.exe

# Scan a running process by PID
yara rules.yar 1234

# Set timeout (seconds)
yara -a 60 rules.yar /evidence/

# Negate — show files that DON'T match
yara -n rules.yar /evidence/
```

### Example YARA Rules for Threat Detection

```text
rule Cobalt_Strike_Beacon
{
    meta:
        description = "Detects Cobalt Strike beacon indicators"
        severity = "critical"
    strings:
        $s1 = "%s as %s\\%s: %d" ascii
        $s2 = "beacon.dll" ascii
        $s3 = "ReflectiveLoader" ascii
        $pipe = "\\\\.\\pipe\\msagent_" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Webshell_Generic
{
    meta:
        description = "Detects common web shell patterns"
        severity = "high"
    strings:
        $php1 = "<?php eval(" ascii nocase
        $php2 = "<?php assert(" ascii nocase
        $php3 = "<?php system(" ascii nocase
        $asp1 = "<%eval request" ascii nocase
        $jsp1 = "Runtime.getRuntime().exec" ascii
    condition:
        filesize < 100KB and any of them
}

rule Suspicious_PE_Imports
{
    meta:
        description = "PE with process injection imports"
        severity = "medium"
    condition:
        uint16(0) == 0x5A4D and
        pe.imports("kernel32.dll", "VirtualAllocEx") and
        pe.imports("kernel32.dll", "WriteProcessMemory") and
        pe.imports("kernel32.dll", "CreateRemoteThread")
}
```

## References

### Tools

- [Sigma (SigmaHQ)](https://github.com/SigmaHQ/sigma)
- [sigma-cli](https://github.com/SigmaHQ/sigma-cli)
- [YARA](https://virustotal.github.io/yara/)

### Further Reading

- [Sigma Rule Specification](https://sigmahq.io/docs/basics/rules.html)
- [YARA Documentation](https://yara.readthedocs.io/en/stable/)

> **Note:** YARA rules can produce false positives when deployed broadly. Document tuning decisions, test against known-clean samples, and scope rule execution to relevant file paths where possible.
