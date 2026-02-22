% Filename: 12-defensive/hardening/windows.md
% Display name: Windows Hardening
% Last update: 2026-02-11
% Authors: @TristanInSec

# Windows Hardening

## Overview

Windows hardening focuses on reducing the attack surface through Group Policy
configuration, enabling security features like Credential Guard and ASR rules,
configuring audit policies, restricting administrative access, and ensuring
endpoint protection is properly deployed. This file covers key hardening
measures for Windows workstations and servers.

## Attack Surface Reduction (ASR) Rules

ASR rules in Microsoft Defender block specific behaviors commonly used by
malware and exploit frameworks.

```text
Enable via Group Policy:
  Computer Configuration → Administrative Templates → Windows Components →
    Microsoft Defender Antivirus → Microsoft Defender Exploit Guard →
      Attack Surface Reduction

Key ASR rules (set to Block or Audit):

Block executable content from email and webmail
  GUID: be9ba2d9-53ea-4cdc-84e5-9b1eeee46550

Block all Office applications from creating child processes
  GUID: d4f940ab-401b-4efc-aadc-ad5f3c50688a

Block Office applications from injecting code into other processes
  GUID: 75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84

Block JavaScript or VBScript from launching downloaded executable content
  GUID: d3e037e1-3eb8-44c8-a917-57927947596d

Block execution of potentially obfuscated scripts
  GUID: 5beb7efe-fd9a-4556-801d-275e5ffc04cc

Block Win32 API calls from Office macros
  GUID: 92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b

Block credential stealing from LSASS
  GUID: 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2

Block process creations from WMI and PSExec commands
  GUID: d1e49aac-8f56-4280-b9ba-993a6d77406c
```

## Credential Protection

```text
Credential Guard (enterprise editions):
  Uses virtualization-based security (VBS) to isolate LSASS
  Prevents credential dumping via Mimikatz-style attacks

  Enable via Group Policy:
    Computer Configuration → Administrative Templates → System →
      Device Guard → Turn On Virtualization Based Security
      → Enable Credential Guard: Enabled with UEFI lock

LSA Protection (RunAsPPL):
  Registry: HKLM\SYSTEM\CurrentControlSet\Control\Lsa
  Value: RunAsPPL = 1 (DWORD)
  Prevents unauthorized processes from accessing LSASS

Remote Credential Guard:
  Protects credentials during RDP sessions
  Prevents credentials from being sent to the remote host
  Enable: mstsc.exe /remoteGuard
```

## Windows Defender Configuration

```text
Group Policy hardening for Windows Defender:

Computer Configuration → Administrative Templates → Windows Components →
  Microsoft Defender Antivirus:

  Turn on real-time protection → Enabled
  Turn on behavior monitoring → Enabled
  Scan all downloaded files and attachments → Enabled
  Configure removal of items from Quarantine folder → Never

  Real-time Protection:
    Turn on process scanning → Enabled
    Monitor file and program activity → Enabled

  MpPreference settings (PowerShell):
    Set-MpPreference -DisableRealtimeMonitoring $false
    Set-MpPreference -MAPSReporting Advanced
    Set-MpPreference -SubmitSamplesConsent SendAllSamples
    Set-MpPreference -PUAProtection Enabled
```

## Group Policy Hardening

### Account Policies

```text
Computer Configuration → Windows Settings → Security Settings →
  Account Policies:

Password Policy:
  Minimum password length:              14 characters
  Password must meet complexity:        Enabled
  Maximum password age:                 60 days
  Minimum password age:                 1 day
  Enforce password history:             24 passwords
  Store passwords using reversible:     Disabled

Account Lockout Policy:
  Account lockout threshold:            5 invalid attempts
  Account lockout duration:             30 minutes
  Reset account lockout counter:        30 minutes
```

### User Rights Assignment

```text
Computer Configuration → Windows Settings → Security Settings →
  Local Policies → User Rights Assignment:

Deny access to this computer from the network:
  → Local account and member of Administrators group (for workstations)

Deny log on through Remote Desktop Services:
  → Local account (force domain authentication)

Debug programs:
  → No one (remove all, prevents SeDebugPrivilege abuse)

Access this computer from the network:
  → Only required accounts/groups
```

### Security Options

```text
Computer Configuration → Windows Settings → Security Settings →
  Local Policies → Security Options:

Accounts: Rename administrator account → custom name
Accounts: Rename guest account → custom name
Accounts: Guest account status → Disabled

Interactive logon: Do not display last user name → Enabled
Interactive logon: Machine inactivity limit → 900 seconds

Network access: Do not allow anonymous enumeration of SAM accounts → Enabled
Network access: Do not allow anonymous enumeration of SAM accounts and shares → Enabled
Network access: Restrict anonymous access to Named Pipes and Shares → Enabled

Network security: LAN Manager authentication level → Send NTLMv2 response only. Refuse LM & NTLM
Network security: Minimum session security for NTLM SSP → Require NTLMv2, require 128-bit
```

## PowerShell Security

```text
Constrained Language Mode:
  Limits PowerShell to core types and approved cmdlets
  Enable via AppLocker policy or __PSLockdownPolicy variable

Script execution policy:
  Set-ExecutionPolicy AllSigned (require signed scripts)

PowerShell logging (detection, not prevention):
  See detection/windows-logs.md for logging configuration

PowerShell v2 removal (prevents downgrade attacks):
  Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root
```

## Windows Firewall

```text
Windows Defender Firewall with Advanced Security:

Default policy:
  Inbound: Block
  Outbound: Allow (or Block with explicit rules for better control)

Key rules:
  - Allow inbound RDP only from management network
  - Allow inbound SMB only from file server subnet
  - Block inbound NetBIOS (ports 137-139) from untrusted networks
  - Block inbound WinRM (5985/5986) except from management hosts
  - Log dropped connections

Firewall profile settings:
  Domain:  Firewall On, Block Inbound, Allow Outbound
  Private: Firewall On, Block Inbound, Allow Outbound
  Public:  Firewall On, Block Inbound, Block Outbound
```

## SMB Hardening

```text
Disable SMBv1:
  Set-SmbServerConfiguration -EnableSMB1Protocol $false
  Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

Require SMB signing:
  Computer Configuration → Windows Settings → Security Settings →
    Local Policies → Security Options:
  Microsoft network server: Digitally sign communications (always) → Enabled
  Microsoft network client: Digitally sign communications (always) → Enabled

Require SMB encryption (SMB 3.0+):
  Set-SmbServerConfiguration -EncryptData $true
```

## References

### Further Reading

- [CIS Benchmarks (Windows)](https://www.cisecurity.org/cis-benchmarks)
- [Microsoft Security Baselines](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines)
