% Filename: 12-defensive/incident-response/04-eradication.md
% Display name: Step 4 - Eradication
% Last update: 2026-02-19
% Authors: @TristanInSec

# Eradication

## Overview

Eradication removes the threat actor's access, tools, and persistence
mechanisms from the environment. This phase should only begin after
containment is established and the scope of the compromise is understood.
Premature eradication (before full scoping) risks alerting the attacker,
who may activate backup access or accelerate destructive actions.

## Eradication Planning

```text
Before beginning eradication:

1. Confirm containment is effective
   - Attacker cannot reach C2 infrastructure
   - Lateral movement is blocked
   - No active exfiltration occurring

2. Complete scope assessment
   - All compromised systems identified
   - All compromised accounts identified
   - All persistence mechanisms cataloged
   - Timeline of attacker activity established

3. Plan coordinated removal
   - Eradicate all persistence simultaneously
   - If done piecemeal, attacker may notice and deploy new persistence
   - Schedule eradication during a maintenance window if possible

4. Prepare for re-entry attempts
   - Enhanced monitoring during and after eradication
   - IDS rules for known attacker TTPs
   - Additional logging on previously compromised systems
```

## Persistence Removal

### Windows Persistence

```text
Check and remove:

Registry Run keys:
  HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
  HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
  HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce

Scheduled tasks:
  schtasks /query /fo TABLE /v
  Remove: schtasks /delete /tn "TaskName" /f

Services:
  sc query type= all state= all
  Remove: sc delete "ServiceName"

WMI event subscriptions:
  Get-CimInstance -Namespace root\Subscription -ClassName __EventFilter
  Get-CimInstance -Namespace root\Subscription -ClassName CommandLineEventConsumer
  Get-CimInstance -Namespace root\Subscription -ClassName __FilterToConsumerBinding

Startup folders:
  C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\
  C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\

DLL hijacking / side-loading:
  Check for unauthorized DLLs in system directories
  Compare hashes against known-good baselines

COM object hijacking:
  Check HKCU\SOFTWARE\Classes\CLSID for unexpected entries
```

### Linux Persistence

```text
Check and remove:

Crontabs:
  /var/spool/cron/crontabs/*
  /etc/cron.d/*
  /etc/crontab

Systemd services:
  /etc/systemd/system/*.service
  ~/.config/systemd/user/*.service
  systemctl list-unit-files --type=service

Shell profiles:
  /etc/profile, /etc/profile.d/*.sh
  ~/.bashrc, ~/.bash_profile, ~/.profile, ~/.zshrc

SSH authorized_keys:
  ~/.ssh/authorized_keys (all users and root)

LD_PRELOAD:
  /etc/ld.so.preload
  /etc/environment (LD_PRELOAD variable)

Kernel modules:
  lsmod — compare against known-good baseline
  /etc/modules-load.d/

Init scripts:
  /etc/init.d/
  /etc/rc.local
```

## Malware Removal

```text
For each compromised system:

1. Identify all malicious files
   - YARA scan across the filesystem
   - Check common staging directories (/tmp, C:\Users\Public, etc.)
   - Compare file hashes against IOC list

2. Remove malicious files
   - Delete malware binaries, scripts, web shells
   - Remove attacker tools (Mimikatz, Cobalt Strike, etc.)
   - Clean injected code from legitimate files

3. Verify removal
   - Re-scan with YARA and antivirus
   - Check process listing for unexpected processes
   - Verify network connections are clean

4. Consider rebuilding
   - For heavily compromised systems, rebuild from scratch
   - Reinstall OS from known-good media
   - Restore data from pre-compromise backups
   - Rebuilding is more reliable than surgical cleaning
```

## Account Remediation

```text
For compromised accounts:

1. Reset all compromised passwords
   - Use strong, unique passwords
   - Reset via out-of-band method if possible

2. Revoke all sessions and tokens
   - Azure/O365: Revoke-MgUserSignInSession -UserId <id>  (Microsoft Graph SDK; AzureAD module deprecated 2024)
   - AWS: Rotate access keys, invalidate temporary credentials
   - On-premises: Reset Kerberos ticket (krbtgt if domain compromise)

3. Re-enroll MFA
   - Reset MFA registration for affected users
   - Verify MFA device is legitimate

4. Audit account permissions
   - Remove any unauthorized group memberships
   - Remove delegated access and app consents
   - Check mail forwarding rules and inbox rules

5. For domain compromise (worst case):
   - Reset krbtgt password TWICE (waiting for replication between resets)
   - Reset all domain admin passwords
   - Reset all service account passwords
   - Rebuild domain controllers from scratch if needed
```

## Verification

```text
Confirm eradication is complete:

1. Full system scan
   - YARA scan, AV scan, rootkit check
   - No known IOCs present

2. Network monitoring
   - No C2 communication
   - No suspicious outbound connections
   - No lateral movement detected

3. Log review
   - No new alerts related to the incident
   - Authentication logs show only legitimate activity
   - No unauthorized processes or services

4. Baseline comparison
   - Compare system state to known-good baseline
   - Verify file integrity (AIDE, Tripwire)
   - Verify registry state (Windows)

5. Wait and watch period
   - Monitor intensively for 48-72 hours after eradication
   - Watch for attacker re-entry via backup persistence
```

## References

### Further Reading

- [NIST SP 800-61: Computer Security Incident Handling Guide](https://csrc.nist.gov/pubs/sp/800/61/r2/final)

> **Note:** YARA rules can produce false positives. Tune and scope rules before use in production eradication workflows; a false positive may cause unnecessary system disruption.
