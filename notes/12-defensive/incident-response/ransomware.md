% Filename: 12-defensive/incident-response/ransomware.md
% Display name: Ransomware Response
% Last update: 2026-02-11
% Authors: @TristanInSec

# Ransomware Response

## Overview

Ransomware incidents require rapid, coordinated response to limit encryption
spread, preserve evidence, and restore operations. Modern ransomware groups
often exfiltrate data before encryption (double extortion), making containment
speed critical. This playbook covers the end-to-end ransomware response
process from initial detection through recovery.

## Detection Indicators

```text
Signs of active ransomware:

Endpoint indicators:
  - Mass file renaming (new extensions: .locked, .encrypted, .crypt)
  - Ransom note files appearing (README.txt, DECRYPT-FILES.html)
  - High CPU/disk usage (encryption in progress)
  - Shadow copies being deleted (vssadmin, wmic)
  - Security software being disabled or killed

Network indicators:
  - Lateral movement (SMB, RDP, WMI across multiple hosts)
  - C2 communication to known ransomware infrastructure
  - Large data transfers outbound (pre-encryption exfiltration)
  - Scanning activity from compromised hosts

Log indicators:
  - Event ID 7045 — new service installed (ransomware executable)
  - Event ID 4688 — suspicious process creation (cmd, PowerShell, wmic)
  - Event ID 4624 LogonType 3 — network logons from unexpected sources
  - Sysmon Event ID 11 — mass file creation
  - Volume Shadow Copy Service event — shadow copies deleted
```

## Immediate Response (First 30 Minutes)

```text
1. Isolate affected systems
   - Disconnect from network immediately (pull cable or disable NIC)
   - Do NOT shut down (preserves memory and encryption state)
   - Block lateral movement: disable SMB, RDP, WMI between hosts
   - Disable shared drives and network shares

2. Identify the ransomware variant
   - Check ransom note for variant name
   - Upload encrypted file sample to ID Ransomware (id-ransomware.malwarehunterteam.com)
   - Check No More Ransom for available decryptors (nomoreransom.org)
   - Preserve ransom note and encrypted samples

3. Assess the scope
   - How many systems are encrypted?
   - Is encryption still in progress?
   - Are backups affected?
   - Has data been exfiltrated?

4. Preserve evidence
   - Capture memory from affected systems
   - Preserve ransom notes and encrypted file samples
   - Screenshot any ransom portal or communication
   - Save all relevant logs immediately
```

## Containment

```text
Network containment:
  - Block all SMB (445) traffic between hosts
  - Block known C2 IPs and domains at firewall
  - Disable WMI and PowerShell remoting
  - Isolate affected network segments
  - Block RDP (3389) except from jump servers

Credential containment:
  - Reset passwords for all compromised accounts
  - Reset krbtgt password if domain compromise suspected (twice)
  - Disable service accounts used for lateral movement
  - Reset local administrator passwords (LAPS rotation)

Backup protection:
  - Verify backup integrity before the incident timeline
  - Disconnect backup systems from the network
  - Test restore from offline/immutable backups
  - Do NOT connect backup media to compromised systems
```

## Investigation

```text
Determine:

1. Initial access vector
   - Phishing email with malicious attachment?
   - Exploited public-facing service (VPN, RDP)?
   - Supply chain compromise?
   - Compromised credentials (leaked/brute-forced)?

2. Attacker dwell time
   - When did initial access occur?
   - What did the attacker do before deploying ransomware?
   - Were tools like Cobalt Strike, Mimikatz used?

3. Data exfiltration
   - Was data stolen before encryption?
   - What data was accessed?
   - Where was it sent?
   - Check network logs for large outbound transfers

4. Encryption scope
   - Which systems are fully encrypted?
   - Which systems are partially encrypted (encryption interrupted)?
   - Are domain controllers compromised?
   - Are backup servers encrypted?
```

## Recovery Decision Tree

```text
Can you restore from backups?
  │
  ├─ YES: Backups are clean and recent
  │   → Rebuild from backups (see restoration process below)
  │
  ├─ PARTIAL: Backups exist but are old or incomplete
  │   → Restore what you can, accept some data loss
  │   → Check No More Ransom for decryptors
  │
  └─ NO: No usable backups
      │
      ├─ Decryptor available (No More Ransom, vendor)
      │   → Use free decryptor
      │
      └─ No decryptor available
          → Consult legal and executive team
          → Preserve encrypted drives (decryptors may be released later)
          → Rebuild systems from scratch
          → Consider data loss implications
```

## Restoration Process

```text
1. Validate backup integrity
   - Verify backups were created before the compromise
   - Scan backup media with YARA/AV before restoring
   - Test restore in isolated environment first

2. Rebuild infrastructure
   - Start with domain controllers (if compromised, rebuild from scratch)
   - Restore DNS, DHCP, authentication services
   - Apply all patches including the exploited vulnerability
   - Harden per security baseline before reconnecting

3. Restore data
   - Restore from most recent clean backup
   - Verify restored data integrity
   - Apply incremental changes manually if needed

4. Enhanced monitoring
   - Deploy EDR on all rebuilt systems
   - Add IDS rules for the specific ransomware variant
   - Monitor for C2 beaconing and lateral movement
   - Watch for re-encryption attempts
```

## Ransom Payment Considerations

```text
Factors to evaluate (NOT a recommendation to pay):

Legal:
  - Some jurisdictions restrict ransom payments
  - OFAC sanctions: paying certain groups violates US law
  - Legal counsel must be involved in any payment decision
  - Law enforcement should be notified

Practical:
  - Payment does NOT guarantee decryption
  - Decryption tools from attackers may be buggy or slow
  - Paying encourages further attacks
  - Paying may fund additional criminal activity

If considering payment:
  - Engage professional ransomware negotiators
  - Verify proof of decryption (test file)
  - Negotiate timeline and terms
  - Plan for decryption to be slow and error-prone
  - Continue rebuilding in parallel regardless
```

## References

### Further Reading

- [CISA Ransomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide)
- [No More Ransom Project](https://www.nomoreransom.org/)
