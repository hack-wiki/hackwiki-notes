% Filename: 12-defensive/incident-response/05-recovery.md
% Display name: Step 5 - Recovery
% Last update: 2026-02-19
% Authors: @TristanInSec

# Recovery

## Overview

Recovery restores affected systems and services to normal operation after
eradication is complete. This phase includes system restoration, integrity
validation, enhanced monitoring for reinfection, and lessons learned
documentation. Recovery should be gradual, with close monitoring at each
stage to ensure the threat has been fully eliminated.

## System Restoration

```text
Restoration approaches (by reliability):

1. Rebuild from scratch (most reliable)
   - Reinstall OS from known-good media
   - Apply all patches and hardening
   - Restore data from pre-compromise backups
   - Reconfigure applications and services
   - Best for: servers, domain controllers, critical systems

2. Restore from backup (reliable if backups are verified)
   - Restore full system image from before compromise
   - Verify backup integrity (was the backup taken before compromise?)
   - Apply patches for the exploitation vector
   - Scan restored system before reconnecting to network
   - Best for: systems with well-tested backup processes

3. Clean and patch (least reliable)
   - Remove malware and persistence (eradication phase)
   - Patch vulnerability that was exploited
   - Run integrity checks
   - Best for: large numbers of workstations with limited compromise
```

## Restoration Order

```text
Restore systems in priority order:

Phase 1 — Infrastructure (first 24-48 hours):
  - Domain controllers and DNS servers
  - Authentication systems (RADIUS, LDAP)
  - Network infrastructure (firewalls, switches, VPN)
  - Certificate authorities

Phase 2 — Critical services (48-96 hours):
  - Email and communication systems
  - Databases and application servers
  - File servers
  - Backup systems (verify integrity first)

Phase 3 — Business applications (1-2 weeks):
  - Web applications
  - Business-specific applications
  - Development and test environments

Phase 4 — User systems (2-4 weeks):
  - Workstations (reimage or clean in batches)
  - Mobile devices (re-enroll)
  - VPN clients (reissue certificates if needed)
```

## Validation Before Reconnection

```text
Before reconnecting a restored system to the network:

1. Patch verification
   - All OS and application patches current
   - Vulnerability that was exploited is patched
   - Security software updated with latest signatures

2. Configuration verification
   - System hardened per security baseline
   - Unnecessary services disabled
   - Firewall rules applied
   - Audit logging enabled

3. Integrity check
   - AIDE / Tripwire baseline scan
   - YARA scan for known IOCs
   - Antivirus full scan
   - No unexpected processes, services, or connections

4. Credential reset
   - Local admin passwords changed (unique per system)
   - Service account passwords rotated
   - Certificates reissued if needed

5. Monitoring setup
   - Enhanced logging enabled
   - EDR agent installed and reporting
   - IDS signatures for attacker TTPs active
```

## Post-Recovery Monitoring

```text
Enhanced monitoring period (2-4 weeks after recovery):

Watch for:
  - Authentication from previously compromised accounts
  - Connections to known C2 infrastructure
  - Reappearance of IOCs (file hashes, registry keys, DNS queries)
  - Unexpected service installations or scheduled tasks
  - Unusual outbound traffic patterns
  - Privilege escalation attempts

Monitoring intensity:
  Week 1-2: 24/7 active monitoring with dedicated analysts
  Week 3-4: Enhanced alerting with reduced staffing
  After 4 weeks: Return to normal monitoring if no indicators
```

## Lessons Learned

```text
Conduct lessons learned meeting within 2 weeks of incident closure:

Participants:
  - IR team members
  - IT/security management
  - Affected business unit representatives
  - Legal (if applicable)

Questions to address:
  1. What happened? (timeline, root cause, impact)
  2. How was it detected? (could we have detected it sooner?)
  3. What went well in the response?
  4. What could be improved?
  5. Were playbooks and procedures adequate?
  6. Were tools and resources sufficient?
  7. How effective was communication?
  8. What preventive measures should be implemented?

Deliverables:
  - Incident report (executive summary + technical details)
  - Timeline of events
  - Root cause analysis
  - List of action items with owners and deadlines
  - Updated playbooks based on lessons learned
  - New detection rules for the TTPs observed
```

## Incident Documentation

```text
Final incident report should include:

Executive summary:
  - What happened (1-2 paragraphs)
  - Business impact (systems, data, cost)
  - Key actions taken
  - Current status

Technical details:
  - Complete timeline of attacker activity
  - Initial access vector
  - TTPs observed (mapped to MITRE ATT&CK)
  - IOCs (IPs, domains, hashes, file paths)
  - Systems and accounts compromised
  - Data accessed or exfiltrated

Response details:
  - Detection and identification timeline
  - Containment actions and effectiveness
  - Eradication steps
  - Recovery process
  - Total time from detection to recovery

Recommendations:
  - Preventive measures
  - Detection improvements
  - Process improvements
  - Training needs
```

## References

### Further Reading

- [NIST SP 800-61: Computer Security Incident Handling Guide](https://csrc.nist.gov/pubs/sp/800/61/r2/final)

> **Note:** YARA rules can produce false positives. Validate rules against known-clean baselines before using them in recovery verification scans.
