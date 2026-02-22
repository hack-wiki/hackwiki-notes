% Filename: 12-defensive/incident-response/03-containment.md
% Display name: Step 3 - Containment
% Last update: 2026-02-11
% Authors: @TristanInSec

# Containment

## Overview

Containment limits the damage of an incident by preventing the attacker from
expanding access, exfiltrating more data, or causing further harm. Containment
must balance stopping the threat against preserving evidence and maintaining
business operations. Actions are divided into short-term (immediate response)
and long-term (sustained containment while investigation continues).

## Short-Term Containment

```text
Immediate actions to stop active damage (first 1-4 hours):

Network isolation:
  - Disconnect compromised hosts from the network
  - Block attacker IP addresses at the firewall
  - Disable switch ports for affected systems
  - Implement DNS sinkholing for C2 domains
  - Do NOT shut down systems (preserves memory evidence)

Account actions:
  - Disable compromised user accounts
  - Reset passwords for affected accounts
  - Revoke active sessions and tokens
  - Disable VPN access for compromised accounts
  - Do NOT delete accounts (preserves audit trail)

Endpoint actions:
  - Isolate endpoint via EDR (network quarantine)
  - Block malicious hashes at the endpoint protection level
  - Disable the compromised service/application
```

### Network Containment Commands

```bash
# Block an attacker IP at the firewall
sudo iptables -I INPUT -s 203.0.113.50 -j DROP
sudo iptables -I OUTPUT -d 203.0.113.50 -j DROP

# Block a C2 domain via DNS sinkhole
# Add to /etc/hosts or DNS server:
# 127.0.0.1 malicious-c2.example.com

# Isolate a VLAN at the switch (vendor-specific)
# Cisco: shutdown the interface or move to quarantine VLAN
# Linux bridge: ip link set br0 down

# Block outbound traffic on suspicious port
sudo iptables -I OUTPUT -p tcp --dport 4444 -j DROP
```

## Long-Term Containment

```text
Sustained containment while investigation continues:

System-level:
  - Build clean replacement systems from known-good images
  - Apply patches that address the exploitation vector
  - Implement additional monitoring on rebuilt systems
  - Redirect traffic from compromised systems to clean ones

Network-level:
  - Implement network segmentation if not already in place
  - Add IDS rules for known attacker TTPs
  - Increase logging verbosity on key systems
  - Monitor for attacker re-entry attempts

Account-level:
  - Force password resets for broader user populations
  - Enable MFA where not already enabled
  - Audit privileged group membership
  - Review service account permissions

Evidence preservation:
  - Create forensic images of contained systems
  - Capture memory dumps before any changes
  - Preserve all log files (local and centralized)
  - Document every containment action with timestamps
```

## Containment Strategies by Incident Type

### Malware / Ransomware

```text
1. Isolate infected hosts (network disconnect, NOT shutdown)
2. Block C2 communication (firewall rules, DNS sinkhole)
3. Identify and block lateral movement
4. Disable file shares to prevent encryption spread
5. Capture memory before containment actions modify state
6. Preserve encrypted files (may need for decryption later)
7. Do NOT pay ransom without legal/executive guidance
```

### Compromised Account

```text
1. Disable the compromised account immediately
2. Revoke all active sessions (cloud: revoke OAuth tokens)
3. Reset password and MFA enrollment
4. Check for persistence:
   - Mail forwarding rules
   - OAuth app consents
   - Delegated access
   - Mailbox rules
5. Review account activity logs for full scope
6. Check if credentials are reused on other systems
```

### Web Application Compromise

```text
1. Block attacker source IP at WAF/firewall
2. Take application offline if actively exploited
3. Identify and remove web shells
4. Check for backdoor accounts in application database
5. Preserve web server logs and application logs
6. Review code changes (check version control for unauthorized commits)
```

### Data Exfiltration

```text
1. Block the exfiltration channel (IP, domain, protocol)
2. Identify all systems the attacker accessed
3. Determine what data was accessed and exfiltrated
4. Preserve network traffic captures
5. Engage legal for regulatory notification requirements
6. Monitor for data appearing on paste sites / dark web
```

## Containment Decision Framework

| Factor | Aggressive Containment | Cautious Containment |
|---|---|---|
| Active data exfiltration | Immediately isolate | N/A — always act fast |
| Attacker still present | Isolate, then investigate | Monitor, then isolate |
| Evidence preservation | Capture memory first | Capture memory first |
| Business impact | Accept downtime | Minimize disruption |
| Legal requirements | Preserve everything | Preserve everything |

## References

### Further Reading

- [NIST SP 800-61: Computer Security Incident Handling Guide](https://csrc.nist.gov/pubs/sp/800/61/r2/final)
