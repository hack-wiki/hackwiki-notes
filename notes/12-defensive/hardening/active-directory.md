% Filename: 12-defensive/hardening/active-directory.md
% Display name: Active Directory Hardening
% Last update: 2026-02-11
% Authors: @TristanInSec

# Active Directory Hardening

## Overview

Active Directory (AD) is the most targeted infrastructure in enterprise
networks. Hardening AD involves implementing tiered administration,
protecting privileged accounts, securing Kerberos authentication, restricting
lateral movement paths, and monitoring for configuration drift. This file
covers practical AD hardening measures aligned with Microsoft's recommended
practices.

## Tiered Administration Model

```text
Microsoft's tier model separates administrative privileges by asset sensitivity:

Tier 0 — Domain Controllers, AD infrastructure, PKI
  - Only Tier 0 admins can log into Tier 0 assets
  - Separate admin accounts, dedicated admin workstations (PAWs)
  - No internet access from Tier 0 systems

Tier 1 — Member servers, applications
  - Server admins manage servers but cannot access DCs
  - Separate admin accounts from daily-use accounts

Tier 2 — Workstations, user devices
  - Helpdesk and workstation admins
  - Cannot elevate to Tier 1 or Tier 0

Key principle: Higher-tier credentials never touch lower-tier systems.
  If a Tier 0 admin logs into a workstation, their credential hash
  is exposed to workstation-level attacks.
```

## Privileged Account Protection

```text
Separate admin accounts:
  - Daily-use account: jsmith (no admin rights)
  - Server admin: jsmith-t1 (Tier 1 admin)
  - Domain admin: jsmith-t0 (Tier 0 admin, used only on PAWs)

Protected Users group:
  - Add all privileged accounts to Protected Users security group
  - Enforces: no NTLM, no DES/RC4, no delegation, no credential caching
  - Kerberos TGT lifetime reduced to 4 hours

AdminSDHolder:
  - Protects privileged groups (Domain Admins, Enterprise Admins, etc.)
  - Runs every 60 minutes, resets ACLs on protected objects
  - Monitor for unauthorized changes to AdminSDHolder ACL

Managed Service Accounts (gMSA):
  - Use Group Managed Service Accounts for service accounts
  - Passwords automatically rotated (240-byte, auto-generated)
  - Eliminates static service account passwords
  - Create: New-ADServiceAccount -Name svc_sql -DNSHostName svc_sql.domain.com
```

## Kerberos Hardening

```text
Disable RC4 encryption:
  Computer Configuration → Windows Settings → Security Settings →
    Local Policies → Security Options:
  Network security: Configure encryption types allowed for Kerberos
    → Enable AES128 and AES256 only

Enforce AES for service accounts:
  Set-ADUser -Identity svc_account -KerberosEncryptionType AES128,AES256
  (prevents Kerberoasting with weak encryption)

Kerberos ticket lifetime:
  Default Domain Policy → Computer Configuration → Windows Settings →
    Security Settings → Account Policies → Kerberos Policy:
  Maximum lifetime for user ticket:    10 hours
  Maximum lifetime for service ticket: 600 minutes
  Maximum lifetime for user ticket renewal: 7 days

Kerberos delegation restrictions:
  - Set sensitive accounts to "Account is sensitive and cannot be delegated"
  - Use constrained delegation instead of unconstrained where possible
  - Use Resource-Based Constrained Delegation (RBCD) for new deployments
  - Monitor for delegation changes: Event ID 4742

Disable pre-authentication:
  - Ensure all accounts have Kerberos pre-authentication enabled
  - Accounts without pre-auth are vulnerable to AS-REP roasting
  - Audit: Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}
```

## LDAP and NTLM Hardening

```text
Require LDAP signing:
  Domain controller policy:
    HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters
    LDAPServerIntegrity = 2 (Require signing)

Require LDAP channel binding:
  HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters
    LdapEnforceChannelBinding = 2 (Always)

Restrict NTLM:
  Computer Configuration → Windows Settings → Security Settings →
    Local Policies → Security Options:
  Network security: Restrict NTLM: NTLM authentication in this domain
    → Deny all accounts (or Deny all domain accounts)
  Network security: Restrict NTLM: Audit NTLM authentication
    → Enable all (audit first before blocking)

Disable LM and NTLMv1:
  Network security: LAN Manager authentication level
    → Send NTLMv2 response only. Refuse LM & NTLM
```

## GPO Security

```text
Restrict GPO editing:
  - Only Domain Admins and designated GPO administrators
  - Audit GPO changes: Event IDs 5136, 5137, 5141

Restrict who can link GPOs:
  - Delegate GP Link permission sparingly
  - Monitor unexpected GPO links

Block inheritance cautiously:
  - Document any OUs with inheritance blocked
  - Regularly audit for unauthorized blocks

Audit sensitive GPO settings:
  - Password policies, user rights assignments
  - Software restriction policies / AppLocker
  - Startup/logon scripts (common persistence mechanism)
```

## Lateral Movement Restrictions

```text
Local Administrator Password Solution (LAPS):
  - Automatically rotate local admin passwords on domain-joined machines
  - Unique password per machine, stored in AD
  - Prevents pass-the-hash with shared local admin credentials

Deny network logon for local accounts:
  GPO: Deny access to this computer from the network
    → Add "Local account and member of Administrators group"
  (SID: S-1-5-114)
  Prevents local admin credentials from being used for lateral movement

Restrict RDP access:
  - GPO: Allow log on through Remote Desktop Services
    → Only specific admin groups, not Domain Admins
  - Use Remote Credential Guard to protect credentials during RDP

Disable WDigest:
  HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest
    UseLogonCredential = 0 (DWORD)
  Prevents plaintext credentials in memory
```

## Monitoring and Detection

```text
Critical events to monitor:

Authentication:
  4768 — Kerberos TGT request (AS-REP roasting if RC4)
  4769 — Kerberos service ticket (Kerberoasting if RC4)
  4771 — Kerberos pre-auth failure (password spray)
  4776 — NTLM credential validation

Privileged actions:
  4672 — Special privileges assigned (admin logon)
  4728 — Member added to privileged global group
  4732 — Member added to privileged local group
  4756 — Member added to universal group

Directory changes:
  5136 — Directory object modified
  5137 — Directory object created
  5141 — Directory object deleted
  4662 — Operation performed on AD object
         (monitor for DCSync: DS-Replication-Get-Changes)

GPO changes:
  4739 — Domain Policy changed
  5136 — GPO modified (Directory Service Changes audit)
```

## References

### Further Reading

- [Microsoft Securing Privileged Access](https://learn.microsoft.com/en-us/security/privileged-access-workstations/overview)
- [CIS Benchmarks (Active Directory)](https://www.cisecurity.org/cis-benchmarks)
