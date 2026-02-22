% Filename: 12-defensive/hardening/overview.md
% Display name: System Hardening
% Last update: 2026-02-11
% Authors: @TristanInSec

# System Hardening

## Overview

System hardening reduces the attack surface by disabling unnecessary services,
applying secure configurations, enforcing least privilege, and enabling
security controls. Hardening should be applied at every layer — operating
systems, applications, network infrastructure, and directory services.

## Topics

- [Linux Hardening](linux.md) — kernel parameters, service management,
  filesystem permissions, AppArmor, auditd, and SSH hardening
- [Windows Hardening](windows.md) — Group Policy, Windows Defender settings,
  credential protection, audit policies, and attack surface reduction
- [Active Directory Hardening](active-directory.md) — tiered administration,
  privileged access management, Kerberos hardening, and GPO security
- [Network Hardening](network.md) — firewall configuration, network
  segmentation, TLS enforcement, DNS security, and wireless hardening

## Hardening Principles

```text
1. Minimize attack surface  → Remove unused software, disable unused services
2. Least privilege          → Users and services run with minimum permissions
3. Defense in depth         → Multiple overlapping controls at every layer
4. Secure defaults          → Change default passwords, disable default accounts
5. Audit and monitor        → Log security events, detect configuration drift
6. Patch management         → Apply security updates promptly
```
