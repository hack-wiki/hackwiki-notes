% Filename: 01-fundamentals/windows-basics/overview.md
% Display name: Windows Basics Overview
% Last update: 2026-02-11
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# Windows Basics

## Overview

Windows is the dominant operating system in enterprise environments, making it the primary target for penetration testing engagements. Understanding Windows architecture, command-line tools, and configuration systems is essential for enumeration, privilege escalation, lateral movement, and persistence. This section covers the core Windows concepts that security professionals encounter during engagements.

## Topics in This Section

- [Windows Architecture](architecture.md) — Kernel vs user mode, processes, security tokens, SIDs, services, NTFS, authentication, and networking fundamentals
- [CMD Basics](cmd-basics.md) — Command Prompt navigation, system enumeration, user and network commands, WMIC, file transfers, and batch scripting
- [PowerShell Introduction](powershell-intro.md) — Cmdlet structure, pipeline and objects, system enumeration, remote execution, execution policy bypasses, and file operations
- [Windows Registry](registry.md) — Registry structure, hive files, persistence keys, privilege escalation keys, credential storage, and forensic artifacts

## General Approach

When landing on a Windows target:

1. **Identify context** — `whoami /all` to determine user, groups, privileges, and integrity level
2. **Enumerate the system** — OS version, patches, architecture, domain membership
3. **Map users and groups** — local admins, domain membership, service accounts
4. **Check network position** — interfaces, connections, shares, domain controllers
5. **Hunt for credentials** — registry autologon, cached credentials, config files, Credential Manager
6. **Assess services and tasks** — unquoted paths, weak permissions, scheduled tasks
