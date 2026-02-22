% Filename: 13-programming/powershell/overview.md
% Display name: PowerShell for Security
% Last update: 2026-02-11
% Authors: @TristanInSec

# PowerShell for Security

## Overview

PowerShell is the primary scripting language for Windows administration and
a critical tool for both offensive and defensive security operations. It
provides deep integration with Windows APIs, Active Directory, WMI, and
.NET, making it essential for post-exploitation, enumeration, and security
automation. PowerShell Core (pwsh) also runs on Linux and macOS.

## Topics

- [PowerShell Fundamentals](fundamentals.md) — syntax, variables, operators,
  control flow, functions, modules, and working with objects
- [Offensive PowerShell](offensive.md) — enumeration, credential handling,
  lateral movement, file transfer, and common offensive techniques

## Quick Reference

```text
PowerShell on different platforms:
  powershell.exe       — Windows PowerShell (5.1, Windows only)
  pwsh                 — PowerShell Core (7.x, cross-platform)

Running scripts:
  pwsh script.ps1                     — run a script
  pwsh -Command "Get-Process"         — run a command
  pwsh -File script.ps1               — run a file
  pwsh -ExecutionPolicy Bypass -File script.ps1  — bypass execution policy

Getting help:
  Get-Help <cmdlet>                   — show help
  Get-Help <cmdlet> -Examples         — show examples
  Get-Command *process*               — find commands by name
  Get-Member                          — show object properties and methods
```
