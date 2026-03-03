% Filename: 13-programming/bash/overview.md
% Display name: Bash Scripting
% Last update: 2026-02-11
% Authors: @TristanInSec

# Bash Scripting

## Overview

Bash is the default shell on most Linux distributions and the primary
scripting language for system administration, automation, and security
tooling on Unix systems. Understanding Bash is essential for writing
enumeration scripts, automating tool chains, parsing output, and building
quick one-liners during engagements.

## Topics

- [Bash Script Writing](scripting.md) — variables, control flow, functions,
  arrays, file operations, and script structure for security automation
- [Useful One-Liners](one-liners.md) — practical one-liners for
  reconnaissance, enumeration, file operations, network tasks, and log
  analysis

## Quick Reference

```text
Bash basics:
  bash script.sh       — run a script
  chmod +x script.sh   — make executable
  ./script.sh          — run directly
  bash -x script.sh    — debug mode (trace execution)
  bash -n script.sh    — syntax check without executing

Shebang lines:
  #!/usr/bin/env bash  — portable (recommended)
  #!/bin/bash          — explicit path
```
