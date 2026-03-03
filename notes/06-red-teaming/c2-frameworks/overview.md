% Filename: 06-red-teaming/c2-frameworks/overview.md
% Display name: C2 Frameworks Overview
% Last update: 2026-02-11
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# C2 Frameworks

## Overview

Command and Control (C2) frameworks provide the infrastructure to manage implants on compromised hosts. They handle payload generation, encrypted communications, task management, and post-exploitation. The choice of C2 framework depends on the engagement requirements — stealth, collaboration, agent capabilities, and evasion features.

## Topics in This Section

- [Sliver](sliver.md)
- [Havoc](havoc.md)
- [Mythic](mythic.md)
- [Cobalt Strike](cobalt-strike.md)

## Framework Comparison

```text
Framework       License       Language   Agents           C2 Channels              Collaboration
──────────────  ────────────  ─────────  ───────────────  ───────────────────────  ─────────────
Sliver          Open source   Go         Go (cross-plat)  mTLS, HTTP/S, DNS, WG    Multi-operator
Havoc           Open source   C/C++/Go   C (Windows)      HTTP/S, SMB, Ext C2      Multi-operator
Mythic          Open source   Go/Docker  Modular (many)   HTTP/S, DNS, WS, etc.    Multi-operator
Cobalt Strike   Commercial    Java       C (Windows)      HTTP/S, DNS, SMB, TCP    Multi-operator
```
