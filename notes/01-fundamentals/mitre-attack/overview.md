% Filename: 01-fundamentals/mitre-attack/overview.md
% Display name: MITRE ATT&CK Framework
% Last update: 2026-02-19
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# MITRE ATT&CK Framework

## Overview

MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) is a knowledge base of adversary behavior based on real-world observations. It documents adversary behavior across the full attack lifecycle — including pre-compromise activities (Reconnaissance TA0043, Resource Development TA0042) and post-compromise actions (execution, persistence, lateral movement, and impact).

ATT&CK is the shared language between red teams, blue teams, threat intelligence analysts, and security leadership. Penetration testers use it to structure engagements and map findings. Defenders use it to identify detection gaps and prioritize security controls. Threat intelligence teams use it to describe adversary behavior consistently.

This section covers the framework's structure, how to read and navigate it, and how to use the ATT&CK Navigator for visualization.

## Topics in This Section

- [Tactics](tactics.md) — The 14 tactical objectives adversaries pursue, from reconnaissance through impact
- [Techniques](techniques.md) — How adversaries achieve tactical objectives, including sub-techniques and procedures
- [ATT&CK Navigator](navigator.md) — Visualizing ATT&CK coverage, creating threat-informed heat maps, and layering defensive assessments

## General Approach

ATT&CK is a reference framework, not a checklist. Use it to:

1. **Map findings during engagements** — tag every technique you use with its ATT&CK ID so reports speak a common language
2. **Identify detection gaps** — overlay your detection capabilities on the ATT&CK matrix to find blind spots
3. **Emulate threat actors** — use ATT&CK's threat group profiles to build realistic adversary emulation plans
4. **Prioritize defenses** — focus detection engineering on the techniques most commonly used by adversaries relevant to your organization
