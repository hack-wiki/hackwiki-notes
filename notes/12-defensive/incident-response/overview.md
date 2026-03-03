% Filename: 12-defensive/incident-response/overview.md
% Display name: IR Overview
% Last update: 2026-02-11
% Authors: @TristanInSec

# Incident Response

## Overview

Incident response (IR) is the structured process for detecting, containing,
and recovering from security incidents. This section follows the SANS PICERL
incident response lifecycle: preparation, identification, containment,
eradication, recovery, and lessons learned. Two common incident types —
ransomware and phishing — are covered with dedicated playbooks.

## Topics

- [IR Preparation](01-preparation.md) — building an IR program, team structure,
  playbooks, communication plans, and tooling
- [Identification](02-identification.md) — detecting incidents, initial triage,
  scoping, and evidence preservation
- [Containment](03-containment.md) — short-term and long-term containment
  strategies for hosts, accounts, and networks
- [Eradication](04-eradication.md) — removing threat actor access, cleaning
  persistence, and verifying elimination
- [Recovery](05-recovery.md) — restoring systems, validating integrity,
  monitoring for reinfection, and lessons learned
- [Ransomware Response](ransomware.md) — ransomware-specific playbook
  covering detection, containment, decryption, and recovery
- [Phishing Incident Response](phishing-ir.md) — phishing-specific playbook
  covering email analysis, credential reset, and user notification

## SANS PICERL Incident Response Lifecycle

```text
┌─────────────┐    ┌────────────────┐    ┌──────────────┐    ┌──────────────┐
│ Preparation │───>│ Identification │───>│ Containment  │───>│ Eradication  │
└─────────────┘    └────────────────┘    └──────────────┘    └──────────────┘
                                                                     │
                  ┌─────────────────┐    ┌──────────────┐            │
                  │ Lessons Learned │<───│   Recovery   │<───────────┘
                  └─────────────────┘    └──────────────┘
```
