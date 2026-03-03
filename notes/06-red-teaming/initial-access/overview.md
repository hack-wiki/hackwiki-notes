% Filename: 06-red-teaming/initial-access/overview.md
% Display name: Initial Access & Payloads
% Last update: 2026-02-11
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# Initial Access & Payloads

## Overview

Initial access is the first foothold into the target environment. Red teams craft payloads that bypass security controls, deliver them through phishing or other vectors, and establish a C2 callback. Payload development requires understanding AV/EDR detection mechanisms and using techniques like shellcode loaders, obfuscation, and code signing to evade them.

## Topics in This Section

- [Payload Generation](payload-generation.md)
- [Shellcode Loaders](shellcode-loaders.md)
- [Binary Signing](binary-signing.md)

## General Approach

1. **Generate shellcode** — msfvenom, C2 framework, or custom
2. **Build a loader** — wrap shellcode in an evasive delivery mechanism
3. **Obfuscate and sign** — bypass static detection and reputation checks
4. **Test against target's AV/EDR** — verify evasion in a lab before deployment
5. **Deliver** — phishing, web exploit, physical access, or other vector
