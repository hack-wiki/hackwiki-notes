% Filename: 06-red-teaming/evasion/overview.md
% Display name: Defense Evasion
% Last update: 2026-02-11
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# Defense Evasion

## Overview

Defense evasion encompasses techniques that red teams use to avoid detection by AV, EDR, application controls, and logging mechanisms. This section covers bypassing specific Windows security features (AMSI, AppLocker, ETW), evading endpoint detection products, process injection techniques, payload obfuscation, and leveraging built-in Windows utilities (LOLBins) to blend in with normal activity.

## Topics in This Section

- [AMSI Bypass](amsi-bypass.md)
- [AppLocker Bypass](applocker-bypass.md)
- [AV/EDR Bypass](av-edr-bypass.md)
- [ETW Bypass](etw-bypass.md)
- [Process Injection](process-injection.md)
- [Obfuscation](obfuscation.md)
- [Windows LOLBins](windows-lolbins.md)

## General Approach

1. **Identify defenses** — determine what AV/EDR, application controls, and logging are in place
2. **Bypass security features** — disable or evade AMSI, ETW, AppLocker as needed
3. **Obfuscate payloads** — transform code to avoid static signatures
4. **Use living-off-the-land techniques** — leverage trusted OS binaries for execution
5. **Test in a lab** — validate evasion against the target's specific security stack before deployment
