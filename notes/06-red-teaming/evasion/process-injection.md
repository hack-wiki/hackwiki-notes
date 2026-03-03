% Filename: 06-red-teaming/evasion/process-injection.md
% Display name: Process Injection
% Last update: 2026-02-11
% ATT&CK Tactics: TA0005 (Defense Evasion), TA0004 (Privilege Escalation)
% ATT&CK Techniques: T1055 (Process Injection)
% Authors: @TristanInSec

# Process Injection

## Overview

Process injection executes code within the address space of another process, allowing the attacker to hide within a legitimate process, inherit its security context and network access, and evade process-based detection rules. Different injection techniques vary in stealth, complexity, and compatibility. Choosing the right technique depends on the target process, EDR coverage, and required privileges.

## ATT&CK Mapping

- **Tactic:** TA0005 - Defense Evasion, TA0004 - Privilege Escalation
- **Technique:** T1055 - Process Injection

## Techniques

### Classic Remote Thread Injection (T1055)

```text
The simplest and most detected injection technique:

1. OpenProcess(PROCESS_ALL_ACCESS, targetPID)
2. VirtualAllocEx(hProcess, RWX memory)
3. WriteProcessMemory(hProcess, shellcode)
4. CreateRemoteThread(hProcess, shellcode address)

Detection:
  - EDR hooks all four API calls
  - Cross-process memory allocation is highly suspicious
  - CreateRemoteThread is a well-known indicator

Use case: Testing environments, CTFs, no EDR
```

### DLL Injection (T1055.001)

```text
Inject a DLL into a target process via LoadLibrary:

1. OpenProcess(targetPID)
2. VirtualAllocEx — allocate memory for DLL path string
3. WriteProcessMemory — write DLL path to target process
4. CreateRemoteThread with LoadLibraryA as the start address
   and the DLL path as the argument

The target process calls LoadLibrary, which loads and executes
the DLL's DllMain function.

Advantages:
  - Well-understood, simple to implement
  - DLL can contain complex logic

Disadvantages:
  - DLL must exist on disk (detectable by AV)
  - CreateRemoteThread is monitored
  - LoadLibrary triggers image load callbacks in the kernel
```

### Reflective DLL Injection (T1055)

```text
Load a DLL entirely from memory without touching disk:

1. Read DLL into a buffer (in the injecting process)
2. Allocate memory in target process
3. Write the entire DLL (PE file) to target process memory
4. Write a reflective loader stub that:
   - Parses the PE headers
   - Resolves imports manually
   - Applies relocations
   - Calls DllMain
5. CreateRemoteThread pointing to the reflective loader

Advantages:
  - No DLL file on disk
  - No LoadLibrary call (bypasses image load monitoring)

Disadvantages:
  - Cross-process memory write still detectable
  - Full PE in memory can be found by memory scanning
```

### Process Hollowing (T1055.012)

```text
Replace the code of a legitimate process with malicious code:

1. CreateProcess("svchost.exe", CREATE_SUSPENDED)
   — process is created but not running yet
2. NtUnmapViewOfSection — unmap the legitimate code
3. VirtualAllocEx — allocate new memory at the image base
4. WriteProcessMemory — write malicious PE image
5. SetThreadContext — update entry point to malicious code
6. ResumeThread — process starts executing malicious code

From the OS perspective: svchost.exe is running normally
From memory perspective: the code is completely replaced

Detection:
  - Memory image doesn't match the on-disk binary
  - Section permissions don't match expected PE layout
  - Thread start address outside mapped module ranges
```

### APC Injection (T1055.004)

```text
Asynchronous Procedure Calls — queue code execution in a target thread:

1. OpenProcess + OpenThread (find an alertable thread)
2. VirtualAllocEx — allocate memory for shellcode
3. WriteProcessMemory — write shellcode
4. QueueUserAPC(shellcode_address, hThread)

The shellcode executes when the target thread enters an alertable wait state
(SleepEx, WaitForSingleObjectEx, WaitForMultipleObjectsEx, etc.)

Advantages:
  - No CreateRemoteThread (avoids that specific hook)
  - Can target specific threads

Disadvantages:
  - Requires an alertable thread (not guaranteed)
  - Early Bird variant: inject into a newly created suspended process
    (the first APC runs before the process entry point)

Early Bird APC Injection:
  1. CreateProcess(SUSPENDED)
  2. VirtualAllocEx + WriteProcessMemory (shellcode)
  3. QueueUserAPC to the main thread
  4. ResumeThread — APC fires before any application code
```

### Thread Hijacking (T1055.003)

```text
Hijack an existing thread's execution flow:

1. OpenProcess + OpenThread
2. SuspendThread(hThread)
3. GetThreadContext — save current register state
4. VirtualAllocEx + WriteProcessMemory (shellcode)
5. SetThreadContext — change RIP/EIP to shellcode address
6. ResumeThread — thread now executes shellcode

The shellcode can optionally restore the original context and jump back
to the original code after execution.

Advantages:
  - No new thread created
  - Uses existing thread context

Disadvantages:
  - Suspending threads can cause stability issues
  - GetThreadContext/SetThreadContext are monitored
```

### NtMapViewOfSection (T1055)

```text
Map a section object into a target process (no WriteProcessMemory):

1. NtCreateSection — create a shared memory section
2. NtMapViewOfSection — map section into current process (RW)
3. Copy shellcode into the mapped section
4. NtMapViewOfSection — map same section into target process (RX)
5. CreateRemoteThread or APC to execute

Advantages:
  - No WriteProcessMemory call (bypasses that specific hook)
  - Shared section appears in both processes

Disadvantages:
  - Still need to trigger execution (thread/APC)
  - NtMapViewOfSection in remote process is still suspicious
```

### Module Stomping / DLL Hollowing

```text
Overwrite a legitimate DLL's .text section in a target process:

1. Identify a loaded but infrequently used DLL in the target process
2. Write shellcode over the DLL's .text section
3. The shellcode now resides in a "legitimate" module's memory range

Advantages:
  - Shellcode appears to be part of a signed, legitimate DLL
  - Thread start address points to a known module (looks normal)

Disadvantages:
  - DLL functionality is destroyed
  - Memory content doesn't match on-disk DLL (detectable)
```

## Injection Technique Comparison

```text
Technique                  Stealth   Complexity   Disk Artifact   New Thread
─────────────────────────  ────────  ──────────   ─────────────   ──────────
Remote Thread Injection    Low       Low          No              Yes
DLL Injection              Low       Low          Yes (DLL)       Yes
Reflective DLL Injection   Medium    Medium       No              Yes
Process Hollowing          Medium    High         No              No (reused)
APC Injection              Medium    Medium       No              No
Early Bird APC             High      Medium       No              No
Thread Hijacking           High      High         No              No
NtMapViewOfSection         Medium    Medium       No              Yes
Module Stomping            High      High         No              No
```

## Good Injection Targets

```text
Process              Why
───────────────────  ─────────────────────────────────────────────────
explorer.exe         Always running, makes network connections
svchost.exe          Many instances, expected to do everything
RuntimeBroker.exe    Common, often idle
taskhostw.exe        Runs scheduled tasks, varied behavior
dllhost.exe          COM surrogate, varied behavior
sihost.exe           Shell Infrastructure Host

Avoid:
  - lsass.exe (heavily protected, triggers alerts)
  - csrss.exe (protected process, injection fails)
  - smss.exe (session manager, very restricted)
```

## Detection Methods

### Host-Based Detection

- Cross-process memory operations (VirtualAllocEx, WriteProcessMemory)
- Thread creation in remote processes (CreateRemoteThread, NtCreateThreadEx)
- Thread start addresses outside known module ranges
- Memory sections with executable permissions that don't correspond to loaded modules
- Kernel callbacks: PsSetCreateThreadNotifyRoutine, PsSetLoadImageNotifyRoutine

### Behavioral Indicators

- svchost.exe making unexpected network connections
- Explorer.exe spawning cmd.exe or powershell.exe
- Processes with memory regions that don't match their on-disk image

## Mitigation Strategies

- **EDR with kernel callbacks** — detect injection regardless of userland hooks
- **Code Integrity Guard** — prevent unsigned code from being injected into processes
- **Attack Surface Reduction (ASR)** — block common injection patterns
- **Protected Process Light (PPL)** — prevent injection into security-critical processes
- **Credential Guard** — prevent injection into lsass.exe

## References

### MITRE ATT&CK

- [T1055 - Process Injection](https://attack.mitre.org/techniques/T1055/)
- [T1055.001 - DLL Injection](https://attack.mitre.org/techniques/T1055/001/)
- [T1055.002 - PE Injection](https://attack.mitre.org/techniques/T1055/002/)
- [T1055.003 - Thread Execution Hijacking](https://attack.mitre.org/techniques/T1055/003/)
- [T1055.004 - Asynchronous Procedure Call](https://attack.mitre.org/techniques/T1055/004/)
- [T1055.012 - Process Hollowing](https://attack.mitre.org/techniques/T1055/012/)
