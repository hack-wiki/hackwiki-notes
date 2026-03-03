% Filename: 01-fundamentals/windows-basics/registry.md
% Display name: Windows Registry
% Last update: 2026-02-11
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# Windows Registry

## Overview

The Windows Registry is a hierarchical database that stores configuration for the operating system, applications, hardware, and users. For security professionals, the registry is critical in three contexts: **persistence** (attackers write to Run keys, services, and scheduled tasks), **privilege escalation** (misconfigured keys grant write access to low-privilege users), and **forensics** (user activity, program execution, and network connections leave traces in registry keys). Understanding registry structure and knowing which keys to query is fundamental to Windows engagements.

## Key Concepts

### Registry Structure

The registry is organized into a tree of **hives**, **keys**, **subkeys**, and **values**.

```text
Hive (root)
└── Key
    ├── Subkey
    │   └── Value (Name = Data)
    └── Value (Name = Data)

Example:
HKEY_LOCAL_MACHINE
└── SOFTWARE
    └── Microsoft
        └── Windows NT
            └── CurrentVersion
                └── Winlogon
                    ├── DefaultUserName = "admin"
                    └── Shell = "explorer.exe"
```

### Root Keys (Hives)

```text
Abbreviation  Full Name                  Purpose
------------  -------------------------  ----------------------------------
HKLM          HKEY_LOCAL_MACHINE         System-wide hardware and software config
HKCU          HKEY_CURRENT_USER          Current user's settings and preferences
HKCR          HKEY_CLASSES_ROOT          File associations and COM objects (virtual: merged view of HKLM\Software\Classes + HKCU\Software\Classes; user settings take precedence — exploitable for COM hijacking)
HKU           HKEY_USERS                 All loaded user profiles
HKCC          HKEY_CURRENT_CONFIG        Current hardware profile
```

**Security relevance:**
- `HKLM` — machine-wide settings, usually requires admin to modify. Contains service configs, driver paths, and system policies
- `HKCU` — current user's settings, writable by the current user. Persistence here survives reboots but is user-specific
- `HKU` — contains all loaded profiles, including `S-1-5-18` (SYSTEM). Useful for enumerating other users' settings when running as SYSTEM

### Hive Files on Disk

Registry hives are stored as files. Accessing them offline (from a disk image or backup) bypasses OS-level access controls.

```text
Hive File                              Registry Path
-------------------------------------  ----------------------------
C:\Windows\System32\config\SAM         HKLM\SAM (local passwords)
C:\Windows\System32\config\SYSTEM      HKLM\SYSTEM (system config)
C:\Windows\System32\config\SOFTWARE    HKLM\SOFTWARE (software config)
C:\Windows\System32\config\SECURITY    HKLM\SECURITY (LSA secrets)
C:\Users\<user>\NTUSER.DAT             HKCU (user profile)
C:\Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat  HKCU\Software\Classes
```

**Security relevance:**
- SAM + SYSTEM together allow offline extraction of local password hashes
- SECURITY hive contains LSA secrets (cached domain credentials, service account passwords)
- NTUSER.DAT contains per-user persistence keys, MRU lists, and typed paths
- These files are locked while Windows is running — access them via volume shadow copies, boot from external media, or offline disk analysis

### Registry Data Types

```text
Type              Description                      Example
----------------  -------------------------------  -------------------------
REG_SZ            String                           "C:\Windows\notepad.exe"
REG_EXPAND_SZ     Expandable string (variables)    "%SYSTEMROOT%\notepad.exe"
REG_DWORD         32-bit integer                   0x00000001
REG_QWORD         64-bit integer                   0x0000000000000001
REG_BINARY        Binary data                      hex bytes
REG_MULTI_SZ      Multiple strings (array)         "val1\0val2\0val3"
REG_NONE          No defined type                  (various)
```

### Querying the Registry

```cmd
:: Query a key and list all values
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"

:: Query a specific value
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName

:: Search recursively for a string
reg query HKLM /f "password" /t REG_SZ /s

:: List all subkeys under a key
reg query "HKLM\SYSTEM\CurrentControlSet\Services"

:: Export key to file
reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" C:\Temp\run.reg

:: Remote registry query (requires Remote Registry service)
reg query "\\10.10.10.5\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName
```

**PowerShell equivalents:**

```powershell
# Query a key
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"

# Query a specific value
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ProductName

# List subkeys
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion"

# Search for a value name recursively
Get-ChildItem "HKLM:\SOFTWARE" -Recurse -ErrorAction SilentlyContinue |
    Get-ItemProperty -ErrorAction SilentlyContinue |
    Where-Object { $_ -match "password" }

# Read/write registry values
Get-ItemPropertyValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductName
Set-ItemProperty "HKCU:\Software\Test" -Name "key" -Value "data"
New-Item "HKCU:\Software\Test" -Force
New-ItemProperty "HKCU:\Software\Test" -Name "key" -Value "data" -PropertyType String
```

### Persistence Keys

Attackers use autorun keys to maintain access across reboots. These are the first places to check during incident response.

**Run and RunOnce keys (execute at user logon):**

```cmd
:: Per-user autorun
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce

:: Machine-wide autorun (requires admin to write)
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce

:: Query current Run entries
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
```

**Service keys (execute at boot):**

```cmd
:: All services are stored under
HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>

:: Key values
ImagePath    — binary path (unquoted = hijacking opportunity)
Start        — 0=Boot, 1=System, 2=Auto, 3=Manual, 4=Disabled
              (Boot/System are driver start types; Auto/Manual/Disabled apply to Win32 services)
ObjectName   — account the service runs as (LocalSystem, etc.)
Type         — service type (own process, shared, driver)

:: Query a service
reg query "HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>"
```

**Other persistence locations:**

```cmd
:: Winlogon (shell, userinit — runs at every logon)
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
    Shell = explorer.exe                   ← replace or append
    Userinit = C:\Windows\system32\userinit.exe,   ← append path

:: Image File Execution Options (debugger hijack)
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<exe>
    Debugger = C:\path\to\malware.exe      ← runs instead of target exe

:: Scheduled tasks (stored in registry and XML files)
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree
```

### Privilege Escalation Keys

```cmd
:: AlwaysInstallElevated — if both are set to 1, any user can install
:: MSI packages with SYSTEM privileges
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

:: Unquoted service paths — check ImagePath values with spaces and no quotes
reg query "HKLM\SYSTEM\CurrentControlSet\Services" /s /v ImagePath | findstr /v """"

:: Service permissions — check if low-privilege users can modify service keys
:: Use accesschk from Sysinternals or check DACL manually
```

### Credential Storage Keys

```cmd
:: Autologon credentials (plaintext if configured)
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultUserName
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon

:: Cached domain credentials (count)
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v CachedLogonsCount

:: VNC stored passwords (key paths are version-specific — verify on target)
:: RealVNC 4.x (legacy):
reg query "HKLM\SOFTWARE\RealVNC\WinVNC4" /v Password
:: TightVNC (older installs):
reg query "HKCU\SOFTWARE\TightVNC\Server" /v Password

:: PuTTY saved sessions (may contain proxy credentials)
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s

:: WinSCP stored credentials
reg query "HKCU\Software\Martin Prikryl\WinSCP 2\Sessions" /s

:: SNMP community strings
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities"
```

### Forensic Keys

Registry keys that reveal user activity, program execution history, and system events.

```cmd
:: Last shutdown time
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Windows" /v ShutdownTime

:: Recently typed paths in Explorer address bar
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"

:: Recent documents (MRU — Most Recently Used)
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"

:: UserAssist — GUI program execution with timestamps (ROT13 encoded)
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"

:: BAM/DAM — Background/Desktop Activity Monitor
:: Path with \State subkey applies to Windows 10 1809+ and Windows 11
reg query "HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
:: Pre-1809 Windows 10 path (no \State):
:: reg query "HKLM\SYSTEM\CurrentControlSet\Services\bam\UserSettings"

:: USB device history
reg query "HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR"

:: Mounted devices
reg query "HKLM\SYSTEM\MountedDevices"

:: Network profiles (SSIDs, connection dates)
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles" /s

:: ShellBags (folder access history — proves a user opened a folder)
reg query "HKCU\Software\Microsoft\Windows\Shell\Bags"
reg query "HKCU\Software\Microsoft\Windows\Shell\BagMRU"

:: AppCompatCache (shimcache — program execution evidence)
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
```

### Registry Security

Registry keys have DACLs (Discretionary Access Control Lists) just like files. Misconfigured permissions on service keys or Run keys can allow privilege escalation.

```cmd
:: View ACLs on a registry key (PowerShell)
powershell -c "Get-Acl 'HKLM:\SYSTEM\CurrentControlSet\Services\<ServiceName>' | Format-List"

:: Check which users can write to a service key
powershell -c "(Get-Acl 'HKLM:\SYSTEM\CurrentControlSet\Services\<ServiceName>').Access | Where-Object { $_.RegistryRights -match 'Write' -or $_.RegistryRights -match 'FullControl' }"
```

## Practical Examples

### Enumerate Persistence Locations

```cmd
:: Check all common autorun locations
echo === Run Keys ===
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
echo === RunOnce Keys ===
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce"
echo === Winlogon ===
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit
echo === IFEO ===
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /s /v Debugger 2>nul
```

### Quick Registry Credential Hunt

```powershell
# Check autologon
$wl = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue
if ($wl.DefaultPassword) { Write-Output "AutoLogon: $($wl.DefaultUserName) / $($wl.DefaultPassword)" }

# Check PuTTY sessions
Get-ChildItem "HKCU:\Software\SimonTatham\PuTTY\Sessions" -ErrorAction SilentlyContinue |
    ForEach-Object { Get-ItemProperty $_.PSPath } |
    Select-Object @{N="Session";E={$_.PSChildName}}, HostName, UserName, ProxyUsername, ProxyPassword
```

## References

### Microsoft Documentation

- [Windows Registry Overview](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry)
- [Structure of the Registry](https://learn.microsoft.com/en-us/windows/win32/sysinfo/structure-of-the-registry)
- [Predefined Keys](https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys)
- [Registry Value Types](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types)
- [Run and RunOnce Registry Keys](https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys)
- [reg Command Reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/reg)
- [reg query Command](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/reg-query)
- [Access Control Lists](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-lists)

### Tools

- [Sysinternals Suite](https://learn.microsoft.com/en-us/sysinternals/)
