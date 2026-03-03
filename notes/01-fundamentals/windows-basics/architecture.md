% Filename: 01-fundamentals/windows-basics/architecture.md
% Display name: Windows Architecture
% Last update: 2026-02-11
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# Windows Architecture

## Overview

Understanding Windows internals is essential for privilege escalation, lateral movement, persistence, and forensic analysis. Windows uses a layered architecture separating user-mode applications from kernel-mode components. Attackers exploit boundaries between these layers — injecting into processes, abusing services, manipulating tokens, and leveraging the registry for persistence. This page covers the core architectural concepts that security professionals encounter during engagements.

## Key Concepts

### User Mode vs Kernel Mode

Windows separates execution into two privilege levels enforced by the CPU's ring architecture.

```text
Ring 0 (Kernel Mode)         Ring 3 (User Mode)
--------------------------   --------------------------
Full hardware access         Restricted hardware access
NT Kernel (ntoskrnl.exe)     Applications (notepad, cmd)
Device drivers               DLLs (user32.dll, kernel32.dll)
HAL (hal.dll)                Subsystem processes (csrss.exe)
File system drivers          Service processes (svchost.exe)
```

**Security relevance:**
- Kernel-mode code has unrestricted access — a kernel exploit grants complete system control
- User-mode processes are isolated from each other via virtual address spaces
- Device drivers run in kernel mode — malicious drivers bypass all user-mode security
- Kernel-mode rootkits operate below the OS, making detection difficult

### Processes and Threads

A **process** is a container with its own virtual address space, security token, and handles. A **thread** is the unit of execution within a process. Every process has at least one thread.

**Key process attributes:**
- **PID** — unique process identifier
- **PPID** — parent process ID (who created this process)
- **Security token** — defines the process's privileges and identity
- **Virtual address space** — isolated memory region
- **Handle table** — references to kernel objects (files, registry keys, other processes)

**Critical system processes:**

```text
Process              PID    Parent    Purpose
-------------------  -----  --------  ----------------------------------
System               4      0         Kernel threads and drivers
smss.exe             ~      System    Session Manager — first user-mode process
csrss.exe            ~      smss      Client/Server Runtime — per-session
wininit.exe          ~      smss      Session 0 initialization
winlogon.exe         ~      smss      Handles user logon/logoff
services.exe         ~      wininit   Service Control Manager (SCM)
lsass.exe            ~      wininit   Local Security Authority — authentication
svchost.exe          ~      services  Hosts Windows services (multiple instances)
explorer.exe         ~      userinit* User shell (desktop, taskbar)
```

**Security relevance:**
- Unusual parent-child relationships indicate process injection or malware (e.g., `cmd.exe` spawned by `winword.exe`)
- `lsass.exe` holds credentials in memory — dumping it yields NTLM hashes and Kerberos tickets
- `svchost.exe` runs multiple instances, each hosting different services — malware often masquerades as svchost
- *`explorer.exe` parent (`userinit.exe`) exits immediately after spawning it, so explorer.exe appears parentless in a live process tree — this is normal, not suspicious
- Process hollowing replaces a legitimate process's memory with malicious code while keeping the original PID

```cmd
:: List processes with parent PID
:: Note: wmic is deprecated in Windows 10 21H2+ and absent on Windows 11 23H2+
wmic process get ProcessId,ParentProcessId,Name,CommandLine

:: PowerShell equivalent
powershell -c "Get-Process | Select-Object Id,ProcessName,Path"

:: Detailed process tree (Sysinternals)
pslist.exe -t
```

### Security Tokens and Privileges

Every process and thread has a security token that defines its identity and privileges. Tokens are assigned at logon and inherited by child processes.

**Token contents:**
- **User SID** — identifies the user account
- **Group SIDs** — group memberships
- **Privileges** — specific rights (e.g., SeDebugPrivilege, SeImpersonatePrivilege)
- **Integrity level** — Low, Medium, High, or System

**Key privileges for attackers:**

```text
Privilege                    Abuse Potential
---------------------------  -------------------------------------------
SeDebugPrivilege             Inject into/read any process (lsass dumping)
SeImpersonatePrivilege       Impersonate tokens (Potato attacks)
SeAssignPrimaryTokenPrivilege  Assign tokens to processes
SeBackupPrivilege            Read any file regardless of ACLs
SeRestorePrivilege           Write any file regardless of ACLs
SeTakeOwnershipPrivilege     Take ownership of any object
SeLoadDriverPrivilege        Load kernel drivers (kernel-mode code exec)
```

```cmd
:: View current user's privileges
whoami /priv

:: View token details
whoami /all

:: PowerShell: check specific privilege
powershell -c "whoami /priv | Select-String 'SeDebug'"
```

### Security Identifiers (SIDs)

SIDs uniquely identify security principals (users, groups, computers). SIDs are used internally — the human-readable name is just a display label.

**SID format:** `S-1-5-21-<domain>-<RID>`

**Well-known SIDs:**

```text
SID                          Name                    Notes
---------------------------  ----------------------  -------------------------
S-1-0-0                      Nobody                  Null SID
S-1-1-0                      Everyone                All users
S-1-5-7                      Anonymous                Unauthenticated connections
S-1-5-11                     Authenticated Users     All authenticated users
S-1-5-18                     SYSTEM (LocalSystem)    Highest local privilege
S-1-5-19                     LOCAL SERVICE            Reduced privileges
S-1-5-20                     NETWORK SERVICE          Network-capable, reduced
S-1-5-21-...-500             Administrator            Built-in admin (RID 500)
S-1-5-21-...-501             Guest                   Built-in guest (RID 501)
S-1-5-21-...-512             Domain Admins            AD admin group
S-1-5-21-...-513             Domain Users             All domain users
S-1-5-32-544                 BUILTIN\Administrators  Local admin group
```

```cmd
:: Display current user SID
whoami /user

:: Display all user SIDs on the system
:: Note: wmic is deprecated in Windows 10 21H2+ and absent on Windows 11 23H2+
wmic useraccount get Name,SID
```

### Services

Windows services run in the background under specific accounts (LocalSystem, LocalService, NetworkService, or domain accounts). They are managed by the Service Control Manager (SCM).

**Service properties:**

```text
Property           Example                  Security Relevance
-----------------  ----------------------   ----------------------------
Binary path        C:\Windows\System32\...  Unquoted paths = hijacking
Start type         Auto, Manual, Disabled   Auto-start = persistence
Account            LocalSystem              Determines token/privileges
Dependencies       Other services, drivers  Cascading impact on disable
Permissions        DACL on service object   Weak perms = config change
```

**Common attack vectors:**
- **Unquoted service paths** — if a service binary path contains spaces and isn't quoted, Windows searches each path segment, allowing DLL/binary planting
- **Weak service permissions** — if a low-privilege user can modify the service configuration, they can change the binary path to a malicious executable
- **Service account privileges** — services running as LocalSystem have full machine access

```cmd
:: List all services
sc query type= service state= all

:: Query specific service details
sc qc <ServiceName>

:: Show service permissions
sc sdshow <ServiceName>

:: PowerShell: list services with binary paths
powershell -c "Get-CimInstance Win32_Service | Select-Object Name,StartName,PathName,State"
```

### Windows File System (NTFS)

NTFS (New Technology File System) is the default Windows file system. It supports access control lists, encryption, compression, and alternate data streams.

**Key directories:**

```text
Path                           Purpose
-----------------------------  ----------------------------------
C:\Windows\                    OS files
C:\Windows\System32\           64-bit system binaries and DLLs (confusingly named)
C:\Windows\SysWOW64\           32-bit binaries on 64-bit OS (WoW64 = Windows on Windows 64-bit)
C:\Windows\Temp\               System temp (world-writable)
C:\Users\<username>\           User profile
C:\Users\<username>\AppData\   Application data (Local, Roaming)
C:\Program Files\              64-bit installed applications
C:\Program Files (x86)\        32-bit installed applications
C:\ProgramData\                App data shared across all users
```

**Security features:**
- **ACLs** — Discretionary (DACL) and System (SACL) access control lists on every object
- **Alternate Data Streams (ADS)** — hidden data attached to files (used by malware to hide payloads)
- **EFS** — Encrypting File System (per-file encryption tied to user certificate)
- **Inheritance** — permissions flow from parent folders to child objects

```cmd
:: View file ACLs
icacls C:\Windows\System32\config\SAM

:: List alternate data streams
dir /R <file>

:: View NTFS permissions in PowerShell
powershell -c "Get-Acl 'C:\Users' | Format-List"
```

### Authentication Architecture

Windows authentication flows through several components depending on the scenario (local logon, domain logon, network authentication).

**Key components:**

```text
Component          Process       Purpose
-----------------  -----------   ----------------------------------
Winlogon           winlogon.exe  Handles interactive logon UI
LSA                lsass.exe     Validates credentials, issues tokens
SAM                Registry      Local account database (hashed passwords)
NTDS.dit           ntds.dit      AD account database on domain controllers
NTLM               -             Challenge-response authentication
Kerberos            -             Ticket-based authentication (AD default)
Credential Manager  -             Cached credentials (vault)
```

**Local authentication flow:**

```text
1. User enters credentials at Winlogon
2. Winlogon sends to LSA (lsass.exe)
3. LSA hashes the password and compares with SAM database
4. If valid, LSA creates an access token
5. Token is assigned to the user's shell (explorer.exe)
6. All child processes inherit the token
```

**Domain authentication (Kerberos):**

```text
1. User enters credentials
2. LSA sends AS-REQ to Domain Controller (KDC)
3. KDC validates against NTDS.dit, returns TGT
4. User presents TGT to request TGS for specific services
5. Service validates the TGS and grants access
```

**Security relevance:**
- SAM file contains local password hashes — extractable with admin access
- `lsass.exe` caches credentials in memory (NTLM hashes, Kerberos tickets; plaintext only if WDigest is enabled — off by default since Windows 8.1/Server 2012 R2)
- NTLM relay attacks forward captured authentication to other services
- Pass-the-hash uses extracted NTLM hashes without knowing the password

### Windows Networking

```text
Component          Purpose                    Security Relevance
-----------------  -------------------------  -------------------------
SMB (445)          File/printer sharing       Lateral movement, relay
RPC (135)          Remote procedure calls     Service enumeration
WinRM (5985/5986)  Remote management          Remote command execution
RDP (3389)         Remote desktop             Brute-force, hijacking
LDAP (389/636)     Directory queries          AD enumeration
Kerberos (88)      Authentication             Ticket attacks
DNS (53)           Name resolution            AD-integrated zones
```

```cmd
:: Show network connections
netstat -ano

:: Show listening ports with process names
netstat -anob

:: PowerShell equivalent
powershell -c "Get-NetTCPConnection | Select-Object LocalPort,RemoteAddress,State,OwningProcess"

:: Show network shares
net share

:: Show current SMB sessions
net session
```

## Practical Examples

### Enumerating System Information

```cmd
:: System overview
systeminfo

:: OS version and build
ver

:: Hostname and domain
hostname
echo %USERDOMAIN%

:: Environment variables (reveal paths, domain info)
set

:: Installed hotfixes (missing patches = potential exploits)
wmic qfe list brief

:: PowerShell: detailed system info
powershell -c "Get-ComputerInfo | Select-Object OsName,OsVersion,OsBuildNumber,CsDomain"
```

### Enumerating Users and Groups

```cmd
:: Local users
net user

:: Detailed user info
net user <username>

:: Local groups
net localgroup

:: Members of Administrators group
net localgroup Administrators

:: Domain users (if domain-joined)
net user /domain

:: Domain groups
net group /domain

:: PowerShell: local users with details
powershell -c "Get-LocalUser | Select-Object Name,Enabled,LastLogon"
```

## References

### Microsoft Documentation

- [User Mode and Kernel Mode](https://learn.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/user-mode-and-kernel-mode)
- [About Processes and Threads](https://learn.microsoft.com/en-us/windows/win32/procthread/about-processes-and-threads)
- [Access Tokens](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- [Security Identifiers (SIDs)](https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers)
- [Windows Services](https://learn.microsoft.com/en-us/windows/win32/services/services)
- [Access Control Model](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-model)
- [LSA Authentication](https://learn.microsoft.com/en-us/windows/win32/secauthn/lsa-authentication)
- [Virtual Address Space](https://learn.microsoft.com/en-us/windows/win32/memory/virtual-address-space)
- [File Systems](https://learn.microsoft.com/en-us/windows/win32/fileio/file-systems)

### Tools

- [Sysinternals Suite](https://learn.microsoft.com/en-us/sysinternals/)
